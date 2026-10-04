using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>
/// The fault locator's rule set, strongest first. Pure function of a <see cref="FaultSnapshot"/>:
/// <list type="number">
/// <item>own link down (LocalLinkDown / Wi-Fi disconnect of this host)</item>
/// <item>storm / loop override</item>
/// <item>every hop beyond this PC down → own link</item>
/// <item>path cut: first down hop whose predecessor answers (and nothing behind it answers)</item>
/// <item>blast radius: lowest common ancestor of the devices that became unreachable</item>
/// <item>probe-agent vantage points</item>
/// <item>internet down while all LAN hops answer → ISP</item>
/// <item>port-only, speed-drop and DHCP conditions</item>
/// </list>
/// Port signals on the suspect (or its uplink port) and agent failures towards it then boost the confidence.
/// </summary>
public static class FaultRules
{
    public const double MaxConfidence = 0.98;
    public const double PortBoost = 0.1;

    private static readonly HashSet<SignalKind> PortKinds =
        [SignalKind.PortDown, SignalKind.PortFlapping, SignalKind.PortErrors, SignalKind.PortDuplexMismatch, SignalKind.PortSpeedDowngrade, SignalKind.PortPoeOverload];

    public static FaultVerdict? Evaluate(FaultSnapshot s)
    {
        var v = OwnLink(s) ?? StormOrLoop(s) ?? OwnLinkFromPath(s) ?? PathCut(s) ?? BlastRadius(s) ?? Agents(s) ?? InternetDown(s) ?? Minor(s);
        return v is null ? null : Boost(v, s);
    }

    // ============================================================================================ 1. own link / Wi-Fi

    private static FaultVerdict? OwnLink(FaultSnapshot s)
    {
        var link = s.Active.LastOrDefault(x => x.Kind == SignalKind.LocalLinkDown);
        var wifi = s.Active.LastOrDefault(x => x.Kind is SignalKind.WifiDisconnected)
                   ?? s.Active.LastOrDefault(x => x.Kind is SignalKind.WifiAuthFailed);
        if (link is null && wifi is null) return null;

        var evidence = new List<string>();
        if (link is not null) evidence.Add(link.Summary);
        if (wifi is not null) evidence.Add(wifi.Summary);
        foreach (var e in s.Window.Where(x => x.Kind is SignalKind.LocalSpeedChanged or SignalKind.DhcpLeaseLost or SignalKind.WifiWeakSignal or SignalKind.WifiRoamed))
            evidence.Add(e.Summary);
        var affected = AllPathMacs(s.Path, skipSelf: true).Concat(s.Unreachable).Distinct().ToList();
        Mac? self = link?.Device ?? s.Path?.Hops.FirstOrDefault(h => h.Role == HopRole.ThisHost)?.Mac;

        if (wifi is not null)
        {
            string ap = s.Path?.Hops.FirstOrDefault(h => h.Role == HopRole.AccessPoint)?.Name ?? "the access point";
            string what = wifi.Kind == SignalKind.WifiAuthFailed ? "Wi-Fi authentication failed" : "Wi-Fi connection lost";
            return new FaultVerdict(IncidentCategory.Wifi, AlertSeverity.Critical, $"This PC: {what}",
                $"{what} between this PC and {ap}: {wifi.Summary}", link is not null ? 0.92 : 0.85, wifi.Device ?? self, null, $"This PC ↔ {ap}", affected, evidence);
        }

        string adapter = link!.Port ?? "the network adapter";
        var speed = s.Window.LastOrDefault(x => x.Kind == SignalKind.LocalSpeedChanged);
        string root = $"Your own network link is down (cable/port/NIC or Wi-Fi association) on {adapter}" +
                      (speed is not null ? $"; earlier: {speed.Summary}" : "");
        return new FaultVerdict(IncidentCategory.OwnLink, AlertSeverity.Critical, "Own network link down", root, 0.95,
            self, null, $"This PC ({adapter}) ↔ {FirstHopName(s.Path) ?? "its switch/AP"}", affected, evidence);
    }

    // ============================================================================================ 2. storm / loop

    private static FaultVerdict? StormOrLoop(FaultSnapshot s)
    {
        var loop = s.Active.LastOrDefault(x => x.Kind == SignalKind.LoopSuspected);
        var storm = s.Active.LastOrDefault(x => x.Kind == SignalKind.StormDetected);
        if (loop is null && storm is null) return null;
        var evidence = s.Window.Where(x => x.Kind is SignalKind.StormDetected or SignalKind.LoopSuspected or SignalKind.StpTopologyChange)
            .Select(x => x.Summary).Distinct().ToList();
        var affected = s.Unreachable.Concat(loop?.Affected ?? []).Concat(storm?.Affected ?? []).Distinct().ToList();
        if (loop is not null)
        {
            string where = Where(loop, s);
            return new FaultVerdict(IncidentCategory.Loop, AlertSeverity.Critical, "Network loop suspected",
                $"Layer-2 loop{where}: {loop.Summary}", Math.Max(0.7, loop.Weight), loop.Device, loop.Port, null, affected, evidence);
        }
        string w = Where(storm!, s);
        return new FaultVerdict(IncidentCategory.Storm, AlertSeverity.Critical, "Broadcast storm",
            $"Broadcast/multicast storm{w}: {storm!.Summary}", Math.Max(0.7, storm.Weight), storm.Device, storm.Port, null, affected, evidence);
    }

    private static string Where(DiagnosticSignal sig, FaultSnapshot s)
    {
        if (sig.Device is not { } d) return "";
        var name = NameOf(d, s);
        return sig.Port is { } p ? $" entering at {name} port {p}" : $" from {name}";
    }

    // ============================================================================================ 3. nothing answers

    private static FaultVerdict? OwnLinkFromPath(FaultSnapshot s)
    {
        if (s.Path is not { } path) return null;
        var probed = path.Hops.Where(h => h.Role != HopRole.ThisHost && h.Probe != HopProbe.None && h.Health != HopHealth.Unknown).ToList();
        if (probed.Count < 2 || probed.Any(h => h.Health != HopHealth.Down)) return null;
        // the first hop beyond this PC must be among the failing ones (not just an unprobed AP)
        var first = probed[0];
        var evidence = new List<string> { $"none of the {probed.Count} hops on the path answers (first: {HopLabel(first)})" };
        evidence.AddRange(s.Window.Where(x => x.Kind is SignalKind.LocalSpeedChanged or SignalKind.DhcpLeaseLost or SignalKind.LocalGatewayChanged).Select(x => x.Summary));
        var self = path.Hops.FirstOrDefault(h => h.Role == HopRole.ThisHost);
        return new FaultVerdict(IncidentCategory.OwnLink, AlertSeverity.Critical, "Own network link down",
            $"Your own network link is down (cable/port/NIC or Wi-Fi association): not even the first hop {HopLabel(first)} answers (or that device itself is dead)",
            0.75, self?.Mac, first.PortIn, $"This PC ↔ {first.Name}", AllPathMacs(path, skipSelf: true).Concat(s.Unreachable).Distinct().ToList(), evidence);
    }

    // ============================================================================================ 4. path cut

    private static FaultVerdict? PathCut(FaultSnapshot s)
    {
        if (s.Path is not { } path) return null;
        var hops = path.Hops;
        for (int i = 1; i < hops.Count; i++)
        {
            var h = hops[i];
            if (h.Health != HopHealth.Down) continue;
            // a hop that does not answer while hops behind it do is just not answering pings: not a cut
            if (hops.Skip(i + 1).Any(x => x.Health is HopHealth.Up or HopHealth.Degraded)) continue;
            var prev = hops.Take(i).LastOrDefault(x => x.Health is HopHealth.Up or HopHealth.Degraded || x.Role == HopRole.ThisHost);
            if (prev is null) continue;
            return CutVerdict(s, path, prev, h);
        }
        return null;
    }

    private static FaultVerdict CutVerdict(FaultSnapshot s, NetworkPath path, PathHop prev, PathHop h)
    {
        string port = h.PortIn is { } p ? $" (port {p})" : "";
        string uplinkPort = prev.Mac is { } pm && s.Tree?.Parent(pm) == h.Mac && s.Tree?.UpstreamPort(pm) is { } up ? $" port {up}" : "";
        (IncidentCategory cat, string cause, double conf) = h.Role switch
        {
            HopRole.Switch => (IncidentCategory.LocalNetwork, $"{h.Name}{port} or the cable/port between it and {prev.Name}", 0.8),
            HopRole.UnmanagedSwitch => (IncidentCategory.LocalNetwork,
                $"{InferredName(h.Name)} or its uplink — none of its anchor devices answer", 0.65),
            HopRole.AccessPoint => (IncidentCategory.Wifi, $"the access point {h.Name} (radio, power/PoE) or its uplink", 0.8),
            HopRole.Router or HopRole.Firewall => (IncidentCategory.Router, $"the {(h.Role == HopRole.Firewall ? "firewall" : "router")} or the LAN link into it{uplinkPort}", 0.8),
            HopRole.Modem => (IncidentCategory.Modem, "modem or the router↔modem cable/WAN link", 0.8),
            HopRole.IspHop => (IncidentCategory.Isp, "the ISP network (outage beyond your modem/router)", 0.75),
            _ => (IncidentCategory.Isp, "upstream ISP / internet routing (the internet target does not answer)", 0.55),
        };
        string head = prev.Role == HopRole.ThisHost
            ? $"{HopLabel(h)} — the first hop after this PC — does not answer"
            : $"Everything up to {HopLabel(prev)} answers; {HopLabel(h)} does not";
        string title = cat switch
        {
            IncidentCategory.Isp => "Internet / ISP outage",
            IncidentCategory.Modem => $"Modem unreachable: {h.Name}",
            IncidentCategory.Router => $"Router unreachable: {h.Name}",
            IncidentCategory.Wifi => $"Access point down: {h.Name}",
            _ => $"Network break at {h.Name}",
        };
        var idx = path.Hops.ToList().IndexOf(h);
        var affected = path.Hops.Skip(idx).Where(x => x.Mac is not null).Select(x => x.Mac!.Value).Concat(s.Unreachable).Distinct().ToList();
        var evidence = new List<string> { $"{HopLabel(h)}: {h.Note ?? "no answer"}" };
        if (prev.Role != HopRole.ThisHost) evidence.Add($"{HopLabel(prev)} answers{(prev.RttMs is { } r ? $" ({r:0.#} ms)" : "")}");
        if (h.Probe == HopProbe.Anchors && h.Anchors.Count > 0) evidence.Add($"anchors: {string.Join(", ", h.Anchors.Select(a => NameOf(a, s)))}");
        return new FaultVerdict(cat, AlertSeverity.Critical, title, $"{head} → {cause}", conf, h.Mac, h.PortIn, $"{prev.Name} ↔ {h.Name}", affected, evidence);
    }

    // ============================================================================================ 5. blast radius / LCA

    private enum Reach { Up, Down, Unknown }

    private static FaultVerdict? BlastRadius(FaultSnapshot s)
    {
        var set = new HashSet<Mac>(s.Unreachable);
        var apSig = s.Active.LastOrDefault(x => x.Kind is SignalKind.ApDown or SignalKind.ApClientsUnreachable);
        foreach (var sig in s.Active.Where(x => x.Kind is SignalKind.DevicesUnreachable or SignalKind.ApClientsUnreachable or SignalKind.ApDown))
        {
            foreach (var m in sig.Affected ?? []) set.Add(m);
            if (sig.Kind == SignalKind.ApDown && sig.Device is { } apm) set.Add(apm);
        }
        if (set.Count == 0 || (set.Count < 2 && apSig is null)) return null;
        var tree = s.Tree;

        Reach State(Mac m)
        {
            if (set.Contains(m)) return Reach.Down;
            if (m == SyntheticNodes.Internet) return Reach.Unknown;
            if (s.Path?.Hops.FirstOrDefault(h => h.Mac == m) is { Health: HopHealth.Up or HopHealth.Degraded }) return Reach.Up;
            if (!s.Nodes.TryGetValue(m, out var n) || n.Inferred) return Reach.Unknown;
            return n.Online ? Reach.Up : Reach.Down;
        }

        Mac? lca = null;
        var inTree = tree is null ? [] : set.Where(tree.Contains).ToList();
        if (tree is not null && inTree.Count > 0) lca = tree.LowestCommonAncestor(inTree);
        if (apSig?.Device is { } apMac && (lca is null || inTree.Count < set.Count / 2)) lca = apMac;
        if (lca is not { } suspect) return null;

        var evidence = new List<string>();
        if (apSig is not null) evidence.Add(apSig.Summary);
        var affected = set.OrderBy(m => m).ToList();
        string Names() => string.Join(", ", affected.Take(6).Select(m => NameOf(m, s))) + (affected.Count > 6 ? $" +{affected.Count - 6} more" : "");
        evidence.Add($"unreachable: {Names()}");
        int n = affected.Count(m => m != suspect);

        if (State(suspect) == Reach.Up)
        {
            var node = s.Nodes.GetValueOrDefault(suspect);
            if (node is { IsAp: true } || apSig?.Kind == SignalKind.ApClientsUnreachable)
                return new FaultVerdict(IncidentCategory.Wifi, AlertSeverity.Warning, $"Wi-Fi clients of {NameOf(suspect, s)} unreachable",
                    $"All {n} Wi-Fi clients of {NameOf(suspect, s)} are unreachable while the AP answers → AP radio/SSID problem",
                    0.75, suspect, null, null, affected, evidence);
            bool isRoot = tree?.Parent(suspect) is null || node is { Gateway: true } || suspect == SyntheticNodes.Internet;
            if (isRoot)
            {
                if (n < 3) return null;
                return new FaultVerdict(IncidentCategory.Unknown, AlertSeverity.Warning, $"{n} devices unreachable",
                    $"{n} devices became unreachable at once but share no common switch or AP below {NameOf(suspect, s)}", 0.3, null, null, null, affected, evidence);
            }
            return new FaultVerdict(IncidentCategory.LocalNetwork, AlertSeverity.Warning, $"{n} devices behind {NameOf(suspect, s)} unreachable",
                $"{n} devices behind {NameOf(suspect, s)} are unreachable while it answers → check their ports/VLAN on {NameOf(suspect, s)} or a device hanging below it",
                0.5, suspect, null, null, affected, evidence);
        }

        // the LCA itself is down or cannot be probed: climb while the parent is not reachable either
        while (tree?.Parent(suspect) is { } parent && parent != SyntheticNodes.Internet && State(parent) != Reach.Up)
            suspect = parent;
        var up = tree?.Parent(suspect);
        bool parentUp = up is { } pu && State(pu) == Reach.Up;
        string? port = tree?.UpstreamPort(suspect);
        var sn = s.Nodes.GetValueOrDefault(suspect);
        string sName = NameOf(suspect, s);
        string upName = up is { } u ? NameOf(u, s) : "the network";
        string uplink = port is not null ? $"its uplink to {upName} port {port}" : $"its uplink to {upName}";
        n = affected.Count(m => m != suspect);
        bool suspectDown = State(suspect) == Reach.Down;
        double conf = parentUp ? (suspectDown ? 0.8 : 0.7) : 0.5;
        if (parentUp) evidence.Add($"{upName} still answers");

        IncidentCategory cat;
        string root, title;
        if (sn is { IsAp: true } || apSig?.Kind == SignalKind.ApDown && apSig.Device == suspect)
        {
            cat = IncidentCategory.Wifi;
            title = $"Access point down: {sName}";
            root = $"{sName} is unreachable{(n > 0 ? $" together with its {n} Wi-Fi clients" : "")} → the AP, its PoE/power or {uplink}";
        }
        else if (sn is { Type: DeviceType.Router or DeviceType.Firewall } || sn is { Gateway: true })
        {
            cat = IncidentCategory.Router;
            title = $"Router unreachable: {sName}";
            root = $"{sName} and {n} devices behind it are unreachable → the router or {uplink}";
        }
        else
        {
            cat = IncidentCategory.LocalNetwork;
            bool inferred = sn is null || sn.Inferred;
            title = inferred ? $"{InferredName(sName)} down" : $"Network break at {sName}";
            root = inferred
                ? $"{InferredName(sName)} or {uplink} — {n} devices behind it unreachable"
                : $"{sName}{(suspectDown ? " is unreachable" : "")}{(n > 0 ? $" with {n} devices behind it" : "")} → {sName} or {uplink}";
        }
        return new FaultVerdict(cat, conf >= 0.7 ? AlertSeverity.Critical : AlertSeverity.Warning, title, root, conf, suspect, port,
            up is not null ? $"{upName}{(port is not null ? $" port {port}" : "")} ↔ {sName}" : null, affected, evidence);
    }

    // ============================================================================================ 6. probe agents

    private static FaultVerdict? Agents(FaultSnapshot s)
    {
        var fails = s.Active.Where(x => x.Kind == SignalKind.AgentReportFailure).ToList();
        if (fails.Count == 0) return null;
        var sig = fails[^1];
        // the hub identifies the agent through Affected (its MAC); Source is the publishing component
        string agent = sig.Affected is { Count: > 0 } aff ? NameOf(aff[0], s) : sig.Source;
        if (sig.Device is { } target)
        {
            bool weFail = s.Unreachable.Contains(target)
                          || s.Path?.Hops.Any(h => h.Mac == target && h.Health == HopHealth.Down) == true
                          || s.Nodes.TryGetValue(target, out var tn) && !tn.Online && !tn.Inferred;
            string tName = NameOf(target, s);
            if (weFail)
            {
                var cat = s.Nodes.GetValueOrDefault(target) switch
                {
                    { IsAp: true } => IncidentCategory.Wifi,
                    { Type: DeviceType.Router or DeviceType.Firewall } or { Gateway: true } => IncidentCategory.Router,
                    _ => IncidentCategory.LocalNetwork,
                };
                return new FaultVerdict(cat, AlertSeverity.Critical, $"{tName} unreachable from two vantage points",
                    $"Both this PC and probe agent {agent} fail to reach {tName} → {tName} itself (or its own link) is the culprit",
                    0.85, target, null, null, [target], [sig.Summary]);
            }
            return new FaultVerdict(IncidentCategory.LocalNetwork, AlertSeverity.Warning, $"Probe agent {agent} cannot reach {tName}",
                $"This PC reaches {tName}, but probe agent {agent} does not → the problem is in the agent's segment (its link, switch or AP)",
                0.6, null, null, $"{agent} ↔ {tName}", [target], [sig.Summary]);
        }
        bool inetDown = s.Path?.Hops.LastOrDefault() is { Role: HopRole.InternetTarget, Health: HopHealth.Down };
        if (inetDown) return null; // both vantage points lose the internet: the ISP rule below decides
        return new FaultVerdict(IncidentCategory.LocalNetwork, AlertSeverity.Warning, $"Probe agent {agent} reports failures",
            $"Probe agent {agent} reports failures this PC does not see → the problem is in the agent's segment: {sig.Summary}",
            0.55, null, null, null, [], [sig.Summary]);
    }

    // ============================================================================================ 7. internet down, LAN up

    private static FaultVerdict? InternetDown(FaultSnapshot s)
    {
        var inet = s.Active.LastOrDefault(x => x.Kind == SignalKind.InternetDown);
        if (inet is null) return null;
        var evidence = new List<string> { inet.Summary };
        evidence.AddRange(s.Active.Where(x => x.Kind == SignalKind.AgentReportFailure).Select(x => x.Summary));
        if (s.Path is { } path)
        {
            var modem = path.Hops.FirstOrDefault(h => h.Role == HopRole.Modem && h.Health == HopHealth.Down);
            if (modem is not null)
            {
                var prev = path.Hops.Take(path.Hops.ToList().IndexOf(modem)).Last();
                return CutVerdict(s, path, prev, modem);
            }
            var lan = path.Hops.Where(h => h.Role is HopRole.AccessPoint or HopRole.Switch or HopRole.UnmanagedSwitch or HopRole.Router or HopRole.Firewall).ToList();
            var gw = lan.LastOrDefault(h => h.Role is HopRole.Router or HopRole.Firewall);
            if (lan.Count > 0 && lan.All(h => h.Health is HopHealth.Up or HopHealth.Degraded or HopHealth.Unknown) && gw is { Health: HopHealth.Up or HopHealth.Degraded })
            {
                var lastUp = path.Hops.LastOrDefault(h => h.Role != HopRole.InternetTarget && h.Health is HopHealth.Up or HopHealth.Degraded) ?? gw;
                return new FaultVerdict(IncidentCategory.Isp, AlertSeverity.Critical, "Internet / ISP outage",
                    $"All LAN hops up to {HopLabel(lastUp)} answer, but the internet targets do not → ISP / upstream outage", 0.75,
                    lastUp.Mac, null, $"{lastUp.Name} ↔ ISP", [], evidence);
            }
        }
        return new FaultVerdict(IncidentCategory.Isp, AlertSeverity.Critical, "Internet / ISP outage",
            $"None of the internet targets answer → ISP / upstream outage (LAN path state unknown)", 0.5, null, null, null, [], evidence);
    }

    // ============================================================================================ 8. single-signal conditions

    private static FaultVerdict? Minor(FaultSnapshot s)
    {
        var port = s.Active.Where(x => PortKinds.Contains(x.Kind)).OrderByDescending(x => x.Weight).ThenByDescending(x => x.Time).FirstOrDefault();
        if (port is not null)
        {
            string sw = port.Device is { } d ? NameOf(d, s) : "a switch";
            var evidence = s.Active.Where(x => PortKinds.Contains(x.Kind) && x.Device == port.Device).Select(x => x.Summary).Distinct().ToList();
            return new FaultVerdict(IncidentCategory.SwitchPort, AlertSeverity.Warning,
                $"Port problem on {sw}{(port.Port is { } pp ? $" port {pp}" : "")}", port.Summary, Math.Clamp(port.Weight, 0.3, 0.9),
                port.Device, port.Port, null, port.Affected ?? [], evidence);
        }
        var speed = s.Active.LastOrDefault(x => x.Kind == SignalKind.LocalSpeedChanged && x.Weight >= 0.5);
        if (speed is not null)
            return new FaultVerdict(IncidentCategory.OwnLink, AlertSeverity.Warning, "Own link speed dropped",
                speed.Summary, 0.5, speed.Device, null, $"This PC ↔ {FirstHopName(s.Path) ?? "its switch"}", [], [speed.Summary]);
        var dhcp = s.Active.LastOrDefault(x => x.Kind == SignalKind.DhcpLeaseLost);
        if (dhcp is not null)
        {
            var gw = s.Path?.Hops.FirstOrDefault(h => h.Role is HopRole.Router or HopRole.Firewall);
            return new FaultVerdict(IncidentCategory.Router, AlertSeverity.Warning, "DHCP lease lost",
                $"{dhcp.Summary} → the DHCP server ({gw?.Name ?? "usually the router"}) did not answer", 0.5, gw?.Mac, null, null, [], [dhcp.Summary]);
        }
        return null;
    }

    // ============================================================================================ boosting

    private static FaultVerdict Boost(FaultVerdict v, FaultSnapshot s)
    {
        if (v.SuspectDevice is not { } suspect || v.Category is IncidentCategory.Storm or IncidentCategory.Loop or IncidentCategory.SwitchPort) return v;
        var parent = s.Tree?.Parent(suspect);
        var uplinkPort = v.SuspectPort ?? s.Tree?.UpstreamPort(suspect);
        Mac? pathPrev = null;
        if (s.Path is { } path)
        {
            var hops = path.Hops.ToList();
            int i = hops.FindIndex(h => h.Mac == suspect);
            if (i > 0) pathPrev = hops.Take(i).LastOrDefault(h => h.Mac is not null)?.Mac;
        }

        bool Matches(DiagnosticSignal p)
        {
            if (p.Device is not { } d) return false;
            if (d == suspect) return true;
            if (d == parent) return p.Port is null || s.Tree?.UpstreamPort(suspect) is not { } up || SignalActivity.PortEquals(p.Port, up);
            return d == pathPrev;
        }

        double conf = v.Confidence;
        var evidence = v.Evidence.ToList();
        string? port = v.SuspectPort;
        foreach (var p in s.Window.Where(x => PortKinds.Contains(x.Kind) && Matches(x)).GroupBy(x => (x.Kind, x.Device, x.Port)).Select(g => g.Last()))
        {
            conf = Math.Min(MaxConfidence, conf + PortBoost);
            evidence.Add($"{NameOf(p.Device!.Value, s)}{(p.Port is { } pp ? $" port {pp}" : "")}: {p.Summary}");
            if (port is null && p.Device == parent) port = p.Port ?? uplinkPort;
        }
        foreach (var a in s.Active.Where(x => x.Kind == SignalKind.AgentReportFailure && x.Device == suspect))
        {
            conf = Math.Min(MaxConfidence, conf + PortBoost);
            evidence.Add($"probe agent {a.Source} cannot reach it either: {a.Summary}");
        }
        return v with { Confidence = Math.Round(conf, 3), Evidence = evidence.Distinct().ToList(), SuspectPort = port };
    }

    // ============================================================================================ helpers

    private static string HopLabel(PathHop h) => h.Ip is { } ip && !h.Name.Contains(ip.ToString(), StringComparison.Ordinal) ? $"{h.Name} ({ip})" : h.Name;

    private static string? FirstHopName(NetworkPath? p) => p?.Hops.FirstOrDefault(h => h.Role != HopRole.ThisHost)?.Name;

    private static IEnumerable<Mac> AllPathMacs(NetworkPath? p, bool skipSelf) =>
        p is null ? [] : p.Hops.Where(h => !(skipSelf && h.Role == HopRole.ThisHost) && h.Mac is not null).Select(h => h.Mac!.Value);

    private static string NameOf(Mac m, FaultSnapshot s)
    {
        if (s.Nodes.TryGetValue(m, out var n)) return n.Label;
        var hop = s.Path?.Hops.FirstOrDefault(h => h.Mac == m);
        return hop is not null ? HopLabel(hop) : m.ToString();
    }

    /// <summary>"Inferred switch 'TV rack'", without doubling the prefix of auto-generated names.</summary>
    private static string InferredName(string name) =>
        name.StartsWith("Inferred", StringComparison.OrdinalIgnoreCase) ? name : $"Inferred switch '{name}'";
}
