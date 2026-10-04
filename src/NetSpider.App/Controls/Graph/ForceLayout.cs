using NetSpider.Core.Model;

namespace NetSpider.App.Controls.Graph;

/// <summary>
/// Fruchterman–Reingold style force layout with Barnes–Hut quadtree repulsion (O(n log n)), springs on topology links,
/// an elliptical "web ring" radial force per BFS depth, a weak radial-tree anchor, and AABB label collision (spatial hash).
/// The gateway is pinned at the origin and the Internet node above it. Not thread-safe: owned by the physics thread.
/// </summary>
public sealed class ForceLayout
{
    private GraphSnapshot _snap = GraphSnapshot.Empty;
    private float[] _x = [], _y = [], _vx = [], _vy = [];
    private bool[] _fixed = [];
    private readonly Dictionary<Mac, (float X, float Y)> _userPins = new();
    private readonly Quad _quad = new();
    private float _alpha = 1f;

    public const float AlphaMin = 0.004f;
    public float Alpha => _alpha;
    public bool Asleep => _alpha <= AlphaMin;
    public GraphSnapshot Snapshot => _snap;

    // tuning
    private const float Repulsion = 600f;
    private const float Theta2 = 0.81f; // θ = 0.9
    private const float LinkStrength = 0.025f;
    private const float RingStrength = 0.30f;
    private const float AnchorStrength = 0.05f;
    private const float VelocityDecay = 0.55f;
    private const float AlphaDecay = 0.018f;

    public void Reheat(float a = 0.6f) => _alpha = Math.Max(_alpha, a);

    public void SetSnapshot(GraphSnapshot snap)
    {
        var old = new Dictionary<Mac, (float, float, float, float)>(_snap.Nodes.Length);
        for (int i = 0; i < _snap.Nodes.Length && i < _x.Length; i++) old[_snap.Nodes[i].Mac] = (_x[i], _y[i], _vx[i], _vy[i]);

        int n = snap.Nodes.Length;
        _x = new float[n]; _y = new float[n]; _vx = new float[n]; _vy = new float[n]; _fixed = new bool[n];
        int added = 0;
        // place in depth order so parents get positions before their children
        foreach (var node in snap.Nodes.OrderBy(x => x.Depth))
        {
            int i = node.Index;
            if (old.TryGetValue(node.Mac, out var p)) { (_x[i], _y[i], _vx[i], _vy[i]) = p; continue; }
            added++;
            var (tx, ty) = AnchorTarget(snap, node);
            if (node.Parent >= 0 && node.Parent < n && old.ContainsKey(snap.Nodes[node.Parent].Mac))
            {
                // new device: spawn next to its parent and let it fly out to its ring (looks like a spider dropping in)
                var pp = old[snap.Nodes[node.Parent].Mac];
                _x[i] = pp.Item1 + (tx - pp.Item1) * 0.25f;
                _y[i] = pp.Item2 + (ty - pp.Item2) * 0.25f;
            }
            else { _x[i] = tx; _y[i] = ty; }
            // deterministic jitter breaks symmetry
            _x[i] += ((int)(node.Mac.Value % 17) - 8) * 0.7f;
            _y[i] += ((int)(node.Mac.Value % 13) - 6) * 0.7f;
        }
        _snap = snap;
        ApplyPins();
        if (added > 0) Reheat(added > n / 2 ? 1f : 0.5f);
        else Reheat(0.12f);
    }

    public static (float X, float Y) AnchorTarget(GraphSnapshot snap, GNode node)
    {
        if (node.Index == snap.Gateway) return (0, 0);
        if (node.IsInternet) return (0, -GraphBuilder.InternetOffset);
        float r = snap.RingRadius(node.Depth);
        return (MathF.Cos(node.AnchorAngle) * r * GraphSnapshot.Ex, MathF.Sin(node.AnchorAngle) * r * GraphSnapshot.Ey);
    }

    public void Pin(Mac mac, float x, float y)
    {
        _userPins[mac] = (x, y);
        if (_snap.Index.TryGetValue(mac, out var i) && i < _x.Length) { _x[i] = x; _y[i] = y; _vx[i] = _vy[i] = 0; _fixed[i] = true; }
        Reheat(0.25f);
    }

    public void Unpin(Mac mac)
    {
        if (!_userPins.Remove(mac)) return;
        ApplyPins();
        Reheat(0.4f);
    }

    public void ClearPins() { _userPins.Clear(); ApplyPins(); Reheat(0.6f); }

    /// <summary>Forgets every position and user pin (demo ↔ real switch): the next snapshot is laid out from scratch.</summary>
    public void Reset()
    {
        _userPins.Clear();
        _snap = GraphSnapshot.Empty;
        _x = []; _y = []; _vx = []; _vy = [];
        _fixed = [];
        _alpha = 1f;
    }

    /// <summary>Number of user-pinned nodes (diagnostics/tests).</summary>
    public int PinCount => _userPins.Count;

    private void ApplyPins()
    {
        Array.Clear(_fixed);
        for (int i = 0; i < _snap.Nodes.Length; i++)
        {
            var node = _snap.Nodes[i];
            if (_userPins.TryGetValue(node.Mac, out var p)) { _x[i] = p.X; _y[i] = p.Y; _fixed[i] = true; }
            else if (i == _snap.Gateway) { _x[i] = 0; _y[i] = 0; _fixed[i] = true; }
            else if (node.IsInternet) { _x[i] = 0; _y[i] = -GraphBuilder.InternetOffset; _fixed[i] = true; }
        }
    }

    public LayoutFrame Publish() => new(_snap, (float[])_x.Clone(), (float[])_y.Clone());

    /// <summary>Runs <paramref name="iterations"/> steps synchronously (headless snapshot / tests).</summary>
    public void Run(int iterations)
    {
        _alpha = 1f;
        for (int k = 0; k < iterations; k++) Step(force: true);
    }

    /// <summary>One simulation tick. Returns false when asleep (nothing moved).</summary>
    public bool Step(bool force = false)
    {
        int n = _snap.Nodes.Length;
        if (n == 0 || (!force && Asleep)) return false;
        var nodes = _snap.Nodes;
        float alpha = _alpha;

        // ---- Barnes–Hut repulsion ----
        _quad.Build(_x, _y, n);
        for (int i = 0; i < n; i++)
        {
            if (_fixed[i]) continue;
            var (fx, fy) = _quad.Force(i, _x[i], _y[i], Theta2);
            _vx[i] += fx * Repulsion * alpha;
            _vy[i] += fy * Repulsion * alpha;
        }

        // ---- springs on links ----
        foreach (var e in _snap.Edges)
        {
            int a = e.A, b = e.B;
            float dx = _x[b] - _x[a], dy = _y[b] - _y[a];
            float d = MathF.Sqrt(dx * dx + dy * dy) + 0.01f;
            float rest = nodes[a].Radius + nodes[b].Radius + (e.Kind switch
            {
                LinkKind.Wan => GraphBuilder.InternetOffset,
                LinkKind.VirtualHypervisor => 70f,
                LinkKind.WifiAssoc => 150f,
                _ => 150f,
            });
            float k = (d - rest) / d * LinkStrength * alpha;
            dx *= k; dy *= k;
            if (!_fixed[a]) { _vx[a] += dx * 0.5f; _vy[a] += dy * 0.5f; }
            if (!_fixed[b]) { _vx[b] -= dx * 0.5f; _vy[b] -= dy * 0.5f; }
        }

        // ---- elliptical ring + radial-tree anchor ----
        for (int i = 0; i < n; i++)
        {
            if (_fixed[i]) continue;
            var node = nodes[i];
            float r = _snap.RingRadius(node.Depth);
            // normalized elliptical radius
            float ex = _x[i] / GraphSnapshot.Ex, ey = _y[i] / GraphSnapshot.Ey;
            float cur = MathF.Sqrt(ex * ex + ey * ey) + 0.01f;
            float k = (r - cur) / cur * RingStrength * alpha;
            _vx[i] += _x[i] * k;
            _vy[i] += _y[i] * k;

            var (tx, ty) = AnchorTarget(_snap, node);
            _vx[i] += (tx - _x[i]) * AnchorStrength * alpha;
            _vy[i] += (ty - _y[i]) * AnchorStrength * alpha;
        }

        // ---- integrate ----
        for (int i = 0; i < n; i++)
        {
            if (_fixed[i]) { _vx[i] = _vy[i] = 0; continue; }
            _vx[i] *= VelocityDecay;
            _vy[i] *= VelocityDecay;
            float sp = MathF.Sqrt(_vx[i] * _vx[i] + _vy[i] * _vy[i]);
            if (sp > 40f) { _vx[i] *= 40f / sp; _vy[i] *= 40f / sp; }
            _x[i] += _vx[i];
            _y[i] += _vy[i];
        }

        // ---- label-box collision (always on, so labels never overlap) ----
        Collide(nodes, n, alpha);

        _alpha += (0 - _alpha) * AlphaDecay;
        if (_alpha < AlphaMin) _alpha = AlphaMin;
        return true;
    }

    private readonly Dictionary<long, List<int>> _grid = new();

    private void Collide(GNode[] nodes, int n, float alpha)
    {
        const float cell = 180f;
        foreach (var l in _grid.Values) l.Clear();
        for (int i = 0; i < n; i++)
        {
            long key = Key((int)MathF.Floor(_x[i] / cell), (int)MathF.Floor(_y[i] / cell));
            if (!_grid.TryGetValue(key, out var list)) _grid[key] = list = [];
            list.Add(i);
        }
        for (int i = 0; i < n; i++)
        {
            var ni = nodes[i];
            int cx = (int)MathF.Floor(_x[i] / cell), cy = (int)MathF.Floor(_y[i] / cell);
            for (int gx = cx - 1; gx <= cx + 1; gx++)
                for (int gy = cy - 1; gy <= cy + 1; gy++)
                {
                    if (!_grid.TryGetValue(Key(gx, gy), out var list)) continue;
                    foreach (var j in list)
                    {
                        if (j <= i) continue;
                        var nj = nodes[j];
                        // boxes: badge + label below it
                        float hwI = Math.Max(ni.Radius + 10, ni.LabelW / 2 + 9), hwJ = Math.Max(nj.Radius + 10, nj.LabelW / 2 + 9);
                        float topI = _y[i] - ni.Radius - 14, botI = _y[i] + ni.Radius + 12 + ni.LabelH;
                        float topJ = _y[j] - nj.Radius - 14, botJ = _y[j] + nj.Radius + 12 + nj.LabelH;
                        float ox = Math.Min(_x[i] + hwI, _x[j] + hwJ) - Math.Max(_x[i] - hwI, _x[j] - hwJ);
                        float oy = Math.Min(botI, botJ) - Math.Max(topI, topJ);
                        if (ox <= 0 || oy <= 0) continue;
                        bool fi = _fixed[i], fj = _fixed[j];
                        if (fi && fj) continue;
                        float wi = fi ? 0 : fj ? 1 : 0.5f, wj = fj ? 0 : fi ? 1 : 0.5f;
                        const float strength = 0.5f;
                        if (ox < oy)
                        {
                            float s = (_x[i] < _x[j] || (_x[i] == _x[j] && i < j)) ? -1 : 1;
                            float push = ox * strength;
                            _x[i] += s * push * wi; _x[j] -= s * push * wj;
                        }
                        else
                        {
                            float ci = (topI + botI) / 2, cj = (topJ + botJ) / 2;
                            float s = (ci < cj || (ci == cj && i < j)) ? -1 : 1;
                            float push = oy * strength;
                            _y[i] += s * push * wi; _y[j] -= s * push * wj;
                        }
                    }
                }
        }
        _ = alpha;
    }

    private static long Key(int x, int y) => ((long)x << 32) ^ (uint)y;

    /// <summary>Array-backed Barnes–Hut quadtree; rebuilt every step.</summary>
    private sealed class Quad
    {
        private float[] _cx = new float[256], _cy = new float[256], _mass = new float[256], _size = new float[256], _mx = new float[256], _my = new float[256];
        private int[] _child = new int[256 * 4];
        private int[] _body = new int[256];
        private int _count;
        private float[] _px = [], _py = [];

        public void Build(float[] x, float[] y, int n)
        {
            _px = x; _py = y;
            _count = 0;
            float minX = float.MaxValue, minY = float.MaxValue, maxX = float.MinValue, maxY = float.MinValue;
            for (int i = 0; i < n; i++)
            {
                minX = Math.Min(minX, x[i]); maxX = Math.Max(maxX, x[i]);
                minY = Math.Min(minY, y[i]); maxY = Math.Max(maxY, y[i]);
            }
            float size = Math.Max(maxX - minX, maxY - minY) + 1f;
            int root = NewCell((minX + maxX) / 2, (minY + maxY) / 2, size);
            for (int i = 0; i < n; i++) Insert(root, i, 0);
            Summarize(root);
        }

        private int NewCell(float cx, float cy, float size)
        {
            if (_count == _cx.Length)
            {
                int m = _count * 2;
                Array.Resize(ref _cx, m); Array.Resize(ref _cy, m); Array.Resize(ref _mass, m); Array.Resize(ref _size, m);
                Array.Resize(ref _mx, m); Array.Resize(ref _my, m); Array.Resize(ref _body, m); Array.Resize(ref _child, m * 4);
            }
            int c = _count++;
            _cx[c] = cx; _cy[c] = cy; _size[c] = size; _mass[c] = 0; _mx[c] = 0; _my[c] = 0; _body[c] = -1;
            _child[c * 4] = _child[c * 4 + 1] = _child[c * 4 + 2] = _child[c * 4 + 3] = -1;
            return c;
        }

        private void Insert(int c, int i, int depth)
        {
            while (true)
            {
                bool leaf = _child[c * 4] < 0 && _child[c * 4 + 1] < 0 && _child[c * 4 + 2] < 0 && _child[c * 4 + 3] < 0;
                if (leaf && _body[c] < 0 && _mass[c] == 0) { _body[c] = i; _mass[c] = 1; return; }
                if (depth > 24) { _mass[c] += 1; return; } // coincident points
                if (leaf && _body[c] >= 0)
                {
                    int existing = _body[c];
                    _body[c] = -1;
                    _mass[c] = 0;
                    PushDown(c, existing, depth);
                }
                int q = Quadrant(c, _px[i], _py[i]);
                int ch = _child[c * 4 + q];
                if (ch < 0)
                {
                    float h = _size[c] / 4;
                    ch = NewCell(_cx[c] + ((q & 1) != 0 ? h : -h), _cy[c] + ((q & 2) != 0 ? h : -h), _size[c] / 2);
                    _child[c * 4 + q] = ch;
                }
                c = ch;
                depth++;
            }
        }

        private void PushDown(int c, int i, int depth)
        {
            int q = Quadrant(c, _px[i], _py[i]);
            float h = _size[c] / 4;
            int ch = NewCell(_cx[c] + ((q & 1) != 0 ? h : -h), _cy[c] + ((q & 2) != 0 ? h : -h), _size[c] / 2);
            _child[c * 4 + q] = ch;
            Insert(ch, i, depth + 1);
        }

        private int Quadrant(int c, float x, float y) => (x >= _cx[c] ? 1 : 0) | (y >= _cy[c] ? 2 : 0);

        private void Summarize(int c)
        {
            if (_body[c] >= 0) { _mx[c] = _px[_body[c]]; _my[c] = _py[_body[c]]; _mass[c] = 1; return; }
            float m = 0, sx = 0, sy = 0;
            bool any = false;
            for (int k = 0; k < 4; k++)
            {
                int ch = _child[c * 4 + k];
                if (ch < 0) continue;
                Summarize(ch);
                m += _mass[ch]; sx += _mx[ch] * _mass[ch]; sy += _my[ch] * _mass[ch];
                any = true;
            }
            if (any && m > 0) { _mass[c] = m; _mx[c] = sx / m; _my[c] = sy / m; }
            else { _mx[c] = _cx[c]; _my[c] = _cy[c]; }
        }

        /// <summary>Sum of unit repulsion vectors (1/d falloff) acting on point i.</summary>
        public (float, float) Force(int i, float x, float y, float theta2)
        {
            float fx = 0, fy = 0;
            Span<int> stack = stackalloc int[256];
            int sp = 0;
            stack[sp++] = 0;
            while (sp > 0)
            {
                int c = stack[--sp];
                if (_mass[c] == 0) continue;
                float dx = x - _mx[c], dy = y - _my[c];
                float d2 = dx * dx + dy * dy;
                bool leaf = _body[c] >= 0;
                if (leaf && _body[c] == i) continue;
                if (leaf || _size[c] * _size[c] < theta2 * d2)
                {
                    if (d2 < 1f) { dx = (i % 7) - 3; dy = (i % 5) - 2; d2 = dx * dx + dy * dy + 1; }
                    d2 = Math.Max(d2, 400f);
                    float w = _mass[c] / d2;
                    fx += dx * w; fy += dy * w;
                    continue;
                }
                for (int k = 0; k < 4; k++)
                {
                    int ch = _child[c * 4 + k];
                    if (ch >= 0 && sp < stack.Length) stack[sp++] = ch;
                }
            }
            return (fx, fy);
        }
    }
}
