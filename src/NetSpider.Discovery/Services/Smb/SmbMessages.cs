using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NetSpider.Discovery.Services.Smb;

/// <summary>Pre-built SMB request byte blobs (without the NBSS length prefix).</summary>
internal static class SmbMessages
{
    /// <summary>SMB2 NEGOTIATE requesting dialects 0x0202–0x0311.</summary>
    public static byte[] Smb2Negotiate()
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        WriteSmb2Header(w, command: 0x0000, messageId: 0);
        ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
        w.Write((ushort)36);                 // StructureSize
        w.Write((ushort)dialects.Length);    // DialectCount
        w.Write((ushort)0x0001);             // SecurityMode = signing enabled
        w.Write((ushort)0);                  // Reserved
        w.Write((uint)0x00000000);           // Capabilities
        w.Write(Guid.NewGuid().ToByteArray()); // ClientGuid
        int ctxOffsetField = (int)ms.Position;
        w.Write((uint)0);                    // NegotiateContextOffset (backfilled)
        w.Write((ushort)1);                  // NegotiateContextCount
        w.Write((ushort)0);                  // Reserved2
        foreach (var d in dialects) w.Write(d);
        // Offering 3.1.1 requires a PREAUTH_INTEGRITY context; Windows resets the connection without it.
        while (ms.Position % 8 != 0) w.Write((byte)0);
        int ctxOffset = (int)ms.Position;    // relative to the SMB2 header, which starts at 0
        w.Write((ushort)0x0001);             // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        w.Write((ushort)38);                 // DataLength
        w.Write((uint)0);                    // Reserved
        w.Write((ushort)1);                  // HashAlgorithmCount
        w.Write((ushort)32);                 // SaltLength
        w.Write((ushort)0x0001);             // SHA-512
        w.Write(RandomNumberGenerator.GetBytes(32));
        var buf = ms.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(ctxOffsetField), (uint)ctxOffset);
        return buf;
    }

    /// <summary>SMB2 SESSION_SETUP carrying an NTLMSSP NEGOTIATE token (raw, no SPNEGO wrapper).</summary>
    public static byte[] Smb2SessionSetup()
    {
        var ntlm = NtlmNegotiate();
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        WriteSmb2Header(w, command: 0x0001, messageId: 1);
        int bodyStart = (int)ms.Position;
        w.Write((ushort)25);     // StructureSize
        w.Write((byte)0);        // Flags
        w.Write((byte)0);        // SecurityMode
        w.Write((uint)0);        // Capabilities
        w.Write((uint)0);        // Channel
        // SecurityBufferOffset is from the start of the SMB2 header (which is 64 bytes in).
        int secBufOffsetField = (int)ms.Position;
        w.Write((ushort)0);      // placeholder offset
        w.Write((ushort)ntlm.Length); // SecurityBufferLength
        w.Write((ulong)0);       // PreviousSessionId
        int secBufPos = (int)ms.Position;
        w.Write(ntlm);
        var buf = ms.ToArray();
        // backfill SecurityBufferOffset = secBufPos (relative to SMB2 header start = 0)
        ushort off = (ushort)secBufPos;
        buf[secBufOffsetField] = (byte)off;
        buf[secBufOffsetField + 1] = (byte)(off >> 8);
        return buf;
    }

    private static void WriteSmb2Header(BinaryWriter w, ushort command, ulong messageId)
    {
        w.Write(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' }); // ProtocolId
        w.Write((ushort)64);   // StructureSize
        w.Write((ushort)0);    // CreditCharge
        w.Write((uint)0);      // Status / ChannelSequence
        w.Write(command);      // Command
        w.Write((ushort)1);    // CreditRequest
        w.Write((uint)0);      // Flags
        w.Write((uint)0);      // NextCommand
        w.Write(messageId);    // MessageId
        w.Write((uint)0);      // Reserved (ProcessId)
        w.Write((uint)0);      // TreeId
        w.Write((ulong)0);     // SessionId
        w.Write(new byte[16]); // Signature
    }

    /// <summary>Minimal NTLMSSP NEGOTIATE (type 1) token.</summary>
    public static byte[] NtlmNegotiate()
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(Encoding.ASCII.GetBytes("NTLMSSP\0"));
        w.Write((uint)1); // MessageType = NEGOTIATE
        // Flags: UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | NEGOTIATE_VERSION | 128 | 56
        uint flags = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000200 | 0x00008000 | 0x02000000 | 0x20000000 | 0x80000000;
        w.Write(flags);
        w.Write((ulong)0); // DomainNameFields
        w.Write((ulong)0); // WorkstationFields
        w.Write(new byte[] { 10, 0, 0, 0, 0, 0, 0, 0x0F }); // Version (Windows 10-ish, NTLM revision 15)
        return ms.ToArray();
    }

    /// <summary>SMB1 NEGOTIATE PROTOCOL request advertising the NT LM 0.12 dialect.</summary>
    public static byte[] Smb1Negotiate()
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }); // protocol
        w.Write((byte)0x72);   // SMB_COM_NEGOTIATE
        w.Write((uint)0);      // Status
        w.Write((byte)0x18);   // Flags
        w.Write((ushort)0xC853); // Flags2
        w.Write((ushort)0);    // PIDHigh
        w.Write(new byte[8]);  // SecuritySignature
        w.Write((ushort)0);    // Reserved
        w.Write((ushort)0);    // TID
        w.Write((ushort)0xFEFF); // PIDLow
        w.Write((ushort)0);    // UID
        w.Write((ushort)0);    // MID
        w.Write((byte)0);      // WordCount
        var dialects = "\x02NT LM 0.12\0";
        var bytes = Encoding.ASCII.GetBytes(dialects);
        w.Write((ushort)bytes.Length); // ByteCount
        w.Write(bytes);
        return ms.ToArray();
    }
}
