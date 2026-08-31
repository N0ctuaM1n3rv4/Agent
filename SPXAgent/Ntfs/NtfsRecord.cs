using System.Text;

namespace SpxAgent.Ntfs;

// Parsed view of a single MFT record ("FILE" record): header fields,
// attribute list, and USA-fixup handling.
internal sealed class NtfsRecord
{
    public const uint AttrStandardInformation = 0x10;
    public const uint AttrFileName = 0x30;
    public const uint AttrData = 0x80;
    public const uint AttrIndexRoot = 0x90;
    public const uint AttrIndexAllocation = 0xA0;
    public const uint AttrBitmap = 0xB0;
    public const uint AttrEnd = 0xFFFFFFFF;

    private const int OffMagic = 0;
    private const int OffUsaOffset = 4;   // u16
    private const int OffUsaCount = 6;    // u16
    private const int OffSequenceNumber = 0x10; // u16
    private const int OffFirstAttr = 0x14; // u16
    private const int OffFlags = 0x16;     // u16
    private const int OffUsedSize = 0x18;  // u32
    private const int OffBaseRecord = 0x20; // u64
    private const int OffMftRecordNumber = 0x2C; // u32

    public const ushort FlagInUse = 0x0001;
    public const ushort FlagDirectory = 0x0002;

    private readonly byte[] _record;

    public ushort Flags { get; }
    public ushort SequenceNumber { get; }
    public int FirstAttrOffset { get; }
    public int UsedSize { get; }
    public uint MftRecordNumber { get; }
    public ulong BaseRecord { get; }
    public bool IsDirectory => (Flags & FlagDirectory) != 0;
    public bool IsInUse => (Flags & FlagInUse) != 0;

    private NtfsRecord(byte[] record, ushort flags, ushort sequenceNumber, int firstAttr, int usedSize, uint mftNumber, ulong baseRecord)
    {
        _record = record;
        Flags = flags;
        SequenceNumber = sequenceNumber;
        FirstAttrOffset = firstAttr;
        UsedSize = usedSize;
        MftRecordNumber = mftNumber;
        BaseRecord = baseRecord;
    }

    // Load record `number` from the MFT, applying USA fixup.
    public static NtfsRecord Read(NtfsVolume vol, long number)
    {
        byte[] raw = vol.ReadBytes(vol.MftOffset + number * vol.RecordSize, vol.RecordSize);
        if (raw.Length < 0x30 || Encoding.ASCII.GetString(raw, 0, 4) != "FILE")
            throw new InvalidDataException($"MFT record {number}: bad magic");

        byte[] fixedRecord = ApplyUsaFixup(vol, raw);
        ushort flags = ReadU16(fixedRecord, OffFlags);
        ushort sequenceNumber = ReadU16(fixedRecord, OffSequenceNumber);
        int firstAttr = ReadU16(fixedRecord, OffFirstAttr);
        int usedSize = (int)ReadU32(fixedRecord, OffUsedSize);
        uint mftNumber = (uint)ReadU32(fixedRecord, OffMftRecordNumber);
        ulong baseRecord = ReadU64(fixedRecord, OffBaseRecord);
        return new NtfsRecord(fixedRecord, flags, sequenceNumber, firstAttr, usedSize, mftNumber, baseRecord);
    }

    // USA (Update Sequence Array) fixup: every sector's last 2 bytes hold the
    // sequence number; the real values are stashed in the USA array.
    private static byte[] ApplyUsaFixup(NtfsVolume vol, byte[] raw)
    {
        int usaOffset = ReadU16(raw, OffUsaOffset);
        int usaCount = ReadU16(raw, OffUsaCount);
        if (usaCount == 0 || usaOffset + usaCount * 2 > raw.Length)
            return raw;

        byte[] copy = (byte[])raw.Clone();
        ushort usn = ReadU16(copy, usaOffset);
        for (int i = 1; i < usaCount; i++)
        {
            int sectorEnd = i * vol.BytesPerSector - 2;
            if (sectorEnd < 0 || sectorEnd + 2 > copy.Length) break;
            ushort backup = ReadU16(copy, usaOffset + i * 2);
            copy[sectorEnd] = (byte)(backup & 0xFF);
            copy[sectorEnd + 1] = (byte)(backup >> 8);
        }
        return copy;
    }

    // Iterate all attributes (type + raw byte range). Stops at the end marker.
    public IEnumerable<NtfsAttribute> Attributes()
    {
        int off = FirstAttrOffset;
        while (off + 8 <= UsedSize)
        {
            uint type = ReadU32(_record, off);
            if (type == AttrEnd) yield break;
            if (type == 0) yield break; // safety
            uint length = ReadU32(_record, off + 4);
            if (length < 16 || off + length > _record.Length) yield break;
            yield return NtfsAttribute.Create(_record, off, (int)length);
            off += (int)length;
        }
    }

    // Find the first attribute of the given type (optionally a named one).
    public NtfsAttribute? FindAttribute(uint type, string? name = null)
    {
        foreach (NtfsAttribute attr in Attributes())
        {
            if (attr.Type != type) continue;
            if (name is null) return attr;
            if (string.Equals(attr.Name, name, StringComparison.Ordinal)) return attr;
        }
        return null;
    }

    // Name from the first FILE_NAME attribute (Win32 namespace preferred).
    public string? FileName()
    {
        foreach (NtfsAttribute attr in Attributes())
        {
            if (attr.Type != AttrFileName) continue;
            string? n = NtfsAttribute.ParseFileName(attr);
            if (n is not null) return n;
        }
        return null;
    }

    internal byte[] Raw => _record;

    // Debug helpers used by the verification harness (not part of the public API).
    public static byte[] FixupForDebug(NtfsVolume vol, byte[] raw) => ApplyUsaFixup(vol, raw);
    public static NtfsRecord FromBytesForDebug(NtfsVolume vol, byte[] fixedRecord, long recordNumber)
    {
        ushort flags = ReadU16(fixedRecord, OffFlags);
        ushort sequenceNumber = ReadU16(fixedRecord, OffSequenceNumber);
        int firstAttr = ReadU16(fixedRecord, OffFirstAttr);
        int usedSize = (int)ReadU32(fixedRecord, OffUsedSize);
        uint mftNumber = (uint)ReadU32(fixedRecord, OffMftRecordNumber);
        ulong baseRecord = ReadU64(fixedRecord, OffBaseRecord);
        return new NtfsRecord(fixedRecord, flags, sequenceNumber, firstAttr, usedSize, mftNumber, baseRecord);
    }

    private static ushort ReadU16(ReadOnlySpan<byte> b, int off) =>
        (ushort)(b[off] | (b[off + 1] << 8));

    private static uint ReadU32(ReadOnlySpan<byte> b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));

    private static ulong ReadU64(ReadOnlySpan<byte> b, int off)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v |= (ulong)b[off + i] << (8 * i);
        return v;
    }
}
