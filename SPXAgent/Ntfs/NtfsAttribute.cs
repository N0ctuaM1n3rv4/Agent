using System.Text;

namespace SpxAgent.Ntfs;

// One attribute inside an MFT record: common header + resident/non-resident
// payload, plus runlist decoding for non-resident data.
internal sealed class NtfsAttribute
{
    // Common header offsets.
    private const int OffType = 0;        // u32
    private const int OffLength = 4;      // u32
    private const int OffNonResident = 8; // u8
    private const int OffNameLength = 9;  // u8
    private const int OffNameOffset = 10; // u16
    private const int OffFlags = 12;      // u16
    private const int OffAttrId = 14;     // u16

    // Resident header.
    private const int OffResValueLength = 16; // u32
    private const int OffResValueOffset = 20; // u16

    // Non-resident header.
    private const int OffNrLowestVcn = 16;        // u64
    private const int OffNrMappingPairs = 32;     // u16
    private const int OffNrAllocatedSize = 40;    // u64
    private const int OffNrDataSize = 48;         // u64
    private const int OffNrInitializedSize = 56;  // u64

    private readonly byte[] _record;
    private readonly int _offset;
    private readonly int _length;

    public uint Type { get; }
    public bool NonResident { get; }
    public string? Name { get; }
    public bool Compressed => (ReadU16(OffFlags) & 0x0001) != 0;

    public int Offset => _offset;

    // Expose the raw record buffer + mapping-pairs offset for debugging.
    public byte[] RawRecord => _record;
    public int MappingPairsOffset => NonResident
        ? _offset + ReadU16(_record, _offset + OffNrMappingPairs)
        : 0;

    public long DataSize
    {
        get
        {
            if (NonResident) return (long)ReadU64(_record, _offset + OffNrDataSize);
            return ReadU32(_record, _offset + OffResValueLength);
        }
    }

    private NtfsAttribute(byte[] record, int offset, int length, uint type, bool nonResident, string? name)
    {
        _record = record;
        _offset = offset;
        _length = length;
        Type = type;
        NonResident = nonResident;
        Name = name;
    }

    public static NtfsAttribute Create(byte[] record, int offset, int length)
    {
        uint type = ReadU32(record, offset);
        bool nonResident = record[offset + OffNonResident] != 0;
        int nameLength = record[offset + OffNameLength];
        int nameOffset = offset + ReadU16(record, offset + OffNameOffset);
        string? name = null;
        if (nameLength > 0 && nameOffset + nameLength * 2 <= record.Length)
            name = Encoding.Unicode.GetString(record, nameOffset, nameLength * 2);
        return new NtfsAttribute(record, offset, length, type, nonResident, name);
    }

    // Resident value bytes.
    public ReadOnlySpan<byte> ResidentValue()
    {
        if (NonResident) throw new InvalidOperationException("attribute is non-resident");
        uint valueLength = ReadU32(_record, _offset + OffResValueLength);
        int valueOffset = _offset + ReadU16(_record, _offset + OffResValueOffset);
        return _record.AsSpan(valueOffset, (int)valueLength);
    }

    // Absolute offset of the resident value within the record buffer, plus its length.
    public (int Offset, int Length) ResidentValueLocation()
    {
        if (NonResident) throw new InvalidOperationException("attribute is non-resident");
        uint valueLength = ReadU32(_record, _offset + OffResValueLength);
        int valueOffset = _offset + ReadU16(_record, _offset + OffResValueOffset);
        return (valueOffset, (int)valueLength);
    }

    // Full content of this attribute as bytes (resident directly, non-resident
    // via runlist). Reads through the raw volume.
    public byte[] ReadValue(NtfsVolume vol, long start = 0, long length = -1)
    {
        if (!NonResident)
        {
            ReadOnlySpan<byte> value = ResidentValue();
            if (start >= value.Length) return Array.Empty<byte>();
            long take = length < 0 ? value.Length - start : Math.Min(length, value.Length - start);
            return value.Slice((int)start, (int)take).ToArray();
        }

        long dataSize = DataSize;
        if (start >= dataSize) return Array.Empty<byte>();
        long count = length < 0 ? dataSize - start : Math.Min(length, dataSize - start);
        return ReadNonResidentRange(vol, start, count);
    }

    private byte[] ReadNonResidentRange(NtfsVolume vol, long start, long count)
    {
        byte[] result = new byte[count];
        long clusterSize = vol.ClusterSize;
        long logicalVcn = start / clusterSize;
        long fileOffset = 0;
        long outOffset = 0;

        foreach ((long lcn, long runLen) in Runlist())
        {
            long runEndVcn = fileOffset / clusterSize + runLen;
            if (logicalVcn >= fileOffset / clusterSize && logicalVcn < runEndVcn)
            {
                long runStartVcn = fileOffset / clusterSize;
                long skipClusters = logicalVcn - runStartVcn;
                if (lcn < 0)
                {
                    // Sparse: zeros.
                    long zeros = runLen * clusterSize - skipClusters * clusterSize;
                    if (zeros > count - outOffset) zeros = count - outOffset;
                    result.AsSpan((int)outOffset, (int)zeros).Clear();
                    outOffset += zeros;
                    logicalVcn += zeros / clusterSize;
                    fileOffset += runLen * clusterSize;
                    if (outOffset >= count) break;
                    continue;
                }

                long dataOffset = (lcn + skipClusters) * clusterSize;
                long offsetInRun = (start + outOffset) - logicalVcn * clusterSize;
                if (offsetInRun < 0) offsetInRun = 0;
                dataOffset += offsetInRun;
                long avail = runLen * clusterSize - skipClusters * clusterSize - offsetInRun;
                long want = count - outOffset;
                if (avail > want) avail = want;
                byte[] chunk = vol.ReadBytes(dataOffset, (int)avail);
                chunk.CopyTo(result, outOffset);
                outOffset += avail;
                logicalVcn = (start + outOffset) / clusterSize;
                if (outOffset >= count) break;
            }
            fileOffset += runLen * clusterSize;
        }
        return result;
    }

    // Decode the runlist (VCN->LCN mapping) of a non-resident attribute.
    // Returns (lcn, runLengthInClusters); lcn == -1 marks a sparse run.
    public IEnumerable<(long Lcn, long RunLength)> Runlist()
    {
        if (!NonResident) yield break;
        int mappingPairsOffset = _offset + ReadU16(_record, _offset + OffNrMappingPairs);
        long lcn = 0;
        long vcn = 0;
        int off = mappingPairsOffset;

        while (off < _offset + _length)
        {
            byte header = _record[off++];
            // NTFS runlist header: LOW nibble = length-field byte count,
            // HIGH nibble = offset-field byte count (verified against
            // NTFSExplorer.exe sub_140005E10 and live-volume probes).
            int lengthBytes = header & 0x0F;
            int offsetBytes = header >> 4;
            if (lengthBytes == 0) break; // end of runlist
            if (off + lengthBytes + offsetBytes > _record.Length) break;

            long runLength = DecodeUnsigned(_record, off, lengthBytes);
            off += lengthBytes;
            long delta = DecodeSigned(_record, off, offsetBytes);
            off += offsetBytes;

            if (delta == 0 && vcn == 0)
            {
                // First run with no offset -> sparse from VCN 0.
                yield return (-1, runLength);
            }
            else if (delta == 0)
            {
                yield return (-1, runLength);
            }
            else
            {
                lcn += delta;
                yield return (lcn, runLength);
            }
            vcn += runLength;
        }
    }

    // ---------- semantic extractors ----------

    // Parse a FILE_NAME (0x30) attribute's embedded name (Win32 namespace).
    public static string? ParseFileName(NtfsAttribute attr)
    {
        if (attr.NonResident) return null;
        ReadOnlySpan<byte> v = attr.ResidentValue();
        if (v.Length < 0x42 + 2) return null;
        int nameLength = v[0x40];
        int nameOffset = 0x42;
        if (nameOffset + nameLength * 2 > v.Length) return null;
        return Encoding.Unicode.GetString(v.Slice(nameOffset, nameLength * 2));
    }

    // Extract (isDirectory, size, modifiedEpochSeconds) from a FILE_NAME value.
    public static (bool IsDir, long Size, long ModTimeUnix) ParseFileNameMeta(NtfsAttribute attr)
    {
        ReadOnlySpan<byte> v = attr.ResidentValue();
        return ParseFileNameMetaFromSpan(v);
    }

    public static (bool IsDir, long Size, long ModTimeUnix) ParseFileNameMetaFromSpan(ReadOnlySpan<byte> v)
    {
        bool isDir = v.Length >= 0x3C && (ReadU32(v, 0x38) & 0x10000000) != 0;
        long realSize = v.Length >= 0x38 ? (long)ReadU64(v, 0x30) : 0;
        long modTime = v.Length >= 0x18 ? FileTimeToUnix(ReadU64(v, 0x10)) : 0;
        return (isDir, realSize, modTime);
    }

    // STANDARD_INFORMATION (0x10): modified time (FILETIME) at offset 0x08.
    public static long ParseStandardInfoModTime(NtfsAttribute attr)
    {
        ReadOnlySpan<byte> v = attr.ResidentValue();
        if (v.Length < 0x10) return 0;
        return FileTimeToUnix(ReadU64(v, 0x08));
    }

    // ---------- helpers ----------

    private static long FileTimeToUnix(ulong fileTime)
    {
        // FILETIME = 100ns intervals since 1601-01-01; Unix epoch 1970-01-01.
        const ulong epochDiff = 116444736000000000UL;
        if (fileTime < epochDiff) return 0;
        return (long)((fileTime - epochDiff) / 10_000_000);
    }

    private ushort ReadU16(int off) => ReadU16(_record, _offset + off);
    private uint ReadU32(int off) => ReadU32(_record, _offset + off);

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

    private static long DecodeUnsigned(byte[] b, int off, int len)
    {
        long v = 0;
        for (int i = 0; i < len; i++) v |= (long)b[off + i] << (8 * i);
        return v;
    }

    private static long DecodeSigned(byte[] b, int off, int len)
    {
        long v = 0;
        for (int i = 0; i < len; i++) v |= (long)b[off + i] << (8 * i);
        // Sign-extend from `len` bytes.
        int shift = 64 - len * 8;
        v = (v << shift) >> shift;
        return v;
    }
}
