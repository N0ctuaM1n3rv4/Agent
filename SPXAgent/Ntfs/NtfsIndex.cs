using System.Text;

namespace SpxAgent.Ntfs;

// One directory entry discovered in an index.
internal sealed class NtfsDirEntry
{
    public required string Name { get; init; }
    public required bool IsDir { get; init; }
    public required long Size { get; init; }
    public required long ModTimeUnix { get; init; }
    public required ulong FileReference { get; init; }
    public ulong ParentReference { get; init; }
}

// Parsed raw index entry used by the writer when it needs to move existing
// entries between the resident INDEX_ROOT and INDX blocks (B* spill/rebuild).
internal sealed class IndexEntryInfo
{
    public ulong FileReference { get; }
    public int EntryLength { get; }
    public int KeyLength { get; }
    public byte Flags { get; }
    public string? Name { get; }
    public ulong SubnodeVcn { get; }

    public IndexEntryInfo(ulong fileRef, int entryLength, int keyLength, byte flags, string? name, ulong subnodeVcn)
    {
        FileReference = fileRef;
        EntryLength = entryLength;
        KeyLength = keyLength;
        Flags = flags;
        Name = name;
        SubnodeVcn = subnodeVcn;
    }
}

// Directory index parsing: enumerates INDEX_ROOT / INDEX_ALLOCATION and the
// INDX blocks that hold the actual B-tree of FILE_NAME keys.
internal static class NtfsIndex
{
    // INDEX_ENTRY_HEADER offsets (relative to entry start).
    // Per Linux-NTFS spec (Table 2.29):
    //   0x00 u64 file reference
    //   0x08 u16 L = length of the index entry
    //   0x0A u16 M = length of the stream (key)
    //   0x0C u8  flags (0x01 sub-node, 0x02 last entry)
    //   0x0D 3   reserved padding
    //   0x10 M   stream (the FILE_NAME key for a directory)
    //   L-8  8   VCN of sub-node (only when flags & 0x01)
    private const int OffEntryFileRef = 0;      // u64
    private const int OffEntryLength = 8;       // u16
    private const int OffEntryKeyLength = 10;   // u16
    private const int OffEntryFlags = 12;       // u8
    private const int OffEntryKey = 16;         // FILE_NAME key

    private const byte FlagEntryHasSubnode = 0x01;
    private const byte FlagEntryLast = 0x02;

    // INDEX_HEADER offsets (relative to header start).
    // Per Linux-NTFS spec (Table 2.25):
    //   0x00 u32 offset to first index entry
    //   0x04 u32 total size of the index entries
    //   0x08 u32 allocated size of the index entries
    //   0x0C u8  flags (0x00 small index, 0x01 large index)
    //   0x0D 3   reserved padding
    private const int OffIndexEntriesOffset = 0; // u32
    private const int OffIndexLength = 4;        // u32
    private const int OffIndexAllocated = 8;     // u32
    private const int OffIndexFlags = 12;        // u8

    // INDEX_ROOT attribute value layout.
    private const int OffIndexRootHeader = 16;  // INDEX_HEADER at value+0x10

    // INDX block layout.
    private const int OffIndxHeader = 0x18;     // INDEX_HEADER at block+0x18

    // Enumerate all entries in a directory record, following INDEX_ROOT and
    // any INDEX_ALLOCATION (non-resident INDX blocks). Returns entries keyed
    // by their FILE_NAME; root-entry "." and ".." are filtered out.
    public static List<NtfsDirEntry> Enumerate(NtfsVolume vol, NtfsRecord dirRecord)
    {
        var results = new List<NtfsDirEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        NtfsAttribute? rootAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexRoot);
        if (rootAttr is null) return results;

        if (!rootAttr.NonResident)
        {
            ReadOnlySpan<byte> value = rootAttr.ResidentValue();
            int headerOffset = OffIndexRootHeader;
            EnumerateHeaderEntries(vol, value, headerOffset, results, seen);
        }

        // Large directories spill into INDEX_ALLOCATION (INDX blocks).
        NtfsAttribute? allocAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexAllocation);
        if (allocAttr is not null && allocAttr.NonResident)
        {
            byte[] blocks = allocAttr.ReadValue(vol);
            int blockSize = vol.IndexBlockSize;
            if (blockSize <= 0) blockSize = 4096;
            for (int off = 0; off + blockSize <= blocks.Length; off += blockSize)
            {
                if (blocks.Length - off < 0x18) break;
                if (Encoding.ASCII.GetString(blocks, off, 4) != "INDX") continue;
                // Each INDX block carries its own USA fixup.
                byte[] fixedBlock = ApplyUsaFixup(vol, blocks.AsSpan(off, blockSize).ToArray());
                EnumerateHeaderEntries(vol, fixedBlock, OffIndxHeader, results, seen);
            }
        }

        return results;
    }

    // Parse INDEX_HEADER at `headerOffset` within `buffer` and walk entries.
    private static void EnumerateHeaderEntries(NtfsVolume vol, ReadOnlySpan<byte> buffer,
        int headerOffset, List<NtfsDirEntry> results, HashSet<string> seen)
    {
        if (headerOffset + 16 > buffer.Length) return;
        int entriesOffset = (int)ReadU32(buffer, headerOffset + OffIndexEntriesOffset);
        int indexLength = (int)ReadU32(buffer, headerOffset + OffIndexLength);
        int entriesStart = headerOffset + entriesOffset;
        int entriesEnd = Math.Min(headerOffset + indexLength, buffer.Length);
        int off = entriesStart;

        while (off + 16 <= entriesEnd)
        {
            byte flags = buffer[off + OffEntryFlags]; // u8 per spec
            int entryLength = ReadU16(buffer, off + OffEntryLength);
            int keyLength = ReadU16(buffer, off + OffEntryKeyLength);
            if (entryLength < 16 || off + entryLength > entriesEnd + 8) break;

            if ((flags & FlagEntryLast) != 0)
            {
                // Terminal entry; it may carry a subnode VCN but no name key.
                break;
            }

            if (keyLength >= 0x42 && off + OffEntryKey + keyLength <= buffer.Length)
            {
                ReadOnlySpan<byte> key = buffer.Slice(off + OffEntryKey, keyLength);
                ulong fileRef = ReadU64(buffer, off + OffEntryFileRef);
                long recordNum = (long)(fileRef & 0x0000FFFFFFFFFFFFUL);
                ulong parentRef = ReadU64(key, 0);
                int nameLength = key[0x40];
                int nameOffset = 0x42;
                if (nameOffset + nameLength * 2 <= key.Length)
                {
                    string name = Encoding.Unicode.GetString(key.Slice(nameOffset, nameLength * 2));
                    // Skip "." and ".." and duplicates.
                    if (name is "." or ".." || !seen.Add(name))
                    {
                        off += entryLength;
                        continue;
                    }
                    (bool isDir, long size, long modTime) = NtfsAttribute.ParseFileNameMetaFromSpan(key);
                    results.Add(new NtfsDirEntry
                    {
                        Name = name,
                        IsDir = isDir,
                        Size = size,
                        ModTimeUnix = modTime,
                        FileReference = fileRef,
                        ParentReference = parentRef,
                    });
                }
            }

            off += entryLength;
        }
    }

    // Find a child entry by name in a directory record. Returns its file
    // reference or 0 if absent. Walks INDEX_ROOT + INDEX_ALLOCATION like
    // Enumerate but short-circuits on name match.
    public static ulong Find(NtfsVolume vol, NtfsRecord dirRecord, string name)
    {
        foreach (NtfsDirEntry e in Enumerate(vol, dirRecord))
        {
            if (string.Equals(e.Name, name, StringComparison.Ordinal))
                return e.FileReference;
        }
        return 0;
    }

    // Public debug helper (used by the verification harness).
    public static byte[] ApplyUsaForDebug(NtfsVolume vol, byte[] block) => ApplyUsaFixup(vol, block);

    // Read a single INDX block by VCN from a directory's INDEX_ALLOCATION,
    // applying its USA fixup. INDX blocks are one cluster each, VCN-contiguous.
    public static byte[]? ReadIndxBlock(NtfsVolume vol, NtfsRecord dirRecord, long vcn)
    {
        NtfsAttribute? allocAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexAllocation);
        if (allocAttr is null || !allocAttr.NonResident) return null;
        int blockSize = vol.IndexBlockSize;
        if (blockSize <= 0) blockSize = 4096;
        byte[] raw = allocAttr.ReadValue(vol, vcn * blockSize, blockSize);
        if (raw.Length < 0x18 || Encoding.ASCII.GetString(raw, 0, 4) != "INDX") return null;
        return ApplyUsaFixup(vol, raw);
    }

    // Parse the separator entries from a directory's INDEX_ROOT (the ones with
    // a sub-node pointer). Returns (name, raw entry bytes, subnode VCN).
    public static List<(string Name, byte[] Raw, ulong Vcn)> CollectRootSeparators(NtfsRecord dirRecord)
    {
        var results = new List<(string, byte[], ulong)>();
        NtfsAttribute? rootAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexRoot);
        if (rootAttr is null || rootAttr.NonResident) return results;
        ReadOnlySpan<byte> value = rootAttr.ResidentValue();
        int headerOffset = OffIndexRootHeader;
        if (headerOffset + 16 > value.Length) return results;
        int entriesOffset = (int)ReadU32(value, headerOffset + OffIndexEntriesOffset);
        int indexLength = (int)ReadU32(value, headerOffset + OffIndexLength);
        int off = headerOffset + entriesOffset;
        int end = Math.Min(headerOffset + indexLength, value.Length);
        while (off + 16 <= end)
        {
            var info = ParseEntryInfo(value, off, end);
            if (info is null) break;
            if ((info.Flags & FlagEntryLast) != 0) break;
            byte[] raw = value.Slice(off, info.EntryLength).ToArray();
            results.Add((info.Name ?? "", raw, info.SubnodeVcn));
            off += info.EntryLength;
        }
        return results;
    }

    // Read the terminator's sub-node VCN from a directory's INDEX_ROOT (the
    // catch-all pointer to the last leaf). Returns -1 if none.
    public static long ReadRootTerminatorVcn(NtfsRecord dirRecord)
    {
        NtfsAttribute? rootAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexRoot);
        if (rootAttr is null || rootAttr.NonResident) return -1;
        ReadOnlySpan<byte> value = rootAttr.ResidentValue();
        int headerOffset = OffIndexRootHeader;
        if (headerOffset + 16 > value.Length) return -1;
        int entriesOffset = (int)ReadU32(value, headerOffset + OffIndexEntriesOffset);
        int indexLength = (int)ReadU32(value, headerOffset + OffIndexLength);
        int off = headerOffset + entriesOffset;
        int end = Math.Min(headerOffset + indexLength, value.Length);
        while (off + 16 <= end)
        {
            var info = ParseEntryInfo(value, off, end);
            if (info is null) break;
            if ((info.Flags & FlagEntryLast) != 0)
                return (long)info.SubnodeVcn;
            off += info.EntryLength;
        }
        return -1;
    }

    // ---- write-side helpers (used by NtfsWriter) ----

    // Parse one index entry out of a (USA-fixed) buffer at `entryOffset`.
    // Returns null if the buffer is exhausted/invalid. Includes the key name
    // when present. Used by NtfsWriter to read existing entries back.
    public static IndexEntryInfo? ParseEntryInfo(ReadOnlySpan<byte> buffer, int entryOffset, int entriesEnd)
    {
        if (entryOffset + 16 > entriesEnd) return null;
        ulong fileRef = ReadU64(buffer, entryOffset);
        int entryLength = ReadU16(buffer, entryOffset + OffEntryLength);
        int keyLength = ReadU16(buffer, entryOffset + OffEntryKeyLength);
        byte flags = buffer[entryOffset + OffEntryFlags];
        if (entryLength < 16 || entryOffset + entryLength > entriesEnd + 8) return null;
        string? name = null;
        ulong subnode = 0;
        if (keyLength >= 0x42 && entryOffset + OffEntryKey + keyLength <= buffer.Length)
        {
            ReadOnlySpan<byte> key = buffer.Slice(entryOffset + OffEntryKey, keyLength);
            int nameLength = key[0x40];
            int nameOffset = 0x42;
            if (nameOffset + nameLength * 2 <= key.Length)
                name = Encoding.Unicode.GetString(key.Slice(nameOffset, nameLength * 2));
        }
        if ((flags & FlagEntryHasSubnode) != 0 && entryLength >= 24)
            subnode = ReadU64(buffer, entryOffset + entryLength - 8);
        return new IndexEntryInfo(fileRef, entryLength, keyLength, flags, name, subnode);
    }

    // The terminator entry: no key, flags=0x02 (last), length=16.
    public static void WriteTerminator(Span<byte> dest, int offset)
    {
        dest[offset + OffEntryFlags] = 0x02; // last entry
    }

    // Collect all real index entries (raw entry bytes + name), deduped by name.
    // Mirrors Enumerate(): walks the resident INDEX_ROOT and, when present, the
    // INDEX_ALLOCATION INDX blocks. Terminator entries and "." / ".." are
    // skipped. Used by NtfsWriter when rebuilding a directory's B* tree.
    public static List<(string Name, byte[] Raw)> CollectRawEntries(NtfsVolume vol, NtfsRecord dirRecord)
    {
        var results = new List<(string, byte[])>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        NtfsAttribute? rootAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexRoot);
        if (rootAttr is null) return results;
        if (!rootAttr.NonResident)
        {
            ReadOnlySpan<byte> value = rootAttr.ResidentValue();
            CollectRawFromHeader(value, OffIndexRootHeader, results, seen);
        }

        NtfsAttribute? allocAttr = dirRecord.FindAttribute(NtfsRecord.AttrIndexAllocation);
        if (allocAttr is not null && allocAttr.NonResident)
        {
            byte[] blocks = allocAttr.ReadValue(vol);
            int blockSize = vol.IndexBlockSize;
            if (blockSize <= 0) blockSize = 4096;
            for (int off = 0; off + blockSize <= blocks.Length; off += blockSize)
            {
                if (Encoding.ASCII.GetString(blocks, off, 4) != "INDX") continue;
                byte[] fixedBlock = ApplyUsaFixup(vol, blocks.AsSpan(off, blockSize).ToArray());
                CollectRawFromHeader(fixedBlock, OffIndxHeader, results, seen);
            }
        }
        return results;
    }

    private static void CollectRawFromHeader(ReadOnlySpan<byte> buffer, int headerOffset,
        List<(string, byte[])> results, HashSet<string> seen)
    {
        if (headerOffset + 16 > buffer.Length) return;
        int entriesOffset = (int)ReadU32(buffer, headerOffset + OffIndexEntriesOffset);
        int indexLength = (int)ReadU32(buffer, headerOffset + OffIndexLength);
        int entriesStart = headerOffset + entriesOffset;
        int entriesEnd = Math.Min(headerOffset + indexLength, buffer.Length);
        int off = entriesStart;

        while (off + 16 <= entriesEnd)
        {
            byte flags = buffer[off + OffEntryFlags];
            int entryLength = ReadU16(buffer, off + OffEntryLength);
            int keyLength = ReadU16(buffer, off + OffEntryKeyLength);
            if (entryLength < 16 || off + entryLength > entriesEnd + 8) break;
            if ((flags & FlagEntryLast) != 0) break;

            string? name = null;
            if (keyLength >= 0x42 && off + OffEntryKey + keyLength <= buffer.Length)
            {
                ReadOnlySpan<byte> key = buffer.Slice(off + OffEntryKey, keyLength);
                int nameLength = key[0x40];
                if (0x42 + nameLength * 2 <= key.Length)
                    name = Encoding.Unicode.GetString(key.Slice(0x42, nameLength * 2));
            }
            if (name is not null && name is not ("." or "..") && seen.Add(name))
            {
                byte[] raw = buffer.Slice(off, entryLength).ToArray();
                results.Add((name, raw));
            }
            off += entryLength;
        }
    }

    // USA fixup for an INDX block (blockSize = one cluster, multiple sectors).
    private static byte[] ApplyUsaFixup(NtfsVolume vol, byte[] block)
    {
        int usaOffset = ReadU16(block, 4);
        int usaCount = ReadU16(block, 6);
        if (usaCount == 0 || usaOffset + usaCount * 2 > block.Length) return block;

        byte[] copy = (byte[])block.Clone();
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
