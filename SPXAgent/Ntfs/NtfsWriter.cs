using System.Text;

namespace SpxAgent.Ntfs;

// Builder + low-level writer for raw NTFS MFT records and directory index
// entries. Only resident data is supported (data stored inside the record);
// non-resident (cluster-allocated) writes are rejected with NotSupportedException
// and callers fall back per the plan.
internal static class NtfsWriter
{
    // Custom delegate: ref structs (Span<byte>) cannot be generic args, so a
    // named delegate is required for resident-value fillers.
    private delegate void ResidentValueWriter(Span<byte> value);

    // ---- constants ----
    private const ushort FlagInUse = 0x0001;
    private const ushort FlagDirectory = 0x0002;

    // ---- attribute types ----
    private const uint AttrEnd = 0xFFFFFFFF;

    // ---- file record header offsets ----
    private const int FhMagic = 0;          // 4
    private const int FhUsaOffset = 4;      // u16
    private const int FhUsaCount = 6;       // u16
    private const int FhLsn = 8;            // u64
    private const int FhSequence = 0x10;    // u16
    private const int FhLinkCount = 0x12;   // u16
    private const int FhFirstAttr = 0x14;   // u16
    private const int FhFlags = 0x16;       // u16
    private const int FhUsedSize = 0x18;    // u32
    private const int FhAllocatedSize = 0x1C; // u32
    private const int FhBaseRecord = 0x20;  // u64
    private const int FhNextAttrId = 0x28;  // u16
    private const int FhRecordNumber = 0x2C; // u32
    private const int FhDataSize = 0x30;    // padding to first attribute

    // ---- attribute header offsets ----
    private const int AhType = 0;           // u32
    private const int AhLength = 4;         // u32
    private const int AhNonResident = 8;    // u8
    private const int AhNameLength = 9;     // u8
    private const int AhNameOffset = 10;    // u16
    private const int AhFlags = 12;         // u16
    private const int AhId = 14;            // u16
    private const int AhValueLength = 16;   // u32 (resident)
    private const int AhValueOffset = 20;   // u16 (resident)
    private const int AhIndexed = 0x16;     // u8: resident_flags, 1 if indexed (e.g. $FILE_NAME)

    // Build a brand-new file record with SI + FILE_NAME + resident DATA.
    // Returns raw record bytes (USA not yet applied) + used size.
    public static (byte[] Raw, int UsedSize) BuildFileRecord(
        NtfsVolume vol,
        long recordNumber,
        ulong parentReference,
        string fileName,
        byte[] data,
        bool isDirectory,
        ushort sequenceNumber = 1,
        uint securityId = 0)
    {
        int recordSize = vol.RecordSize;
        byte[] rec = new byte[recordSize];

        // ---- FILE record header ----
        // Matches ntfs-3g ntfs_mft_record_layout(): LSN=0, link_count=0.
        WriteAscii(rec, FhMagic, "FILE");
        WriteU16(rec, FhSequence, sequenceNumber);
        WriteU16(rec, FhLinkCount, 0);
        ushort usaOffset = FhDataSize; // 0x30
        WriteU16(rec, FhUsaOffset, usaOffset);
        int usaCount = recordSize / vol.BytesPerSector + 1;
        WriteU16(rec, FhUsaCount, (ushort)usaCount);
        WriteU64(rec, FhLsn, 0);
        WriteU16(rec, FhFlags, isDirectory ? (ushort)(FlagInUse | FlagDirectory) : FlagInUse);
        WriteU32(rec, FhAllocatedSize, (uint)recordSize);
        WriteU32(rec, FhRecordNumber, (uint)recordNumber);

        // Next attribute id tracker (assigned incrementally by the writers;
        // the header field is filled in once the attributes are laid out).
        ushort nextAttrId = 0;

        int attrOff = FhDataSize + usaCount * 2; // room for the USA array
        if (attrOff % 8 != 0) attrOff += 8 - attrOff % 8;
        WriteU16(rec, FhFirstAttr, (ushort)attrOff);

        // ---- $STANDARD_INFORMATION (0x10), resident, 72 bytes (NTFS 3.1) ----
        // Matches Windows-created records (probe: dataSize=72).
        long nowFileTime = DateTimeOffset.UtcNow.ToFileTime();
        int siLen = 0x48; // 72
        attrOff = WriteResident(rec, attrOff, NtfsRecord.AttrStandardInformation, 0x00, null, siLen, false, ref nextAttrId,
            value =>
            {
                WriteU64(value, 0, (ulong)nowFileTime);   // creation
                WriteU64(value, 8, (ulong)nowFileTime);   // modified
                WriteU64(value, 0x10, (ulong)nowFileTime); // mft changed
                WriteU64(value, 0x18, (ulong)nowFileTime); // accessed
                WriteU32(value, 0x20, isDirectory ? 0x10000000u : 0x20u); // file attributes (DIR / ARCHIVE)
                WriteU32(value, 0x34, securityId); // security_id (index into $Secure $SII)
            });

        // ---- $FILE_NAME (0x30), resident, with parent + name ----
        int fnLen = 0x42 + fileName.Length * 2;
        string? savedName = fileName;
        // Windows leaves FILE_NAME allocated/real size 0 at creation and does
        // NOT update them when data is later written (ntfs doc: all fields
        // except parent go stale until rename). chkdsk accepts that.
        attrOff = WriteResident(rec, attrOff, NtfsRecord.AttrFileName, 0x01, null, fnLen, true, ref nextAttrId,
            value =>
            {
                WriteU64(value, 0, parentReference);
                WriteU64(value, 8, (ulong)nowFileTime);   // creation
                WriteU64(value, 0x10, (ulong)nowFileTime); // modified
                WriteU64(value, 0x18, (ulong)nowFileTime); // mft changed
                WriteU64(value, 0x20, (ulong)nowFileTime); // accessed
                WriteU64(value, 0x28, 0);                 // allocated size = 0
                WriteU64(value, 0x30, 0);                 // real size = 0
                WriteU32(value, 0x38, isDirectory ? 0x10000000u : 0x20u); // flags: DIR or ARCHIVE
                WriteU8(value, 0x40, (byte)savedName.Length);
                WriteU8(value, 0x41, 0); // namespace POSIX (matches Windows-created records)
                for (int i = 0; i < savedName.Length; i++)
                    WriteU16(value, 0x42 + i * 2, savedName[i]);
            });

        if (isDirectory)
        {
            // ---- $INDEX_ROOT (0x90) named "$I30", resident, empty (terminator only) ----
            // Matches Windows-created empty dir (probe: dataSize=48, single 0x02 terminator).
            attrOff = WriteResident(rec, attrOff, NtfsRecord.AttrIndexRoot, 0x02, "$I30", 0x30, false, ref nextAttrId,
                value =>
                {
                    WriteU32(value, 0, 0x30);       // attr type: FILE_NAME
                    WriteU32(value, 4, 1);          // collation: FILE_NAME
                    WriteU32(value, 8, (uint)vol.IndexBlockSize); // bytes per index block
                    WriteU8(value, 0x0C, 1);        // clusters per index block
                    WriteU32(value, 0x10, 16);      // entries offset
                    WriteU32(value, 0x14, 32);      // index length (terminator only)
                    WriteU32(value, 0x18, 32);      // allocated size
                    WriteU8(value, 0x1C, 0);        // flags: small index
                    // Terminator INDEX_ENTRY at 0x20.
                    WriteU16(value, 0x28, 16);      // entry length
                    WriteU8(value, 0x2C, 0x02);     // flags: last entry
                });
        }
        else if (data.Length > MaxResidentData(rec, attrOff, recordSize))
        {
            // ---- $DATA (0x80), non-resident ----
            long clusterSize = vol.ClusterSize;
            long numClusters = (data.Length + clusterSize - 1) / clusterSize;
            List<(long Lcn, long Length)> runs = AllocateClusters(vol, numClusters);
            // Write data into the allocated runs.
            long written = 0;
            foreach ((long lcn, long len) in runs)
            {
                long runBytes = len * clusterSize;
                long n = Math.Min(runBytes, data.Length - written);
                if (n > 0)
                    vol.WriteBytes(lcn * clusterSize, data.AsSpan((int)written, (int)n));
                written += n;
            }
            byte[] runlist = EncodeRunlist(runs);
            long totalClusters = numClusters;
            attrOff = WriteNonResident(rec, attrOff, NtfsRecord.AttrData, 0x03, null, 0, totalClusters - 1,
                totalClusters * clusterSize, data.Length, runlist, ref nextAttrId);
        }
        else
        {
            // ---- $DATA (0x80), resident (data fits in record) ----
            int dataLen = data.Length;
            attrOff = WriteResident(rec, attrOff, NtfsRecord.AttrData, 0x03, null, dataLen, false, ref nextAttrId,
                value => data.AsSpan().CopyTo(value));
        }

        // ---- end marker ----
        // ntfs-3g writes AT_END as an 8-byte attribute (type + length=0) and
        // bytes_in_use = align8(attrs_end + 8).
        int usedSize = (attrOff + 8 + 7) & ~7;
        WriteU32(rec, attrOff, AttrEnd);
        WriteU32(rec, attrOff + 4, 0); // AT_END length = 0

        WriteU16(rec, FhNextAttrId, nextAttrId);
        WriteU32(rec, FhUsedSize, (uint)usedSize);
        return (rec, usedSize);
    }

    // Write a non-resident attribute header + runlist into the record.
    private static int WriteNonResident(byte[] rec, int attrOff, uint type, ushort attrId, string? name,
        long lowestVcn, long highestVcn, long allocatedSize, long dataSize, byte[] runlist, ref ushort nextAttrId)
    {
        int nameLen = name?.Length ?? 0;
        int headerLen = 0x40 + (nameLen > 0 ? nameLen * 2 : 0);
        int total = headerLen + runlist.Length;
        total = (total + 7) & ~7;

        WriteU32(rec, attrOff + AhType, type);
        WriteU32(rec, attrOff + AhLength, (uint)total);
        WriteU8(rec, attrOff + AhNonResident, 1);
        WriteU8(rec, attrOff + AhNameLength, (byte)nameLen);
        if (nameLen > 0)
            WriteU16(rec, attrOff + AhNameOffset, 0x40);
        WriteU16(rec, attrOff + AhFlags, 0);
        WriteU16(rec, attrOff + AhId, nextAttrId); // sequential instance id
        nextAttrId++;
        WriteU64(rec, attrOff + 0x10, (ulong)lowestVcn);
        WriteU64(rec, attrOff + 0x18, (ulong)highestVcn);
        WriteU16(rec, attrOff + 0x20, (ushort)headerLen); // mapping-pairs offset = end of header
        WriteU8(rec, attrOff + 0x22, 0);     // compression unit
        WriteU64(rec, attrOff + 0x28, (ulong)allocatedSize);
        WriteU64(rec, attrOff + 0x30, (ulong)dataSize);
        WriteU64(rec, attrOff + 0x38, (ulong)dataSize); // initialized size

        int runlistOffset = attrOff + headerLen;
        runlist.CopyTo(rec, runlistOffset);
        return attrOff + total;
    }

    // Rebuild a record's $DATA attribute as non-resident, preserving all other
    // attributes (SI, FILE_NAME, SD, etc.). Used for resident->non-resident
    // conversion and non-resident regrow. Allocates fresh clusters and writes
    // the data through them; the old $DATA value is discarded in place.
    public static void RebuildDataNonResident(NtfsVolume vol, NtfsRecord rec, byte[] data)
    {
        long clusterSize = vol.ClusterSize;
        long numClusters = (data.Length + clusterSize - 1) / clusterSize;
        List<(long Lcn, long Length)> runs = AllocateClusters(vol, numClusters);
        long written = 0;
        foreach ((long lcn, long len) in runs)
        {
            long runBytes = len * clusterSize;
            long n = Math.Min(runBytes, data.Length - written);
            if (n > 0)
                vol.WriteBytes(lcn * clusterSize, data.AsSpan((int)written, (int)n));
            written += n;
        }
        byte[] runlist = EncodeRunlist(runs);

        byte[] src = rec.Raw; // USA-fixed record bytes
        int firstAttr = rec.FirstAttrOffset;
        if (firstAttr <= 0 || firstAttr >= src.Length)
            throw new InvalidDataException("bad first-attribute offset");
        byte[] record = new byte[vol.RecordSize];
        Array.Copy(src, 0, record, 0, firstAttr); // header + USA array

        int attrOff = firstAttr;
        int off = firstAttr;
        while (off + 8 <= rec.UsedSize)
        {
            uint type = ReadU32(src, off);
            if (type == AttrEnd) break;
            uint len = ReadU32(src, off + 4);
            if (len < 16 || off + (int)len > src.Length) break;
            if (type != NtfsRecord.AttrData)
            {
                Array.Copy(src, off, record, attrOff, (int)len);
                attrOff += (int)len;
            }
            off += (int)len;
        }

        ushort maxId = 0;
        int scanOff = firstAttr;
        while (scanOff + 8 <= rec.UsedSize)
        {
            uint type = ReadU32(src, scanOff);
            if (type == AttrEnd) break;
            uint len = ReadU32(src, scanOff + 4);
            if (len < 16) break;
            ushort id = ReadU16(src, scanOff + AhId);
            if (id > maxId) maxId = id;
            scanOff += (int)len;
        }
        ushort nextId = (ushort)(maxId + 1);
        attrOff = WriteNonResident(record, attrOff, NtfsRecord.AttrData, 0x40, null, 0, numClusters - 1,
            numClusters * clusterSize, data.Length, runlist, ref nextId);
        WriteU32(record, attrOff, AttrEnd);
        WriteU16(record, FhNextAttrId, nextId);
        WriteU32(record, FhUsedSize, (uint)(attrOff + 4));

        byte[] fixedRecord = ApplyFixup(vol, record);
        vol.WriteBytes(vol.MftOffset + rec.MftRecordNumber * vol.RecordSize, fixedRecord);
    }

    // Maximum bytes that can be stored resident after the given attribute offset.
    private static int MaxResidentData(byte[] rec, int attrOff, int recordSize)
    {
        // room for the $DATA attr header (0x18) + value + 4-byte end marker.
        int end = recordSize - usaRoom(rec);
        return Math.Max(0, end - attrOff - 0x18 - 4 - 4);
    }

    private static int usaRoom(byte[] rec) => 0; // end-marker margin placeholder

    // Write a resident attribute; returns the new attribute offset.
    // indexed=true sets the indexed flag (e.g. required for $FILE_NAME).
    private static int WriteResident(byte[] rec, int attrOff, uint type, ushort attrId, string? name,
        int valueLen, bool indexed, ref ushort nextAttrId, ResidentValueWriter fill)
    {
        int nameLen = name?.Length ?? 0;
        int headerLen = nameLen > 0 ? 0x18 + nameLen * 2 : 0x18;
        int total = headerLen + valueLen;
        total = (total + 7) & ~7; // align 8

        WriteU32(rec, attrOff + AhType, type);
        WriteU32(rec, attrOff + AhLength, (uint)total);
        WriteU8(rec, attrOff + AhNonResident, 0);
        WriteU8(rec, attrOff + AhNameLength, (byte)nameLen);
        if (nameLen > 0)
        {
            WriteU16(rec, attrOff + AhNameOffset, 0x18);
            for (int i = 0; i < nameLen; i++)
                WriteU16(rec, attrOff + 0x18 + i * 2, name![i]);
        }
        WriteU16(rec, attrOff + AhFlags, 0);
        WriteU16(rec, attrOff + AhId, nextAttrId); // sequential instance id
        nextAttrId++;
        WriteU32(rec, attrOff + AhValueLength, (uint)valueLen);
        WriteU16(rec, attrOff + AhValueOffset, (ushort)headerLen);
        WriteU8(rec, attrOff + AhIndexed, indexed ? (byte)1 : (byte)0);

        int valueStart = attrOff + headerLen;
        fill(rec.AsSpan(valueStart, valueLen));
        return attrOff + total;
    }

    // Apply the USA fixup before writing a record to disk.
    public static byte[] ApplyFixup(NtfsVolume vol, byte[] record)
    {
        int usaOffset = ReadU16(record, FhUsaOffset);
        int usaCount = ReadU16(record, FhUsaCount);
        ushort usn = (ushort)(0xFFFF & (Environment.TickCount | 0x1000));
        byte[] copy = (byte[])record.Clone();
        // Save original sector-end words and stamp the USN.
        for (int i = 1; i < usaCount; i++)
        {
            int sectorEnd = i * vol.BytesPerSector - 2;
            if (sectorEnd < 0 || sectorEnd + 2 > copy.Length) break;
            ushort orig = ReadU16(copy, sectorEnd);
            WriteU16(copy, usaOffset + i * 2, orig);
            WriteU16(copy, sectorEnd, usn);
        }
        WriteU16(copy, usaOffset, usn);
        return copy;
    }

    // Insert a new FILE_NAME index entry into a directory's index using an
    // incremental B+ tree (matches ntfs-3g): resident insert when small,
    // spill to INDEX_ALLOCATION on first overflow, then walk separators to a
    // leaf INDX block, insert in place, and split the leaf only when full.
    public static void InsertIndexEntry(NtfsVolume vol, NtfsRecord dir, long newRecordNumber, string name, long dataSize)
    {
        // Build the index key from the child's actual $FILE_NAME attribute so
        // timestamps/flags/sizes match the record exactly (chkdsk cross-checks
        // index key vs FILE_NAME; they must be identical).
        NtfsRecord child = NtfsRecord.Read(vol, newRecordNumber);
        NtfsAttribute? childFn = child.FindAttribute(NtfsRecord.AttrFileName);
        if (childFn is null) throw new IOException("child record has no $FILE_NAME");
        byte[] fnValue = childFn.ResidentValue().ToArray();
        fnValue[0x41] = 0; // index key namespace = POSIX
        ulong parentRef = ((ulong)dir.SequenceNumber << 48) | (ulong)dir.MftRecordNumber;
        ulong childRef = ((ulong)child.SequenceNumber << 48) | (ulong)newRecordNumber;
        byte[] newEntry = BuildIndexEntryBytes(parentRef, childRef, fnValue);

        bool hasAllocation = dir.FindAttribute(NtfsRecord.AttrIndexAllocation) is { NonResident: true };

        if (!hasAllocation)
        {
            // Small index: try resident insert into INDEX_ROOT.
            var entries = NtfsIndex.CollectRawEntries(vol, dir);
            int pos = entries.FindIndex(e => CompareNames(e.Name, name) > 0);
            if (pos < 0) pos = entries.Count;
            entries.Insert(pos, (name, newEntry));

            var rootEntries = new List<byte[]>();
            foreach ((_, byte[] raw) in entries) rootEntries.Add(raw);
            rootEntries.Add(Terminator(16));
            byte[] rootValue = BuildIndexRootValue(vol, rootEntries, large: false);
            if (TryRebuildDirRecord(vol, dir, rootValue, null, null, out byte[]? record))
            {
                WriteRecord(vol, dir.MftRecordNumber, record!);
                return;
            }
            // Resident overflow -> spill into a single INDX leaf block.
            SpillIndexRoot(vol, dir, entries);
            return;
        }

        // Large index: walk separators to the leaf and insert in place.
        InsertIntoTree(vol, dir, newEntry, name);
    }

    // NTFS filename collation: case-insensitive via OrdinalIgnoreCase primary,
    // Ordinal tie-break (approximates the $UpCase table for ASCII names).
    private static int CompareNames(string a, string b)
    {
        int c = string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        return c != 0 ? c : string.Compare(a, b, StringComparison.Ordinal);
    }

    // First spill (ntfs-3g ntfs_ir_reparent): move every resident entry into a
    // single INDX leaf block (vcn 0), leaving the INDEX_ROOT with only a
    // NODE+END terminator pointing at it. Adds INDEX_ALLOCATION + BITMAP($I30).
    private static void SpillIndexRoot(NtfsVolume vol, NtfsRecord dir, List<(string Name, byte[] Raw)> entries)
    {
        int blockSize = vol.IndexBlockSize;
        List<(long Lcn, long Length)> runs = AllocateClusters(vol, 1);
        long lcn = runs[0].Lcn;

        var blockEntries = new List<byte[]>();
        foreach ((_, byte[] raw) in entries) blockEntries.Add(raw);
        byte[] block = BuildIndxBlock(vol, 0, blockEntries);
        vol.WriteBytes(lcn * vol.ClusterSize, ApplyFixup(vol, block));

        // Root keeps only a terminator pointing at vcn 0.
        byte[] term = new byte[24];
        WriteU16(term, 8, 24);
        term[12] = 0x02 | 0x01; // last + sub-node
        WriteU64(term, 16, 0);
        byte[] rootValue = BuildIndexRootValue(vol, new List<byte[]> { term }, large: true);

        byte[] runlist = EncodeRunlist(runs);
        byte[] indexAlloc = BuildNonResidentAttrBytes(vol, NtfsRecord.AttrIndexAllocation, 0, "$I30",
            0, 0, blockSize, blockSize, runlist);
        byte[] bitmap = new byte[8];
        bitmap[0] = 0x01; // vcn 0 in use
        byte[] indexBitmap = BuildResidentAttrBytes(NtfsRecord.AttrBitmap, 0, "$I30", bitmap);

        if (!TryRebuildDirRecord(vol, dir, rootValue, indexAlloc, indexBitmap, out byte[]? record))
            throw new NotSupportedException("directory record overflow on index spill; standard API fallback");
        WriteRecord(vol, dir.MftRecordNumber, record!);
    }

    // Walk root separators down to the leaf INDX block holding `name`, insert
    // in sorted order, and split the leaf if it overflows (ntfs-3g ntfs_ie_add
    // -> ntfs_ib_split). Root re-split is not implemented (out of scope).
    private static void InsertIntoTree(NtfsVolume vol, NtfsRecord dir, byte[] newEntry, string name)
    {
        // Pick the leaf: name <= separator key -> that separator's VCN; else
        // the terminator's VCN (last leaf).
        long leafVcn = -1;
        foreach ((string sepName, _, ulong sepVcn) in NtfsIndex.CollectRootSeparators(dir))
        {
            if (CompareNames(name, sepName) <= 0) { leafVcn = (long)sepVcn; break; }
        }
        if (leafVcn < 0) leafVcn = NtfsIndex.ReadRootTerminatorVcn(dir);
        if (leafVcn < 0) throw new InvalidDataException("directory has INDEX_ALLOCATION but no leaf pointer");

        // Read the leaf block, parse its entries, insert in sorted order.
        byte[] block = NtfsIndex.ReadIndxBlock(vol, dir, leafVcn)
            ?? throw new InvalidDataException($"missing INDX block vcn {leafVcn}");
        int blockSize = vol.IndexBlockSize;
        var entries = ParseBlockEntries(block, blockSize);

        int pos = entries.FindIndex(e => CompareNames(e.Name, name) > 0);
        if (pos < 0) pos = entries.Count;
        entries.Insert(pos, (name, newEntry));

        int entryBytes = 0;
        foreach ((_, byte[] raw) in entries) entryBytes += raw.Length;
        int entriesOffset = ReadI32(block, 0x18);   // relative to INDEX_HEADER
        int allocated = ReadI32(block, 0x20);        // relative to INDEX_HEADER
        int needed = entriesOffset + entryBytes + 16; // + terminator
        if (needed <= allocated + 16) // index_length includes header region
        {
            WriteLeafBlock(vol, dir, leafVcn, entries, blockSize);
            return;
        }

        SplitLeaf(vol, dir, leafVcn, entries, blockSize);
    }

    // Split a full leaf at the median; the median key (with a sub-node VCN
    // pointing at the LEFT block) is promoted into the root, and the root
    // terminator is retargeted at the new right block. ntfs-3g ntfs_ib_split.
    private static void SplitLeaf(NtfsVolume vol, NtfsRecord dir, long leafVcn,
        List<(string Name, byte[] Raw)> entries, int blockSize)
    {
        int count = entries.Count;
        int medianIdx = count / 2 - 1;
        if (medianIdx < 0) medianIdx = 0;
        var left = entries.Take(medianIdx + 1).ToList();
        var right = entries.Skip(medianIdx + 1).ToList();
        (string medianName, byte[] medianRaw) = entries[medianIdx];
        // Median moves up; it must not stay in either leaf.
        left.RemoveAt(left.Count - 1);

        // Allocate a new leaf (append VCN = current block count).
        NtfsAttribute? allocAttr = dir.FindAttribute(NtfsRecord.AttrIndexAllocation);
        long dataSize = allocAttr!.DataSize;
        long newVcn = dataSize / blockSize;
        List<(long Lcn, long Length)> runs = AllocateClusters(vol, 1);
        long newLcn = runs[0].Lcn;
        // Extend INDEX_ALLOCATION by one cluster and set the BITMAP($I30) bit
        // for the new VCN, in a single dir-record rebuild (both attrs together,
        // so neither overwrites the other from a stale snapshot).
        ExtendAllocAndBitmap(vol, dir, allocAttr!, newVcn, newLcn, blockSize);

        // The dir record was rebuilt by the extension; re-read it so its
        // INDEX_ALLOCATION runlist covers the new VCN before we write blocks.
        NtfsRecord freshDir = NtfsRecord.Read(vol, dir.MftRecordNumber);

        // Rewrite both leaves.
        WriteLeafBlock(vol, freshDir, leafVcn, left, blockSize);
        WriteLeafBlock(vol, freshDir, newVcn, right, blockSize);

        // Promote median into root: separator key = median, VCN = left leaf.
        var rootSeps = NtfsIndex.CollectRootSeparators(freshDir)
            .Select(s => (s.Name, s.Raw, s.Vcn)).ToList();
        byte[] medianSep = AddSubnode(medianRaw, (ulong)leafVcn);
        int pos = rootSeps.FindIndex(s => CompareNames(s.Name, medianName) > 0);
        if (pos < 0) pos = rootSeps.Count;
        var rootEntries = new List<byte[]>();
        foreach ((_, byte[] raw, _) in rootSeps) rootEntries.Add(raw);
        rootEntries.Insert(pos, medianSep);
        // Terminator points to the last leaf: max existing terminator VCN or newVcn.
        long termVcn = NtfsIndex.ReadRootTerminatorVcn(freshDir);
        if (newVcn > termVcn) termVcn = newVcn;
        byte[] term = new byte[24];
        WriteU16(term, 8, 24);
        term[12] = 0x02 | 0x01;
        WriteU64(term, 16, (ulong)termVcn);
        rootEntries.Add(term);
        byte[] rootValue = BuildIndexRootValue(vol, rootEntries, large: true);

        // Rebuild dir record preserving existing INDEX_ALLOCATION + BITMAP.
        RebuildDirRecordKeepAllocation(vol, freshDir, rootValue);
    }

    private static int ReadI32(byte[] b, int off) =>
        b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24);

    // Parse all real entries (name + raw bytes) from a USA-fixed INDX block.
    private static List<(string Name, byte[] Raw)> ParseBlockEntries(byte[] block, int blockSize)
    {
        var entries = new List<(string, byte[])>();
        int entriesOffset = ReadI32(block, 0x18);      // relative to INDEX_HEADER
        int indexLength = ReadI32(block, 0x1C);        // relative to INDEX_HEADER
        int off = 0x18 + entriesOffset;
        int end = Math.Min(0x18 + indexLength, blockSize);
        while (off + 16 <= end)
        {
            var info = NtfsIndex.ParseEntryInfo(block, off, end);
            if (info is null) break;
            if ((info.Flags & 0x02) != 0) break; // terminator
            entries.Add((info.Name ?? "", block.AsSpan(off, info.EntryLength).ToArray()));
            off += info.EntryLength;
        }
        return entries;
    }

    // Build and write a leaf INDX block for the given entries at `vcn`,
    // locating its cluster via the directory's INDEX_ALLOCATION runlist.
    private static void WriteLeafBlock(NtfsVolume vol, NtfsRecord dir, long vcn,
        List<(string Name, byte[] Raw)> entries, int blockSize)
    {
        var raw = new List<byte[]>();
        foreach ((_, byte[] e) in entries) raw.Add(e);
        byte[] block = BuildIndxBlock(vol, (int)vcn, raw);
        long lcn = IndexVcnToLcn(vol, dir, vcn, blockSize);
        vol.WriteBytes(lcn * vol.ClusterSize, ApplyFixup(vol, block));
    }

    // Map an INDEX_ALLOCATION VCN to its LCN via the attribute runlist.
    private static long IndexVcnToLcn(NtfsVolume vol, NtfsRecord dir, long vcn, int blockSize)
    {
        NtfsAttribute? allocAttr = dir.FindAttribute(NtfsRecord.AttrIndexAllocation)
            ?? throw new InvalidDataException("no INDEX_ALLOCATION");
        long clusterSize = vol.ClusterSize;
        int clustersPerBlock = blockSize / (int)clusterSize;
        long targetCluster = vcn * clustersPerBlock;
        long vcnCursor = 0;
        foreach ((long lcn, long runLen) in allocAttr.Runlist())
        {
            if (targetCluster >= vcnCursor && targetCluster < vcnCursor + runLen)
                return lcn + (targetCluster - vcnCursor);
            vcnCursor += runLen;
        }
        throw new InvalidDataException($"index VCN {vcn} beyond INDEX_ALLOCATION runlist");
    }

    // Extend INDEX_ALLOCATION by one cluster AND set the BITMAP($I30) bit for
    // the new VCN, rebuilding the dir record once with both updated attributes
    // (avoids one rebuild clobbering the other from a stale snapshot).
    private static void ExtendAllocAndBitmap(NtfsVolume vol, NtfsRecord dir, NtfsAttribute allocAttr,
        long newVcn, long newLcn, int blockSize)
    {
        // New INDEX_ALLOCATION runlist = existing runs + the new cluster.
        var runs = new List<(long Lcn, long Length)>();
        foreach ((long lcn, long runLen) in allocAttr.Runlist()) runs.Add((lcn, runLen));
        runs.Add((newLcn, blockSize / vol.ClusterSize));
        byte[] runlist = EncodeRunlist(runs);
        long blockCount = newVcn + 1;
        byte[] newAlloc = BuildNonResidentAttrBytes(vol, NtfsRecord.AttrIndexAllocation, 0, "$I30",
            0, blockCount - 1, blockCount * (long)blockSize, blockCount * (long)blockSize, runlist);

        // New BITMAP with the new VCN bit set.
        NtfsAttribute? bm = dir.FindAttribute(NtfsRecord.AttrBitmap);
        byte[] bits = bm is null ? new byte[8] : bm.ResidentValue().ToArray();
        int needBytes = (int)(newVcn / 8) + 1;
        int newLen = Math.Max(8, (needBytes + 7) & ~7);
        if (bits.Length < newLen) Array.Resize(ref bits, newLen);
        bits[newVcn / 8] |= (byte)(1 << ((int)newVcn % 8));
        byte[] newBitmap = BuildResidentAttrBytes(NtfsRecord.AttrBitmap, 0, "$I30", bits);

        NtfsAttribute? irAttr = dir.FindAttribute(NtfsRecord.AttrIndexRoot);
        byte[] rootValue = irAttr!.ResidentValue().ToArray();
        if (!TryRebuildDirRecord(vol, dir, rootValue, newAlloc, newBitmap, out byte[]? record))
            throw new NotSupportedException("directory record overflow extending INDEX_ALLOCATION");
        WriteRecord(vol, dir.MftRecordNumber, record!);
    }

    // Replace only the INDEX_ROOT attribute value, preserving INDEX_ALLOCATION
    // and BITMAP bytes as-is (used after a leaf split).
    private static void RebuildDirRecordKeepAllocation(NtfsVolume vol, NtfsRecord dir, byte[] rootValue)
    {
        NtfsAttribute? allocAttr = dir.FindAttribute(NtfsRecord.AttrIndexAllocation);
        NtfsAttribute? bmAttr = dir.FindAttribute(NtfsRecord.AttrBitmap);
        byte[]? allocBytes = allocAttr is null ? null : SliceAttr(dir.Raw, allocAttr);
        byte[]? bmBytes = bmAttr is null ? null : SliceAttr(dir.Raw, bmAttr);
        if (!TryRebuildDirRecord(vol, dir, rootValue, allocBytes, bmBytes, out byte[]? record))
            throw new NotSupportedException("directory record overflow on leaf split; standard API fallback");
        WriteRecord(vol, dir.MftRecordNumber, record!);
    }

    // Copy an attribute's raw bytes (header + value) out of a record buffer.
    private static byte[] SliceAttr(byte[] rec, NtfsAttribute attr)
    {
        int len = ReadI32(rec, attr.Offset + 4);
        byte[] b = new byte[len];
        Array.Copy(rec, attr.Offset, b, 0, len);
        return b;
    }

    // Serialize an INDEX_ENTRY (key = FILE_NAME value) for a child file/dir.
    // Serialize an INDEX_ENTRY for a child file/dir. The key is the child's
    // complete FILE_NAME attribute value (fnValue, already namespace-adjusted).
    private static byte[] BuildIndexEntryBytes(ulong parentRef, ulong childRef, byte[] fnValue)
    {
        int keyLen = fnValue.Length;
        int entryLen = (0x10 + keyLen + 7) & ~7;
        byte[] e = new byte[entryLen];
        WriteU64(e, 0, childRef); // file reference (48-bit record + 16-bit seq)
        WriteU16(e, 8, entryLen);
        WriteU16(e, 10, keyLen);
        WriteU8(e, 12, 0); // flags: not last, no sub-node
        // Key = FILE_NAME value, starts at offset 0x10.
        fnValue.CopyTo(e, 0x10);
        return e;
    }

    // The terminator INDEX_ENTRY: no key, flags=0x02 (last).
    private static byte[] Terminator(int length)
    {
        byte[] t = new byte[length];
        t[12] = 0x02;
        WriteU16(t, 8, length);
        return t;
    }

    // Copy an entry and attach a sub-node pointer (flags|=0x01, VCN at end).
    private static byte[] AddSubnode(byte[] e, ulong vcn)
    {
        byte[] n = new byte[e.Length + 8];
        e.CopyTo(n, 0);
        n[12] |= 0x01;
        WriteU16(n, 8, n.Length);
        WriteU64(n, n.Length - 8, vcn);
        return n;
    }

    // Build the INDEX_ROOT (0x90) value: index-root header + index header +
    // serialized entries.
    private static byte[] BuildIndexRootValue(NtfsVolume vol, List<byte[]> rootEntries, bool large)
    {
        int entryBytes = 0;
        foreach (byte[] e in rootEntries) entryBytes += e.Length;
        int valueLen = 0x20 + entryBytes; // 0x10 root + 0x10 index header + entries
        byte[] v = new byte[valueLen];
        WriteU32(v, 0, 0x30);                              // attr type: FILE_NAME
        WriteU32(v, 4, 1);                                 // collation: FILE_NAME
        WriteU32(v, 8, (uint)vol.IndexBlockSize);          // bytes per index block
        WriteU8(v, 0x0C, 1);                               // clusters per index block
        WriteU32(v, 0x10, 0x10);                           // entries offset
        WriteU32(v, 0x14, (uint)(0x10 + entryBytes));      // index length
        WriteU32(v, 0x18, (uint)(0x10 + entryBytes));      // allocated size
        WriteU8(v, 0x1C, large ? (byte)1 : (byte)0);       // large-index flag
        int off = 0x20;
        foreach (byte[] e in rootEntries) { e.CopyTo(v, off); off += e.Length; }
        return v;
    }

    // Build an INDX block (one cluster) with header + index header + entries.
    private static byte[] BuildIndxBlock(NtfsVolume vol, int vcn, List<byte[]> entries)
    {
        int blockSize = vol.IndexBlockSize;
        byte[] block = new byte[blockSize];
        WriteAscii(block, 0, "INDX");
        int usaCount = blockSize / vol.BytesPerSector + 1;
        WriteU16(block, 4, 0x28);  // USA offset = sizeof(INDEX_BLOCK)
        WriteU16(block, 6, usaCount);
        WriteU64(block, 8, 0);     // LSN = 0 (matches ntfs-3g ntfs_ib_alloc)
        WriteU64(block, 0x10, (ulong)vcn);

        // INDEX_HEADER (at 0x18). All three size/offset fields are relative to
        // the INDEX_HEADER start (0x18), matching ntfs-3g ntfs_ib_alloc().
        int ihSize = 16; // sizeof(INDEX_HEADER)
        int entriesOffset = (ihSize + usaCount * 2 + 7) & ~7; // relative to 0x18
        int entryBytes = 0;
        foreach (byte[] e in entries) entryBytes += e.Length;
        entryBytes += 16; // terminator
        WriteU32(block, 0x18, (uint)entriesOffset);                    // entries offset (rel)
        WriteU32(block, 0x1C, (uint)(entriesOffset + entryBytes));     // index length (rel)
        WriteU32(block, 0x20, (uint)(blockSize - (0x28 - ihSize)));    // allocated size (rel)
        WriteU8(block, 0x24, 0);                                       // ih_flags: LEAF_NODE

        int off = 0x18 + entriesOffset;
        foreach (byte[] e in entries) { e.CopyTo(block, off); off += e.Length; }
        Terminator(16).CopyTo(block, off);
        return block;
    }

    // Serialize a resident attribute (header + value) for the record rebuild.
    // indexed=true sets the indexed flag (e.g. required for $FILE_NAME).
    private static byte[] BuildResidentAttrBytes(uint type, ushort attrId, string? name, byte[] value, bool indexed = false)
    {
        int nameLen = name?.Length ?? 0;
        int headerLen = 0x18 + (nameLen > 0 ? nameLen * 2 : 0);
        int total = headerLen + value.Length;
        total = (total + 7) & ~7;
        byte[] a = new byte[total];
        WriteU32(a, 0, type);
        WriteU32(a, 4, (uint)total);
        WriteU8(a, 8, 0); // resident
        WriteU8(a, 9, (byte)nameLen);
        if (nameLen > 0)
        {
            WriteU16(a, 10, 0x18);
            for (int i = 0; i < nameLen; i++)
                WriteU16(a, 0x18 + i * 2, name![i]);
        }
        WriteU16(a, 12, 0);
        WriteU16(a, 14, attrId);
        WriteU32(a, 16, (uint)value.Length);
        WriteU16(a, 20, (ushort)headerLen);
        WriteU8(a, AhIndexed, indexed ? (byte)1 : (byte)0);
        value.CopyTo(a, headerLen);
        return a;
    }

    // Serialize a non-resident attribute (header + runlist) for the record rebuild.
    private static byte[] BuildNonResidentAttrBytes(NtfsVolume vol, uint type, ushort attrId, string? name,
        long lowestVcn, long highestVcn, long dataSize, long allocatedSize, byte[] runlist)
    {
        int nameLen = name?.Length ?? 0;
        int headerLen = 0x40 + (nameLen > 0 ? nameLen * 2 : 0);
        int total = headerLen + runlist.Length;
        total = (total + 7) & ~7;
        byte[] a = new byte[total];
        WriteU32(a, 0, type);
        WriteU32(a, 4, (uint)total);
        WriteU8(a, 8, 1); // non-resident
        WriteU8(a, 9, (byte)nameLen);
        if (nameLen > 0)
        {
            WriteU16(a, 10, 0x40);
            for (int i = 0; i < nameLen; i++)
                WriteU16(a, 0x40 + i * 2, name![i]);
        }
        WriteU16(a, 12, 0);
        WriteU16(a, 14, attrId);
        WriteU64(a, 0x10, (ulong)lowestVcn);
        WriteU64(a, 0x18, (ulong)highestVcn);
        WriteU16(a, 0x20, (ushort)headerLen); // mapping-pairs offset
        WriteU8(a, 0x22, 0);                  // compression unit
        WriteU64(a, 0x28, (ulong)allocatedSize);
        WriteU64(a, 0x30, (ulong)dataSize);
        WriteU64(a, 0x38, (ulong)dataSize);   // initialized size
        runlist.CopyTo(a, headerLen);
        return a;
    }

    // Assemble a rebuilt directory record: preserve the header/USA and every
    // non-index attribute, rebuild the index attributes, then write all
    // attributes sorted by type (then name) with sequential instance IDs.
    // Returns false if the result overflows the record.
    private static bool TryRebuildDirRecord(NtfsVolume vol, NtfsRecord dir, byte[] indexRootValue,
        byte[]? indexAllocBytes, byte[]? indexBitmapBytes, out byte[]? record)
    {
        record = null;
        byte[] src = dir.Raw;
        int firstAttr = dir.FirstAttrOffset;
        if (firstAttr <= 0 || firstAttr >= src.Length) return false;

        var preserved = new List<(uint Type, string? Name, byte[] Raw)>();
        int off = firstAttr;
        while (off + 8 <= dir.UsedSize)
        {
            uint type = ReadU32(src, off);
            if (type == AttrEnd || type == 0) break;
            uint len = ReadU32(src, off + 4);
            if (len < 16 || len > (uint)src.Length || off + (long)len > src.Length) break;
            if (type is not (NtfsRecord.AttrIndexRoot or NtfsRecord.AttrIndexAllocation or NtfsRecord.AttrBitmap))
            {
                int nameLen = src[off + AhNameLength];
                int nameOff = off + ReadU16(src, off + AhNameOffset);
                string? name = null;
                if (nameLen > 0 && nameOff + nameLen * 2 <= src.Length)
                    name = Encoding.Unicode.GetString(src, nameOff, nameLen * 2);

                byte[] bytes = new byte[len];
                Array.Copy(src, off, bytes, 0, (int)len);
                preserved.Add((type, name, bytes));
            }
            off += (int)len;
        }

        var built = new List<(uint Type, string? Name, byte[] Raw)>();
        built.Add((NtfsRecord.AttrIndexRoot, "$I30", BuildResidentAttrBytes(NtfsRecord.AttrIndexRoot, 0, "$I30", indexRootValue)));
        if (indexAllocBytes is not null)
            built.Add((NtfsRecord.AttrIndexAllocation, "$I30", indexAllocBytes));
        if (indexBitmapBytes is not null)
            built.Add((NtfsRecord.AttrBitmap, "$I30", indexBitmapBytes));

        var all = preserved.Concat(built)
            .OrderBy(a => a.Type)
            .ThenBy(a => a.Name, StringComparer.Ordinal)
            .ToList();

        byte[] rec = new byte[vol.RecordSize];
        Array.Copy(src, 0, rec, 0, firstAttr); // header + USA array

        int attrOff = firstAttr;
        ushort nextId = 0;
        foreach (var attr in all)
        {
            byte[] bytes = attr.Raw;
            if (bytes.Length % 8 != 0)
            {
                int aligned = (bytes.Length + 7) & ~7;
                Array.Resize(ref bytes, aligned);
            }
            if (attrOff + bytes.Length + 4 > rec.Length) return false;

            WriteU16(bytes, AhId, nextId);
            bytes.CopyTo(rec, attrOff);
            attrOff += bytes.Length;
            nextId++;
        }

        int usedSize = (attrOff + 8 + 7) & ~7;
        WriteU32(rec, attrOff, AttrEnd);
        WriteU32(rec, attrOff + 4, 0); // AT_END length = 0
        WriteU16(rec, FhNextAttrId, nextId);
        WriteU32(rec, FhUsedSize, (uint)usedSize);
        record = rec;
        return true;
    }

    private static void WriteRecord(NtfsVolume vol, long recordNumber, byte[] rec)
    {
        byte[] fixedRecord = ApplyFixup(vol, rec);
        vol.WriteBytes(vol.MftOffset + recordNumber * vol.RecordSize, fixedRecord);
    }

    // Update the modified-time (FILETIME at SI value offset 0x08) of a record's
    // $STANDARD_INFORMATION attribute in place, then rewrite the record.
    public static void UpdateStandardInfoModTime(NtfsVolume vol, NtfsRecord rec)
    {
        NtfsAttribute? si = rec.FindAttribute(NtfsRecord.AttrStandardInformation);
        if (si is null || si.NonResident) return;
        (int valueOffset, int valueLen) = si.ResidentValueLocation();
        if (valueLen < 0x10 || valueOffset + 0x10 > rec.Raw.Length) return;
        long nowFt = DateTimeOffset.UtcNow.ToFileTime();
        byte[] record = (byte[])rec.Raw.Clone();
        WriteU64(record, valueOffset + 8, (ulong)nowFt); // modified time
        WriteU64(record, valueOffset + 0x10, (ulong)nowFt); // mft changed
        WriteU64(record, valueOffset + 0x18, (ulong)nowFt); // accessed
        WriteRecord(vol, rec.MftRecordNumber, record);
    }

    // Overwrite an existing file's resident $DATA attribute in place. Only
    // shrink-or-equal writes are supported (grow requires non-resident data /
    // attribute surgery -> NotSupportedException, caller falls back).
    public static void OverwriteResidentData(NtfsVolume vol, NtfsRecord rec, NtfsAttribute dataAttr, byte[] data)
    {
        if (dataAttr.NonResident)
            throw new NotSupportedException("non-resident $DATA overwrite unsupported; use standard API fallback");
        if (data.Length > dataAttr.DataSize)
            throw new NotSupportedException("grow-on-overwrite requires non-resident data; use standard API fallback");

        byte[] record = (byte[])rec.Raw.Clone();
        (int valueOffset, int valueLen) = dataAttr.ResidentValueLocation();
        if (valueOffset + valueLen > record.Length)
            throw new InvalidDataException("bad resident value location");
        Array.Copy(data, 0, record, valueOffset, data.Length);
        // Zero the remainder (shrink case).
        for (int i = data.Length; i < valueLen; i++)
            record[valueOffset + i] = 0;
        // Update value length field.
        WriteU32(record, dataAttr.Offset + 16, (uint)data.Length);

        byte[] fixedRecord = ApplyFixup(vol, record);
        vol.WriteBytes(vol.MftOffset + rec.MftRecordNumber * vol.RecordSize, fixedRecord);
    }

    // ---- $MFT::$BITMAP access (record 0's $BITMAP attribute) ----

    // Read one bit of the MFT record bitmap. Returns 1 if the record is
    // marked in-use, 0 if free. Bits beyond the bitmap's coverage are treated
    // as in-use (never allocate past the tracked range).
    public static int ReadMftRecordBit(NtfsVolume vol, long record)
    {
        NtfsRecord mft = NtfsRecord.Read(vol, 0);
        NtfsAttribute? bmp = mft.FindAttribute(NtfsRecord.AttrBitmap);
        if (bmp is null)
            throw new NotSupportedException("$MFT has no $BITMAP attribute; raw allocate unsupported");
        long byteIndex = record / 8;
        byte[] value = bmp.NonResident ? bmp.ReadValue(vol) : bmp.ResidentValue().ToArray();
        if (byteIndex >= value.Length) return 1;
        return (value[byteIndex] >> (int)(record % 8)) & 1;
    }

    // Set (inUse=true) or clear (inUse=false) one bit of the MFT record
    // bitmap. Resident: rewrites record 0 with USA fixup. Non-resident:
    // read-modify-write through the runlist.
    public static void SetMftRecordBit(NtfsVolume vol, long record, bool inUse)
    {
        NtfsRecord mft = NtfsRecord.Read(vol, 0);
        NtfsAttribute? bmp = mft.FindAttribute(NtfsRecord.AttrBitmap);
        if (bmp is null)
            throw new NotSupportedException("$MFT has no $BITMAP attribute; raw allocate unsupported");
        long byteIndex = record / 8;
        int bitIndex = (int)(record % 8);
        byte mask = (byte)(1 << bitIndex);

        if (bmp.NonResident)
        {
            byte[] value = bmp.ReadValue(vol);
            if (byteIndex >= value.Length)
                throw new NotSupportedException("$MFT::$BITMAP exhausted; raw allocate unsupported");
            if (inUse) value[byteIndex] |= mask; else value[byteIndex] &= (byte)~mask;
            WriteNonResidentValue(vol, bmp, value);
        }
        else
        {
            byte[] rec = (byte[])mft.Raw.Clone();
            (int valueOffset, int valueLen) = bmp.ResidentValueLocation();
            if (byteIndex >= valueLen)
                throw new NotSupportedException("$MFT::$BITMAP exhausted; raw allocate unsupported");
            if (inUse) rec[valueOffset + byteIndex] |= mask;
            else rec[valueOffset + byteIndex] &= (byte)~mask;
            byte[] fixedRecord = ApplyFixup(vol, rec);
            vol.WriteBytes(vol.MftOffset, fixedRecord);
        }
    }

    // Write a full value back into a non-resident attribute, honoring its
    // runlist (logical offset -> LCN via VCN progression).
    private static void WriteNonResidentValue(NtfsVolume vol, NtfsAttribute attr, byte[] value)
    {
        long logicalOffset = 0;
        foreach ((long lcn, long runLen) in attr.Runlist())
        {
            if (logicalOffset >= value.Length) break;
            if (lcn < 0) { logicalOffset += runLen * vol.ClusterSize; continue; } // sparse
            long runBytes = runLen * vol.ClusterSize;
            long n = Math.Min(runBytes, value.Length - logicalOffset);
            if (n > 0)
                vol.WriteBytes(lcn * vol.ClusterSize, value.AsSpan((int)logicalOffset, (int)n));
            logicalOffset += runBytes;
        }
    }

    // ---- $Bitmap (volume cluster bitmap, record 6) access ----

    // Allocate `count` free clusters from the volume $Bitmap using first-fit
    // from cluster 16 (clusters 0-15 are reserved for system files/MFT).
    // Marks them in-use and persists the bitmap. Returns the runs in LCN order.
    public static List<(long Lcn, long Length)> AllocateClusters(NtfsVolume vol, long count)
    {
        if (count <= 0) return new List<(long, long)>();

        NtfsRecord bmpRec = NtfsRecord.Read(vol, 6);
        NtfsAttribute? bmpAttr = bmpRec.FindAttribute(NtfsRecord.AttrData);
        if (bmpAttr is null) throw new NotSupportedException("$Bitmap has no $DATA; raw allocate unsupported");
        byte[] bitmap = bmpAttr.NonResident ? bmpAttr.ReadValue(vol) : bmpAttr.ResidentValue().ToArray();
        long maxCluster = bitmap.Length * 8;

        // First-fit scan for `count` free clusters.
        var runs = new List<(long Lcn, long Length)>();
        long remaining = count;
        long runStart = -1;
        for (long lcn = 16; lcn < maxCluster; lcn++)
        {
            bool used = IsClusterUsed(bitmap, lcn);
            if (!used)
            {
                if (runStart < 0) runStart = lcn;
                remaining--;
                if (remaining == 0)
                {
                    runs.Add((runStart, lcn - runStart + 1));
                    break;
                }
                continue;
            }
            // Used cluster: close any open run.
            if (runStart >= 0)
            {
                runs.Add((runStart, lcn - runStart));
                runStart = -1;
            }
        }

        if (remaining > 0)
            throw new NotSupportedException("no free clusters for raw write; standard API fallback");

        // Mark allocated clusters in-use and persist the bitmap.
        foreach ((long lcn, long len) in runs)
            for (long i = lcn; i < lcn + len; i++) SetClusterBit(bitmap, i, used: true);
        WriteBitmapBytes(vol, bmpRec, bmpAttr, bitmap);
        return runs;
    }

    private static bool IsClusterUsed(byte[] bitmap, long lcn) =>
        ((bitmap[lcn / 8] >> (int)(lcn % 8)) & 1) != 0;

    private static void SetClusterBit(byte[] bitmap, long lcn, bool used)
    {
        int bit = (int)(lcn % 8);
        if (used) bitmap[lcn / 8] |= (byte)(1 << bit);
        else bitmap[lcn / 8] &= (byte)~(1 << bit);
    }

    // Persist a full bitmap byte array. Resident: rewrite record 6 with USA
    // fixup. Non-resident: write through the $Bitmap runlist.
    private static void WriteBitmapBytes(NtfsVolume vol, NtfsRecord bmpRec, NtfsAttribute bmpAttr, byte[] bitmap)
    {
        if (bmpAttr.NonResident)
        {
            WriteNonResidentValue(vol, bmpAttr, bitmap);
        }
        else
        {
            byte[] rec = (byte[])bmpRec.Raw.Clone();
            (int valueOffset, int valueLen) = bmpAttr.ResidentValueLocation();
            if (valueOffset + valueLen > rec.Length)
                throw new InvalidDataException("bad $Bitmap resident value location");
            Array.Copy(bitmap, 0, rec, valueOffset, Math.Min(valueLen, bitmap.Length));
            byte[] fixedRecord = ApplyFixup(vol, rec);
            vol.WriteBytes(vol.MftOffset + 6 * vol.RecordSize, fixedRecord);
        }
    }

    private static int UsedSize(byte[] record) => (int)ReadU32(record, FhUsedSize);

    // Encode a runlist from (LCN, lengthInClusters) runs into mapping-pairs
    // bytes. Format (mirror of Runlist() decode):
    //   header byte: high nibble = offset-field byte count, low nibble = length-field byte count
    //   length field: LE unsigned
    //   offset field: LE signed, relative to previous LCN (first run relative to 0)
    //   terminated by a 0x00 byte. Sparse runs (lcn == -1) are not produced here.
    public static byte[] EncodeRunlist(IReadOnlyList<(long Lcn, long Length)> runs)
    {
        using var ms = new MemoryStream();
        long prevLcn = 0;
        foreach ((long lcn, long length) in runs)
        {
            if (length <= 0 || lcn < 0) continue; // ignore sparse/empty
            long delta = lcn - prevLcn;
            int lengthBytes = RequiredBytesUnsigned(length);
            int offsetBytes = RequiredBytesSigned(delta);
            ms.WriteByte((byte)((offsetBytes << 4) | lengthBytes));
            WriteLeUnsigned(ms, length, lengthBytes);
            WriteLeSigned(ms, delta, offsetBytes);
            prevLcn = lcn;
        }
        ms.WriteByte(0x00); // terminator
        return ms.ToArray();
    }

    // Minimal byte count to hold an unsigned value (>= 1).
    private static int RequiredBytesUnsigned(long value)
    {
        int n = 1;
        while (n < 8 && (value >> (8 * n)) != 0) n++;
        return n;
    }

    // Minimal byte count to hold a signed value (sign bit preserved).
    private static int RequiredBytesSigned(long value)
    {
        if (value >= 0)
        {
            int n = 1;
            while (n < 8 && (value >> (8 * n)) != 0) n++;
            // Ensure the top bit of the top byte is a sign bit consistent with 0.
            if (n < 8 && (value & (1L << (8 * n - 1))) != 0) n++;
            return n;
        }
        int m = 1;
        while (m < 8 && (value >> (8 * m)) != -1) m++;
        return m;
    }

    private static void WriteLeUnsigned(Stream s, long value, int bytes)
    {
        for (int i = 0; i < bytes; i++) s.WriteByte((byte)(value >> (8 * i)));
    }

    private static void WriteLeSigned(Stream s, long value, int bytes)
    {
        for (int i = 0; i < bytes; i++) s.WriteByte((byte)(value >> (8 * i)));
    }


    // ---- helpers ----
    // Read the current LSN from $LogFile's restart area. New FILE records must
    // carry an LSN within the log's valid window or chkdsk rejects them as
    // corrupt. Layout (see $LogFile restart area spec):
    //   page 0: "RSTR" header; restart record at offset restart_offset (0x30);
    //   current_lsn at restart record +0x08.
    private static long ReadCurrentLogLsn(NtfsVolume vol)
    {
        try
        {
            NtfsRecord logFile = NtfsRecord.Read(vol, 2); // $LogFile
            NtfsAttribute? data = logFile.FindAttribute(NtfsRecord.AttrData);
            if (data is null) return 0;
            byte[] page0 = data.ReadValue(vol, 0, 4096);
            if (page0.Length < 0x40 || Encoding.ASCII.GetString(page0, 0, 4) != "RSTR")
                return 0;
            int restartOffset = page0[0x18] | (page0[0x19] << 8); // u16 @ 0x18
            // current_lsn is the first field of RESTART_AREA (8 bytes @ +0x00)
            long currentLsn = 0;
            for (int i = 0; i < 8; i++)
                currentLsn |= (long)page0[restartOffset + i] << (8 * i);
            return currentLsn;
        }
        catch
        {
            return 0;
        }
    }

    private static ushort ReadU16(byte[] b, int off) => (ushort)(b[off] | (b[off + 1] << 8));
    private static uint ReadU32(byte[] b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
    private static void WriteU8(Span<byte> b, int off, byte v) => b[off] = v;
    private static void WriteU16(Span<byte> b, int off, int v) { b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); }
    private static void WriteU32(Span<byte> b, int off, uint v) { b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24); }
    private static void WriteU64(Span<byte> b, int off, ulong v)
    {
        for (int i = 0; i < 8; i++) b[off + i] = (byte)(v >> (8 * i));
    }
    private static void WriteAscii(Span<byte> b, int off, string s)
    {
        for (int i = 0; i < s.Length; i++) b[off + i] = (byte)s[i];
    }
}
