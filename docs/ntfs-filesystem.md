# NTFS 模块设计说明

> 文档对应 `SPXAgent/Ntfs/` 下的实现。目标：**不经过 Windows 文件系统栈**，直接对卷设备做扇区级读写，从而绕开 Minifilter（文件系统过滤驱动）对 `CreateFile`/`ReadFile`/`WriteFile` 的监控。所有"文件系统效果"都是通过**解析/改写磁盘上的 NTFS 数据结构**实现的。

## 1. 定位链（读路径的核心心智模型）

```
Boot Sector → $MFT → Record(5=根目录) → Attribute → Runlist / Index → 数据
```

- **Boot Sector**：给出卷参数，定位 `$MFT` 在哪。
- **$MFT**：卷上每个文件/目录的"档案卡"集合，一张卡 = 一个 MFT Record。
- **Attribute**：Record 内描述文件不同方面（文件名、时间戳、数据、目录索引）。
- **Runlist**：非驻留数据实际落在哪些簇。
- **Index**：目录如何按名字查到子项（类似 B-tree）。

任何操作的第一步都是 **路径遍历**：从根目录 `mft[5]` 开始，逐段在目录索引里按名字查找。

```
路径: \Users\test.txt
1. 从根目录 mft[5] 开始
2. 在索引中找 "Users" → 得到 file_reference
3. 跳到对应的 Record
4. 在索引中找 "test.txt" → 得到 file_reference
5. 跳到目标 Record
```

## 2. 数据结构定义（代码注释中展示的即这些）

### 2.1 Boot Sector

```c
// 见 NtfsVolume.cs 中 OffBytesPerSector/OffSectorsPerCluster/OffMftLcn 等常量
typedef struct NTFS_BOOT_SECTOR {
    uint8_t  jump[3];                   // 0x00
    char     oem_id[8];                 // 0x03 "NTFS    "
    uint16_t bytes_per_sector;          // 0x0B 每扇区字节数（通常 512）
    uint8_t  sectors_per_cluster;       // 0x0D 每簇扇区数
    uint16_t reserved_sectors;          // 0x0E
    uint64_t total_sectors;             // 0x28 卷总扇区数
    uint64_t mft_lcn;                   // 0x30 $MFT 起始簇号
    uint64_t mftmirr_lcn;               // 0x38 $MFTMirr 起始簇号
    int8_t   clusters_per_file_record;  // 0x40 每个 Record 簇数（负=2^-n 字节，如 -10 → 1KB）
    int8_t   clusters_per_index_block;  // 0x44 每个索引块簇数
    uint64_t volume_serial_number;      // 0x48
    uint32_t checksum;                  // 0x50
    uint8_t  boot_code[426];            // 0x54
    uint16_t end_marker;                // 0x1FE 0xAA55
} NTFS_BOOT_SECTOR;
```

```
MFT 物理偏移 = mft_lcn × sectors_per_cluster × bytes_per_sector
```

### 2.2 MFT Record（文件/目录的"档案卡"）

```c
// 见 NtfsRecord.cs（OffMagic..OffMftRecordNumber）与 NtfsWriter.cs（Fh* 常量）
typedef struct NTFS_FILE_RECORD_HEADER {
    char     magic[4];              // 0x00 "FILE"
    uint16_t usa_offset;            // 0x04 USA 区偏移
    uint16_t usa_count;             // 0x06 USA 项数量
    uint64_t lsn;                   // 0x08 日志序列号
    uint16_t sequence_number;       // 0x10 Record 复用次数
    uint16_t hard_link_count;       // 0x12 硬链接数
    uint16_t first_attr_offset;     // 0x14 第一个 Attribute 偏移
    uint16_t flags;                 // 0x16 0x0001=使用中 0x0002=目录
    uint32_t used_size;             // 0x18 已使用字节数
    uint32_t allocated_size;        // 0x1C 分配总字节数
    uint64_t base_file_record;      // 0x20 扩展记录引用（0=非扩展）
    uint16_t next_attr_id;          // 0x28 下一个属性 ID
    uint16_t reserved;              // 0x2A
    uint32_t mft_record_number;     // 0x2C Record 编号
} NTFS_FILE_RECORD_HEADER;
```

**USA（Update Sequence Array）修复**：Record 覆盖多个扇区，写盘时每个扇区末尾 2 字节被替换为序列号 `usn`，原值存入 USA 数组；读盘时校验 `usn` 并恢复原值。任何**写入 Record 前必须重新应用 USA fixup**（`NtfsWriter.ApplyFixup`），否则扇区末尾是错误值。

### 2.3 Attribute

```c
// 见 NtfsAttribute.cs（Off* 常量）
typedef struct NTFS_ATTR_HEADER_COMMON {
    uint32_t type;                  // 0x00 0x10=SI 0x30=FILE_NAME 0x80=DATA 0x90=INDEX_ROOT 0xA0=INDEX_ALLOCATION
    uint32_t length;                // 0x04 整个 Attribute 长度
    uint8_t  non_resident;          // 0x08 0=驻留 1=非驻留
    uint8_t  name_length;           // 0x09
    uint16_t name_offset;           // 0x0A
    uint16_t flags;                 // 0x0C
    uint16_t attr_id;               // 0x0E
} NTFS_ATTR_HEADER_COMMON;

typedef struct NTFS_ATTR_HEADER_RESIDENT {     // non_resident=0
    NTFS_ATTR_HEADER_COMMON common;
    uint32_t value_length;          // 0x10 数据长度
    uint16_t value_offset;          // 0x14 数据偏移（相对 Attribute 起始）
    uint8_t  indexed_flag;          // 0x16
    uint8_t  reserved;
} NTFS_ATTR_HEADER_RESIDENT;

typedef struct NTFS_ATTR_HEADER_NONRESIDENT {  // non_resident=1
    NTFS_ATTR_HEADER_COMMON common;
    uint64_t lowest_vcn;            // 0x10
    uint64_t highest_vcn;           // 0x18
    uint16_t mapping_pairs_offset;  // 0x20 Runlist 偏移（相对 Attribute 起始）
    uint8_t  compression_unit;      // 0x22
    uint8_t  reserved[5];           // 0x23
    uint64_t allocated_size;        // 0x28
    uint64_t data_size;             // 0x30 逻辑大小
    uint64_t initialized_size;      // 0x38
    uint64_t compressed_size;       // 0x40 可选
} NTFS_ATTR_HEADER_NONRESIDENT;
```

### 2.4 Runlist（VCN → LCN 映射）

```c
// 见 NtfsAttribute.cs Runlist()。逐字节解析：
// 每个 run 首字节 header：低 4 位 = 长度字段字节数，高 4 位 = 偏移字段字节数
// 然后：长度字段（小端无符号）→ 偏移字段（小端有符号增量，delta==0 表示稀疏）
// 字段顺序：先长度、后偏移。header 低半字节为 0 表示 runlist 结束。
// 例：0x33 0x20 0xC8 0x00 0x00 0x00 0x0C
//     → len=0x00C820=51232, delta=0x0C0000=786432 → run (lcn=786432, len=51232)
```

> ⚠️ 曾在此踩坑：最初把高半字节当长度、低半字节当偏移，导致 $MFT 的 run2 解出 3.5 亿簇。已通过逆向参考工具 `NTFSExplorer.exe` 的 `sub_140005E10` 确认正确语义，并已修复。

数据偏移 = `LCN × ClusterSize`（簇大小 = `sectors_per_cluster × bytes_per_sector`）。

### 2.5 目录索引（INDEX_ROOT / INDEX_ALLOCATION / INDEX_ENTRY）

```c
// INDEX_ROOT(0x90, resident) 的 value 布局 —— 见 NtfsIndex.cs / NtfsWriter.cs InsertIndexEntry
// +0x00 u32 attrType(0x30) +0x04 u32 collation +0x08 u32 indexBlockSize +0x0C u8 clustersPerIndexBlock
// +0x10 INDEX_HEADER: +0x00 u32 entriesOffset +0x04 u32 indexLength +0x08 u32 allocatedSize +0x0C u8 flags
//     entries 起始 = 0x10 + entriesOffset

// INDEX_ENTRY —— 见 NtfsWriter.cs InsertIndexEntry（newEntry 布局）
typedef struct NTFS_INDEX_ENTRY {
    uint64_t file_reference;        // 0x00 低48位=Record号 高16位=序列号
    uint16_t entry_length;          // 0x08 整个 Entry 长度（8 字节对齐）
    uint16_t key_length;            // 0x0A Key 长度（=FILE_NAME value 长度）
    uint16_t flags;                 // 0x0C 0x0001=有子节点 0x0002=最后一项
    uint16_t reserved;              // 0x0E
    uint8_t  key[];                 // 0x10 FILE_NAME 属性 value（key 就是它）
    // 若 flags & 0x0001：key 后跟 8 字节子节点 VCN
} NTFS_INDEX_ENTRY;

// INDEX_ALLOCATION(0xA0, non-resident) 承载的 INDX 块：每块一簇，自带 USA fixup
// +0x00 "INDX" +0x04 usaOffset +0x06 usaCount +0x08 lsn +0x10 VCN
// +0x18 INDEX_HEADER（同上）+ entries
```

## 3. 读路径：如何通过解析实现效果

| 命令 | 数据结构操作 |
|---|---|
| `Pwd` | 直接返回 agent 内部维护的 `_cwd` 字符串，**不碰磁盘** |
| `Cd` | `ResolveRecord(path)`：从 mft[5] 逐段在目录索引里 `Find(name)` 拿 file_reference → 读目标 Record → 校验 `flags & 0x0002` 是目录 → 更新 `_cwd` |
| `Ls` | 解析目录 Record 的 `$INDEX_ROOT`(0x90) + `$INDEX_ALLOCATION`(0xA0) 的 INDX 块，枚举所有 `INDEX_ENTRY`，从每个 entry 的 FILE_NAME key 取出 name/isDir/size/modTime，组装 `NtfsEntry` |
| `Cat` | `ResolveRecord` → 找 `$DATA`(0x80) → 驻留则直接从 Record 内 `value_offset` 取值；非驻留则解 Runlist，按 `LCN×ClusterSize` 读簇 |

## 4. 写路径：如何通过改写数据结构实现效果

> 写路径要同步更新 NTFS 的一致性元数据。当前实现已处理其中大部分（见 §4.1 的"当前已处理的同步更新"），未处理的只有 `$UsnJrnl`（USN 变更日志，可选，见 §6）。

### 4.1 创建文件（touch）—— 当前 `CreateFile` 的实现

对 `fs.Write("\\dir\\f.txt", data)`：

```
1. 找空闲 Record：`AllocateRecord`（`NtfsFileSystem.cs:248`）通过 **`$MFT::$BITMAP`**（record 0 的 `$BITMAP` 属性）扫描空闲槽——`NtfsWriter.ReadMftRecordBit`/`SetMftRecordBit`（`NtfsWriter.cs`）读位图找 0 位并**立即置 1**，从 record 16 起
2. 构建新 FILE Record（NtfsWriter.BuildFileRecord）：
   - 头部：magic "FILE"、flags=0x0001（使用中）、record 号、USA 计数
   - $STANDARD_INFORMATION(0x10)：创建/修改/访问时间戳
   - $FILE_NAME(0x30)：父目录引用 + 名字 + 大小 + 目录标志
   - $DATA(0x80)：驻留时数据直接放 Record 内
   - 结束标记 0xFFFFFFFF
3. 应用 USA fixup 后写回 $MFT 的对应 Record 槽位
4. 在父目录索引插入新 INDEX_ENTRY（NtfsWriter.InsertIndexEntry）：
   - 定位插入点（按名字排序）
   - 构造 entry（file_reference 指向新 Record + FILE_NAME key）
   - 插入后重排，更新 INDEX_HEADER.index_length / allocated_size
   - 若索引在 $INDEX_ROOT 内增长，则连同后续 Attribute 一起右移，更新 Record used_size
```

**当前已处理的同步更新（与代码对应）**：

- `$MFT::$BITMAP` —— 已实现。`AllocateRecord` 经 `ReadMftRecordBit`/`SetMftRecordBit` 标记新分配 Record 占用。
- `$Bitmap`(record 6) —— 已实现。`AllocateClusters`（`NtfsWriter.cs`）首次适配分配簇并置位，`WriteBitmapBytes` 持久化（驻留重写 record 6 + USA fixup；非驻留按 runlist 写回）。
- `$LogFile` —— 新 FILE record 的 LSN 字段写 0（`BuildFileRecord` 中 `WriteU64(rec, FhLsn, 0)`）；未读 `$LogFile` restart area 的真实 LSN。提交 `51d754e` 验证 chkdsk 通过（LSN=0 在实践中未被拒绝）。
- 父目录 `$STANDARD_INFORMATION` 修改时间 —— 已实现。`TouchDirMtime` → `NtfsWriter.UpdateStandardInfoModTime`。
- 目录 `$I30` 索引位图 —— 已实现。索引 spill/扩展时经 `AttrBitmap` 维护。
- security ID 继承 —— 已实现。`ReadSecurityId`/`DefaultSecurityId`（父目录继承，回落 `$Secure` `$SII`，默认 `0x107`）。
- `$UsnJrnl` —— 未实现（唯一缺失项）。USN 变更日志可选，不影响卷完整性。

### 4.2 覆盖写入（write 已有文件）—— 当前 `OverwriteData`

```
1. 读目标 Record，定位 $DATA(0x80)
2. 若驻留且新数据 ≤ 原 value 容量：原地覆写 value + 更新 value_length + USA fixup 写回
3. 若需增长（新数据 > 原 `$DATA` value 容量）或本已非驻留：调 `NtfsWriter.RebuildDataNonResident` 把 `$DATA` 重建为非驻留——`AllocateClusters` 分配新簇 run、写入数据、生成 runlist（**不再有** NotSupportedException / 标准 API 回退）
```

### 4.3 各操作应改动的数据结构（对照 NTFS 规范；含已实现 / 未实现分界）

> 下表：touch / mkdir / write(增长) / rm / mv / cp 已实现。

| 操作 | 本质 | 要改的结构 |
|---|---|---|
| ls | 读目录索引 | 只读：INDEX_ROOT/INDEX_ALLOCATION |
| cat | 读 $DATA | 只读：DATA (resident/runlist) |
| touch | 新建 Record + 插入父索引 | $MFT 新槽 + $MFT::$BITMAP + 父目录 INDEX_* + $LogFile/USN |
| mkdir | 新建目录 Record + 初始化索引 | 同上 + 新目录的 INDEX_ROOT |
| rm | 删索引 entry + 回收资源 | 父目录 INDEX_* + Record flags 清零 + $MFT::$BITMAP + $Bitmap + $LogFile/USN |
| mv | 改索引 + 改 $FILE_NAME | 旧/新父目录 INDEX_* + Record 的 FILE_NAME(parent_ref/名字) |
| cp | 新建 Record + 复制数据 | 同 touch + 写 $DATA |
| write(增长) | $DATA 扩容 | 可能 resident→non-resident 转换 + 分配簇 + 更新 Runlist + $Bitmap + $LogFile/USN |

## 5. 卷访问与锁定

- 卷设备路径：`\\.\X:`（`NtfsVolume.ToDevicePath`），用 `CreateFile` 打开卷设备（例外：这是打开卷，不是文件，不触发 minifilter 文件回调）。
- 读：`SetFilePointerEx` + `ReadFile`，`FILE_FLAG_NO_BUFFERING` + `FSCTL_ALLOW_EXTENDED_DASD_IO` 允许非对齐/越界读取。
- 写：Windows 对已挂载卷的原始写默认拒绝（`ERROR_ACCESS_DENIED`）。必须先 `FSCTL_LOCK_VOLUME` 锁卷（`NtfsVolume.LockVolume`，writable 打开时自动锁），写完 `FSCTL_UNLOCK_VOLUME`（Dispose 时）。

## 6. 当前实现状态与限制

| 能力 | 状态 |
|---|---|
| 读路径（Pwd/Cd/Ls/Cat） | ✅ 完整，真实卷验证 |
| Runlist 解析 | ✅ 已修复（低4位=长度，高4位=偏移），经 NTFSExplorer.exe 逆向确认 |
| 写：新建文件（驻留/目录） | ✅ 完整，一致性元数据同步（$MFT::$BITMAP / 父索引 / 父目录 mtime / security id），chkdsk 验证通过（提交 51d754e） |
| 写：覆盖驻留 $DATA（等长/缩短） | ✅ 完整（OverwriteResidentData） |
| 写：非驻留 / 大文件（增长） | ✅ 已实现（RebuildDataNonResident + AllocateClusters + record-6 $Bitmap） |
| $UsnJrnl | ❌ 未实现（可选，不影响完整性） |
| rm / mv / cp | ✅ 已实现（rm 非递归；大目录 rm 做整棵 B-tree 重建，旧叶子簇不回收） |

### 6.1 Agent 侧接线（当前边界）

`FsCommands.cs` 用 `new NtfsFileSystem()` 构造（`NtfsFileSystem` 默认参数 `writable = false`）。读命令（Pwd/Cd/Ls/Download）正常；写命令（Upload/Rm/Mkdir/Mv/Cp）里 `Fs.Write`/`Fs.Rm`/`Fs.Mv`/`Fs.Cp` 会因卷只读在 `NtfsVolume.WriteBytes` 抛 `InvalidOperationException("volume opened read-only")`，被各命令的 catch 吞掉、把该文件计为 `unwriteableFiles=1` 或 `success=false`。**这不是"回退标准 API"，而是失败**。要让 agent 走原始写路径，需以 `writable: true` 打开卷（`writable=true` 时 `NtfsVolume.Open` 才加 `GENERIC_WRITE` 并 `LockVolume`）。

## 7. 安全与测试

- **绝对不在 C:/D: 真实卷上测试写路径**。写路径只在隔离 VHD（diskpart 创建 + NTFS 格式化 + 挂载）上验证，测完 detach 删除。
- 当前写路径已在隔离 VHD 上自洽读写并通过 chkdsk 验证（提交 51d754e）。
