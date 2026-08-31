namespace SpxAgent.Ntfs;

// Public directory-entry shape surfaced to the Agent (maps to sliver FileInfo).
public sealed record NtfsEntry(
    string Name,
    bool IsDir,
    long Size,
    long ModTimeUnix,
    string Mode,
    string? Link,
    string? Uid,
    string? Gid);
