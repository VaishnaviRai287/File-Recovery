import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# FILE MAGIC SIGNATURES
# Reference: https://www.garykessler.net/library/file_sigs.html
# ─────────────────────────────────────────────────────────────────────────────

FILE_MAGIC_MAP: Dict[bytes, tuple] = {
    b"\x89PNG\r\n\x1a\n": ("image/png", "png"),
    b"\xff\xd8\xff": ("image/jpeg", "jpg"),
    b"GIF87a": ("image/gif", "gif"),
    b"GIF89a": ("image/gif", "gif"),
    b"BM": ("image/bmp", "bmp"),
    b"PK\x03\x04": ("application/zip", "zip"),
    b"PK\x05\x06": ("application/zip", "zip"),
    b"\x50\x4b\x07\x08": ("application/zip", "zip"),
    b"Rar!\x1a\x07": ("application/x-rar", "rar"),
    b"\x1f\x8b": ("application/gzip", "gz"),
    b"BZh": ("application/x-bzip2", "bz2"),
    b"\xfd7zXZ\x00": ("application/x-xz", "xz"),
    b"7z\xbc\xaf\x27\x1c": ("application/x-7z-compressed", "7z"),
    b"%PDF": ("application/pdf", "pdf"),
    b"\xd0\xcf\x11\xe0": ("application/msword", "doc"),  # OLE2 compound
    b"MZ": ("application/x-dosexec", "exe"),
    b"\x7fELF": ("application/x-elf", "elf"),
    b"#!": ("text/x-shellscript", "sh"),
    b"<?xml": ("text/xml", "xml"),
    b"<html": ("text/html", "html"),
    b"<!DOCTYPE": ("text/html", "html"),
    b"\x00\x00\x01\xba": ("video/mpeg", "mpg"),
    b"\x00\x00\x01\xb3": ("video/mpeg", "mpg"),
    b"ftyp": ("video/mp4", "mp4"),
    b"ID3": ("audio/mpeg", "mp3"),
    b"OggS": ("audio/ogg", "ogg"),
    b"RIFF": ("audio/wav", "wav"),
    b"SQLite format 3": ("application/x-sqlite3", "db"),
    b"\x4d\x5a": ("application/x-dosexec", "exe"),
}


def identify_file_type(data: bytes) -> Dict[str, str]:
    """Identify a file's type from its magic bytes."""
    if not data or len(data) < 2:
        return {"mime_type": "application/octet-stream", "extension": "bin", "confidence": "none"}

    for magic, (mime, ext) in FILE_MAGIC_MAP.items():
        if data[:len(magic)] == magic:
            return {"mime_type": mime, "extension": ext, "confidence": "high"}

    # Heuristic: mostly printable ASCII → text
    printable_ratio = sum(1 for b in data[:64] if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    if len(data) > 0 and printable_ratio / min(64, len(data)) > 0.85:
        return {"mime_type": "text/plain", "extension": "txt", "confidence": "medium"}

    return {"mime_type": "application/octet-stream", "extension": "bin", "confidence": "low"}


@dataclass
class ForensicMetadata:
    """Normalized forensic metadata for a recovered artifact (NTFS/EXT4/XFS)."""
    filesystem_type: str        # 'ntfs', 'ext4', 'xfs'
    identifier: str             # MFT record number or inode number (as string)
    filename: Optional[str]     # Only available from NTFS (EXT4/XFS lose filenames on delete)
    size_bytes: int
    is_directory: bool
    uid: Optional[int]          # NTFS: None; EXT4/XFS: owner UID
    gid: Optional[int]          # NTFS: None; EXT4/XFS: owner GID
    mode: Optional[str]         # Octal permissions string (NTFS: None)
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    metadata_changed: Optional[datetime]  # NTFS: MFT modified; EXT4: ctime
    deleted_time: Optional[datetime]      # EXT4 dtime; NTFS/XFS: None
    recovery_confidence: str
    mime_type: str = "application/octet-stream"
    magic_extension: str = "bin"
    raw_data_sample: bytes = b""  # First 64 bytes for file identification

    def enrich_from_content(self, data: bytes) -> None:
        """Identify file type from content and update MIME fields."""
        if data:
            self.raw_data_sample = data[:64]
            result = identify_file_type(data)
            self.mime_type = result["mime_type"]
            self.magic_extension = result["extension"]

    def to_dict(self) -> dict:
        return {
            "filesystem_type": self.filesystem_type,
            "identifier": self.identifier,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "is_directory": self.is_directory,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "metadata_changed": self.metadata_changed.isoformat() if self.metadata_changed else None,
            "deleted_time": self.deleted_time.isoformat() if self.deleted_time else None,
            "recovery_confidence": self.recovery_confidence,
            "mime_type": self.mime_type,
            "magic_extension": self.magic_extension,
        }


class MetadataExtractor:
    """Converts raw filesystem records into normalized ForensicMetadata objects."""

    @staticmethod
    def from_ntfs_record(record) -> ForensicMetadata:
        """Convert a DeletedFileRecord (NTFS) to ForensicMetadata."""
        return ForensicMetadata(
            filesystem_type="ntfs",
            identifier=str(record.mft_record_number),
            filename=record.filename,
            size_bytes=record.size_bytes,
            is_directory=record.is_directory,
            uid=None,
            gid=None,
            mode=None,
            created=record.created,
            modified=record.modified,
            accessed=record.accessed,
            metadata_changed=record.mft_modified,
            deleted_time=None,  # NTFS does not record deletion time
            recovery_confidence=record.recovery_confidence,
        )

    @staticmethod
    def from_ext4_inode(record) -> ForensicMetadata:
        """Convert a DeletedInodeRecord (EXT4) to ForensicMetadata."""
        return ForensicMetadata(
            filesystem_type="ext4",
            identifier=str(record.inode_number),
            filename=None,  # EXT4 directory entries are deleted separately
            size_bytes=record.size_bytes,
            is_directory=record.is_directory,
            uid=record.uid,
            gid=record.gid,
            mode=oct(record.mode),
            created=None,  # EXT4 does not store creation time in inode (ext4-crtime is optional)
            modified=record.modify_time,
            accessed=record.access_time,
            metadata_changed=record.change_time,
            deleted_time=record.deletion_time,
            recovery_confidence=record.recovery_confidence,
        )

    @staticmethod
    def from_xfs_inode(record) -> ForensicMetadata:
        """Convert a DeletedXFSInodeRecord to ForensicMetadata."""
        return ForensicMetadata(
            filesystem_type="xfs",
            identifier=str(record.inode_number),
            filename=None,
            size_bytes=record.size_bytes,
            is_directory=(record.file_type == "directory"),
            uid=record.uid,
            gid=record.gid,
            mode=oct(record.mode),
            created=None,
            modified=record.mtime,
            accessed=record.atime,
            metadata_changed=record.ctime,
            deleted_time=None,  # XFS does not store deletion time
            recovery_confidence=record.recovery_confidence,
        )


def build_timeline(metadata_list: list) -> list:
    """Build a forensic timeline sorted chronologically from a list of ForensicMetadata objects."""
    events = []
    for meta in metadata_list:
        label = meta.filename or f"{meta.filesystem_type}:inode:{meta.identifier}"
        for ts_name, ts_value in [
            ("created", meta.created),
            ("modified", meta.modified),
            ("accessed", meta.accessed),
            ("metadata_changed", meta.metadata_changed),
            ("deleted", meta.deleted_time),
        ]:
            if ts_value:
                events.append({
                    "timestamp": ts_value.isoformat(),
                    "event_type": ts_name,
                    "artifact": label,
                    "filesystem": meta.filesystem_type,
                    "size_bytes": meta.size_bytes,
                    "confidence": meta.recovery_confidence,
                })

    events.sort(key=lambda e: e["timestamp"])
    return events
