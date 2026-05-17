import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Iterator
from datetime import datetime, timezone, timedelta

from config.settings import (
    NTFS_MFT_ENTRY_SIZE,
    NTFS_MFT_MAGIC,
    NTFS_BAD_CLUSTER_MAGIC,
    NTFS_MFT_RECORD_IN_USE,
    NTFS_MFT_RECORD_IS_DIR,
    NTFS_ATTR_STANDARD_INFO,
    NTFS_ATTR_FILE_NAME,
    NTFS_ATTR_DATA,
    NTFS_ATTR_END,
)

logger = logging.getLogger(__name__)

# Windows FILETIME epoch: January 1, 1601 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_TO_UNIX = 10_000_000  # FILETIME is in 100-nanosecond intervals


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if filetime == 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (OverflowError, OSError):
        return None


@dataclass
class MFTAttribute:
    attr_type: int
    attr_length: int
    non_resident: bool
    name: str
    data: bytes


@dataclass
class DeletedFileRecord:
    mft_record_number: int
    filename: str
    parent_mft_ref: int
    size_bytes: int
    is_directory: bool
    flags: int

    # MACE timestamps (NTFS has four timestamp fields)
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    mft_modified: Optional[datetime]

    # Recovery metadata
    raw_record: bytes = field(repr=False)
    recovery_confidence: str = "high"  # high / medium / low / uncertain

    @property
    def extension(self) -> str:
        parts = self.filename.rsplit(".", 1)
        return parts[1].lower() if len(parts) == 2 else ""

    @property
    def created_str(self) -> str:
        return self.created.isoformat() if self.created else "Unknown"

    @property
    def modified_str(self) -> str:
        return self.modified.isoformat() if self.modified else "Unknown"

    def to_dict(self) -> dict:
        return {
            "mft_record_number": self.mft_record_number,
            "filename": self.filename,
            "parent_mft_ref": self.parent_mft_ref,
            "size_bytes": self.size_bytes,
            "is_directory": self.is_directory,
            "created": self.created_str,
            "modified": self.modified_str,
            "accessed": self.accessed.isoformat() if self.accessed else "Unknown",
            "mft_modified": self.mft_modified.isoformat() if self.mft_modified else "Unknown",
            "recovery_confidence": self.recovery_confidence,
            "extension": self.extension,
        }


class MFTParser:

    def __init__(self, reader):
        self.reader = reader
        self._mft_offset: Optional[int] = None
        self._cluster_size: int = 4096
        self._total_records: int = 0

    def _parse_boot_sector(self) -> bool:
        try:
            boot = self.reader.read_at(0, 512)
            if boot[3:11] != b"NTFS    ":
                logger.error("Not an NTFS volume — boot sector OEM ID mismatch.")
                return False

            bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
            sectors_per_cluster = struct.unpack_from("<B", boot, 13)[0]
            self._cluster_size = bytes_per_sector * sectors_per_cluster

            mft_lcn = struct.unpack_from("<Q", boot, 48)[0]
            self._mft_offset = mft_lcn * self._cluster_size

            logger.info(
                f"NTFS boot sector parsed: "
                f"bytes/sector={bytes_per_sector}, "
                f"sectors/cluster={sectors_per_cluster}, "
                f"cluster_size={self._cluster_size}, "
                f"MFT offset={self._mft_offset:#010x}"
            )
            return True
        except Exception as e:
            logger.error(f"Boot sector parse failed: {e}")
            return False

    def _read_mft_record(self, record_number: int) -> Optional[bytes]:
        offset = self._mft_offset + (record_number * NTFS_MFT_ENTRY_SIZE)
        try:
            data = self.reader.read_at(offset, NTFS_MFT_ENTRY_SIZE)
            if len(data) < NTFS_MFT_ENTRY_SIZE:
                return None
            return data
        except Exception:
            return None

    def _parse_mft_record(self, record_number: int, raw: bytes) -> Optional[DeletedFileRecord]:
        # Validate signature
        sig = raw[0:4]
        if sig == NTFS_BAD_CLUSTER_MAGIC:
            logger.debug(f"Record {record_number}: BAAD signature, skipping.")
            return None
        if sig != NTFS_MFT_MAGIC:
            return None

        # Parse record header
        try:
            offset_to_attrs = struct.unpack_from("<H", raw, 0x14)[0]
            flags = struct.unpack_from("<H", raw, 0x16)[0]
        except struct.error:
            return None

        # Only process DELETED records (bit 0 of flags is clear)
        if flags & NTFS_MFT_RECORD_IN_USE:
            return None  # Still allocated — not deleted

        is_directory = bool(flags & NTFS_MFT_RECORD_IS_DIR)

        # Parse attributes
        filename = None
        parent_ref = 0
        size_bytes = 0
        created = modified = accessed = mft_modified = None

        attr_offset = offset_to_attrs
        while attr_offset < NTFS_MFT_ENTRY_SIZE - 8:
            try:
                attr_type = struct.unpack_from("<I", raw, attr_offset)[0]
                if attr_type == NTFS_ATTR_END or attr_type == 0xFFFFFFFF:
                    break
                attr_len = struct.unpack_from("<I", raw, attr_offset + 4)[0]
                if attr_len == 0 or attr_len > NTFS_MFT_ENTRY_SIZE:
                    break

                non_resident = raw[attr_offset + 8]
                name_length = raw[attr_offset + 9]
                content_offset = struct.unpack_from("<H", raw, attr_offset + 20)[0]

                if not non_resident and attr_len > 24:
                    content_start = attr_offset + content_offset
                    content_size = struct.unpack_from("<I", raw, attr_offset + 16)[0]
                    content = raw[content_start:content_start + content_size]

                    if attr_type == NTFS_ATTR_STANDARD_INFO and len(content) >= 48:
                        created = filetime_to_datetime(
                            struct.unpack_from("<Q", content, 0)[0])
                        modified = filetime_to_datetime(
                            struct.unpack_from("<Q", content, 8)[0])
                        mft_modified = filetime_to_datetime(
                            struct.unpack_from("<Q", content, 16)[0])
                        accessed = filetime_to_datetime(
                            struct.unpack_from("<Q", content, 24)[0])

                    elif attr_type == NTFS_ATTR_FILE_NAME and len(content) >= 66:
                        parent_ref = struct.unpack_from("<Q", content, 0)[0] & 0x0000FFFFFFFFFFFF
                        fn_created = filetime_to_datetime(struct.unpack_from("<Q", content, 8)[0])
                        fn_modified = filetime_to_datetime(struct.unpack_from("<Q", content, 16)[0])
                        size_bytes = struct.unpack_from("<Q", content, 40)[0]
                        fn_len = content[64]
                        fn_namespace = content[65]
                        # Prefer POSIX/Win32 namespace (namespace 0 or 1) over DOS (2)
                        if fn_namespace != 2 or filename is None:
                            if len(content) >= 66 + fn_len * 2:
                                fname_bytes = content[66:66 + fn_len * 2]
                                try:
                                    filename = fname_bytes.decode("utf-16-le")
                                except UnicodeDecodeError:
                                    filename = repr(fname_bytes)

                attr_offset += attr_len
            except (struct.error, IndexError):
                break

        if not filename:
            return None

        # Assess recovery confidence based on data completeness
        confidence = "high"
        if not created and not modified:
            confidence = "medium"
        if not size_bytes and not is_directory:
            confidence = "low"

        return DeletedFileRecord(
            mft_record_number=record_number,
            filename=filename,
            parent_mft_ref=parent_ref,
            size_bytes=size_bytes,
            is_directory=is_directory,
            flags=flags,
            created=created,
            modified=modified,
            accessed=accessed,
            mft_modified=mft_modified,
            raw_record=raw,
            recovery_confidence=confidence,
        )

    def iter_deleted_files(self, max_records: int = 100_000) -> Iterator[DeletedFileRecord]:
        if not self._parse_boot_sector():
            logger.error("Cannot scan MFT — boot sector parse failed.")
            return

        logger.info(f"Beginning MFT scan at offset {self._mft_offset:#010x}...")
        found = 0

        for record_num in range(max_records):
            raw = self._read_mft_record(record_num)
            if raw is None:
                if record_num > 100:  # Allow some initial failures
                    logger.info(f"MFT scan ended at record {record_num} (no more data).")
                    break
                continue

            record = self._parse_mft_record(record_num, raw)
            if record:
                found += 1
                logger.debug(
                    f"Deleted: #{record_num} '{record.filename}' "
                    f"({record.size_bytes} bytes, confidence={record.recovery_confidence})"
                )
                yield record

        logger.info(f"MFT scan complete. Found {found} deleted file records.")

    def get_all_deleted_files(self, max_records: int = 100_000) -> List[DeletedFileRecord]:
        return list(self.iter_deleted_files(max_records))
