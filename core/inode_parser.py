import struct
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Iterator

from config.settings import (
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE,
    EXT4_INODE_SIZE,
    EXT4_MAGIC,
    EXT4_BLOCK_SIZE,
    EXT4_INODE_MODE_REGULAR,
    EXT4_INODE_MODE_DIR,
    EXT4_INODE_MODE_SYMLINK,
    EXT4_FEATURE_INCOMPAT_EXTENTS,
)

logger = logging.getLogger(__name__)


def unix_to_datetime(ts: int) -> Optional[datetime]:
    """Convert a UNIX timestamp to UTC datetime."""
    if ts == 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


@dataclass
class EXT4Superblock:
    """Parsed EXT4 superblock — root metadata structure of an EXT4 volume."""
    inode_count: int
    block_count: int
    block_size: int               # Actual block size = 1024 << log_block_size
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    feature_incompat: int
    first_data_block: int
    groups_count: int             # Calculated from inode_count / inodes_per_group

    @property
    def has_extents(self) -> bool:
        return bool(self.feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS)

    @property
    def group_descriptor_size(self) -> int:
        """EXT4 can have 32 or 64 byte group descriptors."""
        from config.settings import EXT4_BLOCK_GROUP_DESC_SIZE
        return EXT4_BLOCK_GROUP_DESC_SIZE  # 64 bytes for ext4

    def inode_group(self, inode_num: int) -> int:
        """Return the block group containing this inode (1-indexed inode number)."""
        return (inode_num - 1) // self.inodes_per_group

    def inode_index(self, inode_num: int) -> int:
        """Return the index of this inode within its block group."""
        return (inode_num - 1) % self.inodes_per_group


@dataclass
class DeletedInodeRecord:
    """Represents a recovered deleted inode entry from the EXT4 inode table."""
    inode_number: int
    file_type: str              # 'regular', 'directory', 'symlink', 'unknown'
    mode: int                   # Raw mode bits
    uid: int
    gid: int
    size_bytes: int
    link_count: int
    deletion_time: Optional[datetime]
    access_time: Optional[datetime]
    change_time: Optional[datetime]
    modify_time: Optional[datetime]
    flags: int
    block_pointers: bytes       # Raw i_block field (60 bytes)
    uses_extents: bool
    recovery_confidence: str = "high"

    @property
    def is_regular_file(self) -> bool:
        return (self.mode & 0xF000) == EXT4_INODE_MODE_REGULAR

    @property
    def is_directory(self) -> bool:
        return (self.mode & 0xF000) == EXT4_INODE_MODE_DIR

    def to_dict(self) -> dict:
        return {
            "inode_number": self.inode_number,
            "file_type": self.file_type,
            "mode": oct(self.mode),
            "uid": self.uid,
            "gid": self.gid,
            "size_bytes": self.size_bytes,
            "link_count": self.link_count,
            "deletion_time": self.deletion_time.isoformat() if self.deletion_time else "Unknown",
            "access_time": self.access_time.isoformat() if self.access_time else "Unknown",
            "modify_time": self.modify_time.isoformat() if self.modify_time else "Unknown",
            "uses_extents": self.uses_extents,
            "recovery_confidence": self.recovery_confidence,
        }


class InodeParser:

    def __init__(self, reader):
        self.reader = reader
        self._superblock: Optional[EXT4Superblock] = None
        self._group_desc_table_offset: int = 0

    def _parse_superblock(self) -> bool:
        """Parse the EXT4 superblock at byte offset 1024."""
        try:
            sb_data = self.reader.read_at(EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE)
            if len(sb_data) < 84:
                return False

            magic = struct.unpack_from("<H", sb_data, 56)[0]
            if magic != EXT4_MAGIC:
                logger.error(f"EXT4 magic mismatch: got {magic:#06x}, expected {EXT4_MAGIC:#06x}")
                return False

            inode_count = struct.unpack_from("<I", sb_data, 0)[0]
            block_count = struct.unpack_from("<I", sb_data, 4)[0]
            log_block_size = struct.unpack_from("<I", sb_data, 24)[0]
            blocks_per_group = struct.unpack_from("<I", sb_data, 32)[0]
            inodes_per_group = struct.unpack_from("<I", sb_data, 40)[0]
            inode_size = struct.unpack_from("<H", sb_data, 88)[0] if len(sb_data) > 90 else 128
            first_data_block = struct.unpack_from("<I", sb_data, 20)[0]
            feature_incompat = struct.unpack_from("<I", sb_data, 96)[0] if len(sb_data) > 100 else 0

            actual_block_size = 1024 << log_block_size
            groups_count = (inode_count + inodes_per_group - 1) // inodes_per_group

            self._superblock = EXT4Superblock(
                inode_count=inode_count,
                block_count=block_count,
                block_size=actual_block_size,
                blocks_per_group=blocks_per_group,
                inodes_per_group=inodes_per_group,
                inode_size=inode_size,
                feature_incompat=feature_incompat,
                first_data_block=first_data_block,
                groups_count=groups_count,
            )

            # Group descriptor table immediately follows the superblock block
            # On 1024-byte block size: group descs start at block 2 (byte 2048)
            # On 4096-byte block size: group descs start at block 1 (byte 4096)
            superblock_block = first_data_block  # Usually 0 for 4096-byte blocks, 1 for 1024
            self._group_desc_table_offset = (superblock_block + 1) * actual_block_size

            logger.info(
                f"EXT4 superblock parsed: "
                f"inode_count={inode_count}, "
                f"block_size={actual_block_size}, "
                f"inodes_per_group={inodes_per_group}, "
                f"groups={groups_count}, "
                f"inode_size={inode_size}"
            )
            return True

        except Exception as e:
            logger.error(f"Superblock parse failed: {e}")
            return False

    def _get_inode_table_offset(self, group_num: int) -> Optional[int]:
        """Get the byte offset of the inode table for a block group."""
        sb = self._superblock
        gd_size = 32  # Standard group descriptor size (32 bytes for EXT2/3, 64 for EXT4)
        # Use 32-byte descriptors for compatibility — bg_inode_table at offset 8
        gd_offset = self._group_desc_table_offset + group_num * gd_size
        try:
            gd_data = self.reader.read_at(gd_offset, gd_size)
            inode_table_block = struct.unpack_from("<I", gd_data, 8)[0]
            return inode_table_block * sb.block_size
        except Exception as e:
            logger.debug(f"Group descriptor {group_num} read failed: {e}")
            return None

    def _parse_inode(self, inode_num: int) -> Optional[DeletedInodeRecord]:
        """Parse a single EXT4 inode; return a record if it is deleted."""
        sb = self._superblock
        group = sb.inode_group(inode_num)
        index = sb.inode_index(inode_num)

        table_offset = self._get_inode_table_offset(group)
        if table_offset is None:
            return None

        inode_offset = table_offset + index * sb.inode_size

        try:
            data = self.reader.read_at(inode_offset, min(sb.inode_size, 256))
            if len(data) < 128:
                return None

            mode = struct.unpack_from("<H", data, 0)[0]
            uid = struct.unpack_from("<H", data, 2)[0]
            size_lo = struct.unpack_from("<I", data, 4)[0]
            atime = struct.unpack_from("<I", data, 8)[0]
            ctime = struct.unpack_from("<I", data, 12)[0]
            mtime = struct.unpack_from("<I", data, 16)[0]
            dtime = struct.unpack_from("<I", data, 20)[0]
            gid = struct.unpack_from("<H", data, 24)[0]
            link_count = struct.unpack_from("<H", data, 26)[0]
            flags = struct.unpack_from("<I", data, 32)[0]
            block_data = data[40:100]  # i_block field (60 bytes)

            # Get high 32 bits of size (ext4 extension at offset 0x6C)
            size_high = struct.unpack_from("<I", data, 108)[0] if len(data) >= 112 else 0
            size_bytes = (size_high << 32) | size_lo

            # Only interested in DELETED inodes: dtime != 0 OR link_count == 0
            if dtime == 0 and link_count != 0:
                return None

            # Determine file type from mode bits
            mode_type = mode & 0xF000
            if mode_type == EXT4_INODE_MODE_REGULAR:
                file_type = "regular"
            elif mode_type == EXT4_INODE_MODE_DIR:
                file_type = "directory"
            elif mode_type == EXT4_INODE_MODE_SYMLINK:
                file_type = "symlink"
            elif mode == 0:
                return None  # Uninitialized inode
            else:
                file_type = "unknown"

            uses_extents = bool(flags & EXT4_FEATURE_INCOMPAT_EXTENTS)

            confidence = "high"
            if size_bytes == 0 and file_type == "regular":
                confidence = "low"
            elif dtime == 0:
                confidence = "medium"

            return DeletedInodeRecord(
                inode_number=inode_num,
                file_type=file_type,
                mode=mode,
                uid=uid,
                gid=gid,
                size_bytes=size_bytes,
                link_count=link_count,
                deletion_time=unix_to_datetime(dtime),
                access_time=unix_to_datetime(atime),
                change_time=unix_to_datetime(ctime),
                modify_time=unix_to_datetime(mtime),
                flags=flags,
                block_pointers=block_data,
                uses_extents=uses_extents,
                recovery_confidence=confidence,
            )

        except Exception as e:
            logger.debug(f"Inode {inode_num} parse error: {e}")
            return None

    def iter_deleted_inodes(self) -> Iterator[DeletedInodeRecord]:
        """Scan all inodes and yield deleted ones."""
        if not self._parse_superblock():
            logger.error("Cannot scan inodes — superblock parse failed.")
            return

        sb = self._superblock
        found = 0
        # First 11 inodes are reserved (root=2, lost+found=11, etc.)
        for inode_num in range(12, sb.inode_count + 1):
            record = self._parse_inode(inode_num)
            if record:
                found += 1
                logger.debug(
                    f"Deleted inode {inode_num}: type={record.file_type}, "
                    f"size={record.size_bytes}, dtime={record.deletion_time}"
                )
                yield record

        logger.info(f"Inode scan complete. Found {found} deleted inodes.")

    def get_all_deleted_inodes(self) -> List[DeletedInodeRecord]:
        """Collect all deleted inodes into a list."""
        return list(self.iter_deleted_inodes())

    def get_superblock_info(self) -> dict:
        """Return superblock metadata for reporting."""
        if not self._superblock:
            self._parse_superblock()
        if not self._superblock:
            return {}
        sb = self._superblock
        return {
            "inode_count": sb.inode_count,
            "block_count": sb.block_count,
            "block_size": sb.block_size,
            "blocks_per_group": sb.blocks_per_group,
            "inodes_per_group": sb.inodes_per_group,
            "inode_size": sb.inode_size,
            "groups_count": sb.groups_count,
            "has_extents": sb.has_extents,
        }
