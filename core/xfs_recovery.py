import struct
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Iterator

from core.hash_verifier import HashVerifier
from config.settings import (
    XFS_SUPERBLOCK_MAGIC,
    XFS_INODE_MAGIC,
    XFS_BLOCK_SIZE,
    XFS_INODE_SIZE,
    XFS_AGI_MAGIC,
    XFS_DINODE_FMT_EXTENTS,
    XFS_DINODE_FMT_BTREE,
    MAX_RECOVERED_FILE_SIZE_MB,
)

logger = logging.getLogger(__name__)

MAX_RECOVER_BYTES = MAX_RECOVERED_FILE_SIZE_MB * 1024 * 1024

# XFS inode data fork formats
XFS_DINODE_FMT_LOCAL = 1    # Data stored in inode literal area
XFS_DINODE_FMT_EXTENTS = 2  # Extent list (bmbt records)
XFS_DINODE_FMT_BTREE = 3    # B-tree of extents


def xfs_timestamp_to_datetime(ts_raw: bytes) -> Optional[datetime]:
    """Convert an XFS timestamp (big-endian: 4-byte seconds + 4-byte nanoseconds) to datetime."""
    if len(ts_raw) < 8:
        return None
    t_sec = struct.unpack_from(">i", ts_raw, 0)[0]  # signed 32-bit seconds
    if t_sec == 0:
        return None
    try:
        return datetime.fromtimestamp(t_sec, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


@dataclass
class XFSSuperblock:
    """Parsed XFS superblock (Allocation Group 0 superblock)."""
    block_size: int
    total_blocks: int
    ag_count: int
    ag_blocks: int
    inode_size: int
    inopblock: int        # Inodes per block
    agblklog: int         # log2 of AG block count
    inopblog: int         # log2 of inodes per block


@dataclass
class DeletedXFSInodeRecord:
    """Represents a recovered deleted file entry from XFS."""
    inode_number: int
    ag_number: int
    file_type: str
    mode: int
    uid: int
    gid: int
    size_bytes: int
    link_count: int
    data_format: int
    atime: Optional[datetime]
    mtime: Optional[datetime]
    ctime: Optional[datetime]
    n_extents: int
    raw_inode: bytes = field(repr=False)
    recovery_confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "inode_number": self.inode_number,
            "ag_number": self.ag_number,
            "file_type": self.file_type,
            "mode": oct(self.mode),
            "uid": self.uid,
            "gid": self.gid,
            "size_bytes": self.size_bytes,
            "link_count": self.link_count,
            "data_format": self.data_format,
            "atime": self.atime.isoformat() if self.atime else "Unknown",
            "mtime": self.mtime.isoformat() if self.mtime else "Unknown",
            "ctime": self.ctime.isoformat() if self.ctime else "Unknown",
            "n_extents": self.n_extents,
            "recovery_confidence": self.recovery_confidence,
        }


class XFSRecoveryEngine:

    def __init__(self, reader, output_dir: str):
        self.reader = reader
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sb: Optional[XFSSuperblock] = None

    def _parse_superblock(self) -> bool:
        """Parse the XFS superblock (AG 0, block 0)."""
        try:
            data = self.reader.read_at(0, 512)
            magic = struct.unpack_from(">I", data, 0)[0]
            if magic != XFS_SUPERBLOCK_MAGIC:
                logger.error(f"XFS magic mismatch: {magic:#010x}")
                return False

            block_size = struct.unpack_from(">I", data, 4)[0]
            total_blocks = struct.unpack_from(">Q", data, 8)[0]
            ag_blocks = struct.unpack_from(">I", data, 84)[0]
            ag_count = struct.unpack_from(">I", data, 88)[0]
            inode_size = struct.unpack_from(">H", data, 104)[0]
            inopblog = struct.unpack_from(">B", data, 76)[0]
            agblklog = struct.unpack_from(">B", data, 75)[0]

            inopblock = 1 << inopblog

            self._sb = XFSSuperblock(
                block_size=block_size,
                total_blocks=total_blocks,
                ag_count=ag_count,
                ag_blocks=ag_blocks,
                inode_size=inode_size,
                inopblock=inopblock,
                agblklog=agblklog,
                inopblog=inopblog,
            )

            logger.info(
                f"XFS superblock parsed: "
                f"block_size={block_size}, "
                f"ag_count={ag_count}, "
                f"ag_blocks={ag_blocks}, "
                f"inode_size={inode_size}"
            )
            return True
        except Exception as e:
            logger.error(f"XFS superblock parse failed: {e}")
            return False

    def _ag_offset(self, ag_num: int) -> int:
        """Return the byte offset of an Allocation Group."""
        return ag_num * self._sb.ag_blocks * self._sb.block_size

    def _inode_byte_offset(self, inode_num: int) -> int:
        """Compute the absolute byte offset of an inode in the image."""
        sb = self._sb
        ag_num = inode_num >> (sb.agblklog + sb.inopblog)
        ag_block = (inode_num >> sb.inopblog) & ((1 << sb.agblklog) - 1)
        inode_idx = inode_num & (sb.inopblock - 1)
        return (
            self._ag_offset(ag_num)
            + ag_block * sb.block_size
            + inode_idx * sb.inode_size
        )

    def _scan_ag_for_inodes(self, ag_num: int) -> Iterator[DeletedXFSInodeRecord]:
        """Scan a single Allocation Group for deleted inodes by magic-byte scanning."""
        sb = self._sb
        ag_start = self._ag_offset(ag_num)
        ag_size = sb.ag_blocks * sb.block_size

        # Scan in inode-sized strides through the AG
        # Skip the first 4 blocks (superblock, AGF, AGI, AGFL headers)
        start_offset = 4 * sb.block_size
        pos = start_offset

        while pos + sb.inode_size <= ag_size:
            abs_offset = ag_start + pos
            if abs_offset >= self.reader.image_size:
                break

            try:
                raw = self.reader.read_at(abs_offset, sb.inode_size)
            except Exception:
                pos += sb.inode_size
                continue

            if len(raw) < 96:
                pos += sb.inode_size
                continue

            # Check inode magic
            magic = struct.unpack_from(">H", raw, 0)[0]
            if magic != XFS_INODE_MAGIC:
                pos += sb.inode_size
                continue

            record = self._parse_xfs_inode(raw, ag_num, abs_offset)
            if record:
                yield record

            pos += sb.inode_size

    def _parse_xfs_inode(
        self, raw: bytes, ag_num: int, abs_offset: int
    ) -> Optional[DeletedXFSInodeRecord]:
        """Parse an XFS inode and return a record if it appears deleted."""
        try:
            sb = self._sb
            mode = struct.unpack_from(">H", raw, 2)[0]
            di_version = raw[4]
            di_format = raw[5]
            uid = struct.unpack_from(">I", raw, 8)[0]
            gid = struct.unpack_from(">I", raw, 12)[0]
            nlink = struct.unpack_from(">I" if di_version >= 2 else ">H", raw, 16)[0]
            size_bytes = struct.unpack_from(">q", raw, 0x38)[0]  # signed 64-bit
            n_extents = struct.unpack_from(">I", raw, 0x4C)[0]

            atime = xfs_timestamp_to_datetime(raw[0x20:0x28])
            mtime = xfs_timestamp_to_datetime(raw[0x28:0x30])
            ctime = xfs_timestamp_to_datetime(raw[0x30:0x38])

            # Deleted condition: nlink == 0 and file has some record of size
            if nlink != 0:
                return None
            if mode == 0:
                return None

            mode_type = mode & 0xF000
            if mode_type == 0x8000:
                file_type = "regular"
            elif mode_type == 0x4000:
                file_type = "directory"
            elif mode_type == 0xA000:
                file_type = "symlink"
            else:
                file_type = "unknown"

            # Reconstruct approximate inode number from offset
            ag_relative_offset = abs_offset - self._ag_offset(ag_num)
            ag_block = ag_relative_offset // sb.block_size
            inode_idx = (ag_relative_offset % sb.block_size) // sb.inode_size
            inode_num = (ag_num << (sb.agblklog + sb.inopblog)) | (ag_block << sb.inopblog) | inode_idx

            confidence = "medium"
            if size_bytes > 0 and di_format in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_LOCAL):
                confidence = "high"
            elif size_bytes == 0:
                confidence = "low"

            return DeletedXFSInodeRecord(
                inode_number=inode_num,
                ag_number=ag_num,
                file_type=file_type,
                mode=mode,
                uid=uid,
                gid=gid,
                size_bytes=max(0, size_bytes),
                link_count=nlink,
                data_format=di_format,
                atime=atime,
                mtime=mtime,
                ctime=ctime,
                n_extents=n_extents,
                raw_inode=raw,
                recovery_confidence=confidence,
            )
        except Exception as e:
            logger.debug(f"XFS inode parse error: {e}")
            return None

    def iter_deleted_inodes(self) -> Iterator[DeletedXFSInodeRecord]:
        """Iterate over all deleted XFS inodes across all AGs."""
        if not self._parse_superblock():
            return
        for ag_num in range(self._sb.ag_count):
            logger.debug(f"Scanning XFS AG {ag_num}...")
            yield from self._scan_ag_for_inodes(ag_num)

    def _recover_inode(self, record: DeletedXFSInodeRecord) -> "XFSRecoveryResult":
        """Attempt to recover file data for a deleted XFS inode."""
        try:
            sb = self._sb
            if record.data_format == XFS_DINODE_FMT_LOCAL:
                # Data stored inline in the inode's data fork
                fork_offset = 96  # Inode core is 96 bytes
                inline_data = record.raw_inode[fork_offset: fork_offset + record.size_bytes]
                data = inline_data
            elif record.data_format == XFS_DINODE_FMT_EXTENTS:
                data = self._read_extents(record)
            else:
                return XFSRecoveryResult(
                    record=record, recovered=False,
                    reason=f"Unsupported data format: {record.data_format}"
                )

            if not data:
                return XFSRecoveryResult(
                    record=record, recovered=False,
                    reason="No data recovered (blocks possibly overwritten)"
                )

            data = data[:record.size_bytes]
            out_name = f"xfs_inode_{record.inode_number}_recovered"
            out_path = self.output_dir / "xfs" / out_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
            sha256 = HashVerifier.hash_bytes(data)

            logger.info(f"XFS recovered inode {record.inode_number}: {len(data)} bytes")
            return XFSRecoveryResult(
                record=record, recovered=True,
                output_path=out_path,
                recovered_size=len(data),
                sha256=sha256,
                reason="Recovered via XFS extent list"
            )
        except Exception as e:
            return XFSRecoveryResult(
                record=record, recovered=False,
                reason=f"XFS recovery exception: {e}"
            )

    def _read_extents(self, record: DeletedXFSInodeRecord) -> bytes:
        """Read file data from XFS inline extents stored in the inode's data fork."""
        sb = self._sb
        fork_offset = 96  # Inode core ends at byte 96
        result = bytearray()
        n_extents = min(record.n_extents, 4)  # Read up to 4 inline extents

        for i in range(n_extents):
            ext_offset = fork_offset + i * 16
            if ext_offset + 16 > len(record.raw_inode):
                break

            ext = record.raw_inode[ext_offset:ext_offset + 16]
            # Unpack the 128-bit extent record
            # High 64 bits: [l0], Low 64 bits: [l1]
            l0 = struct.unpack_from(">Q", ext, 0)[0]
            l1 = struct.unpack_from(">Q", ext, 8)[0]

            # startblock is at bits [88:37] = bits 88 down to bit 37 (52 bits)
            # Simplified: extract physical block from bit field
            startblock = ((l0 & 0x0000_001F_FFFF_FFFF) << 17) | (l1 >> 47)
            blockcount = l1 & 0x001F_FFFF  # 21 bits

            if startblock == 0 or blockcount == 0:
                continue

            bytes_to_read = min(
                blockcount * sb.block_size,
                record.size_bytes - len(result)
            )
            if bytes_to_read <= 0:
                break

            try:
                chunk = self.reader.read_at(startblock * sb.block_size, bytes_to_read)
                result.extend(chunk)
            except Exception as e:
                logger.debug(f"XFS extent read error at block {startblock}: {e}")
                break

        return bytes(result)

    def recover_all(self) -> List["XFSRecoveryResult"]:
        """Scan XFS and recover all deleted files."""
        results = []
        deleted = list(self.iter_deleted_inodes())
        logger.info(f"XFS: attempting recovery of {len(deleted)} deleted inodes...")

        for record in deleted:
            if record.file_type != "regular" or record.size_bytes == 0:
                result = XFSRecoveryResult(
                    record=record, recovered=False,
                    reason="Non-regular or zero-size inode"
                )
            elif record.size_bytes > MAX_RECOVER_BYTES:
                result = XFSRecoveryResult(
                    record=record, recovered=False,
                    reason=f"File too large: {record.size_bytes} bytes"
                )
            else:
                result = self._recover_inode(record)
            results.append(result)

        recovered = sum(1 for r in results if r.recovered)
        logger.info(f"XFS Recovery complete: {recovered}/{len(results)} files recovered.")
        return results


class XFSRecoveryResult:
    """Result of a single XFS inode recovery attempt."""
    __slots__ = ["record", "recovered", "output_path", "recovered_size", "sha256", "reason"]

    def __init__(
        self,
        record: DeletedXFSInodeRecord,
        recovered: bool,
        output_path: Optional[Path] = None,
        recovered_size: int = 0,
        sha256: str = "",
        reason: str = "",
    ):
        self.record = record
        self.recovered = recovered
        self.output_path = output_path
        self.recovered_size = recovered_size
        self.sha256 = sha256
        self.reason = reason

    def to_dict(self) -> dict:
        d = self.record.to_dict()
        d.update({
            "recovered": self.recovered,
            "output_path": str(self.output_path) if self.output_path else None,
            "recovered_size_bytes": self.recovered_size,
            "recovered_sha256": self.sha256,
            "recovery_reason": self.reason,
        })
        return d
