import struct
import logging
from pathlib import Path
from typing import List, Optional

from core.inode_parser import InodeParser, DeletedInodeRecord
from core.hash_verifier import HashVerifier
from config.settings import (
    MAX_RECOVERED_FILE_SIZE_MB,
    EXT4_BLOCK_SIZE,
)

logger = logging.getLogger(__name__)

EXT4_EXTENT_MAGIC = 0xF30A
MAX_RECOVER_BYTES = MAX_RECOVERED_FILE_SIZE_MB * 1024 * 1024


class EXT4RecoveryResult:
    """Result of a single EXT4 inode recovery attempt."""
    __slots__ = ["record", "recovered", "output_path", "recovered_size", "sha256", "reason"]

    def __init__(
        self,
        record: DeletedInodeRecord,
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


class EXT4RecoveryEngine:

    def __init__(self, reader, output_dir: str):
        self.reader = reader
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.inode_parser = InodeParser(reader)
        self.inode_parser._parse_superblock()
        self._block_size = (
            self.inode_parser._superblock.block_size
            if self.inode_parser._superblock else EXT4_BLOCK_SIZE
        )

    def recover_all(self) -> List[EXT4RecoveryResult]:
        """Scan inodes and attempt recovery of all deleted regular files."""
        results = []
        deleted = self.inode_parser.get_all_deleted_inodes()
        logger.info(f"Attempting EXT4 recovery of {len(deleted)} deleted inodes...")

        for record in deleted:
            if not record.is_regular_file:
                result = EXT4RecoveryResult(
                    record=record, recovered=False,
                    reason="Non-regular inode (directory/symlink)"
                )
            elif record.size_bytes == 0:
                result = EXT4RecoveryResult(
                    record=record, recovered=False, reason="Zero-size file"
                )
            elif record.size_bytes > MAX_RECOVER_BYTES:
                result = EXT4RecoveryResult(
                    record=record, recovered=False,
                    reason=f"File too large: {record.size_bytes} bytes"
                )
            else:
                result = self._recover_inode(record)
            results.append(result)

        recovered = sum(1 for r in results if r.recovered)
        logger.info(f"EXT4 Recovery complete: {recovered}/{len(results)} files recovered.")
        return results

    def _recover_inode(self, record: DeletedInodeRecord) -> EXT4RecoveryResult:
        try:
            if record.uses_extents:
                data = self._read_via_extents(record)
            else:
                data = self._read_via_block_pointers(record)

            if not data:
                return EXT4RecoveryResult(
                    record=record, recovered=False,
                    reason="No data recovered from blocks (possibly overwritten)"
                )

            # Trim to actual file size
            data = data[:record.size_bytes]

            out_name = f"inode_{record.inode_number}_recovered"
            out_path = self.output_dir / "ext4" / out_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)

            sha256 = HashVerifier.hash_bytes(data)
            logger.info(
                f"EXT4 recovered inode {record.inode_number}: "
                f"{len(data)} bytes → {out_path.name}"
            )
            return EXT4RecoveryResult(
                record=record, recovered=True,
                output_path=out_path,
                recovered_size=len(data),
                sha256=sha256,
                reason="Recovered via extent tree" if record.uses_extents else "Recovered via block pointers",
            )
        except Exception as e:
            return EXT4RecoveryResult(
                record=record, recovered=False,
                reason=f"Recovery exception: {e}"
            )

    def _read_via_extents(self, record: DeletedInodeRecord) -> bytes:
        """Read file data using the EXT4 extent tree stored in i_block."""
        block_data = record.block_pointers
        if len(block_data) < 12:
            return b""

        # Parse extent header
        eh_magic = struct.unpack_from("<H", block_data, 0)[0]
        if eh_magic != EXT4_EXTENT_MAGIC:
            logger.debug(f"Inode {record.inode_number}: bad extent magic {eh_magic:#06x}")
            return b""

        eh_entries = struct.unpack_from("<H", block_data, 2)[0]
        eh_depth = struct.unpack_from("<H", block_data, 6)[0]

        if eh_depth != 0:
            logger.debug(
                f"Inode {record.inode_number}: extent depth {eh_depth} — "
                "multi-level extent trees not fully supported; reading first extents"
            )

        result = bytearray()
        for i in range(min(eh_entries, 4)):  # Up to 4 inline extents
            entry_offset = 12 + i * 12
            if entry_offset + 12 > len(block_data):
                break

            ee_len = struct.unpack_from("<H", block_data, entry_offset + 4)[0]
            # Bit 15 of ee_len: 0=initialized, 1=unwritten (pre-allocated)
            initialized = not (ee_len & 0x8000)
            ee_len = ee_len & 0x7FFF  # actual block count

            ee_start_hi = struct.unpack_from("<H", block_data, entry_offset + 6)[0]
            ee_start_lo = struct.unpack_from("<I", block_data, entry_offset + 8)[0]
            physical_block = (ee_start_hi << 32) | ee_start_lo

            bytes_to_read = min(
                ee_len * self._block_size,
                record.size_bytes - len(result)
            )
            if bytes_to_read <= 0:
                break

            try:
                chunk = self.reader.read_at(physical_block * self._block_size, bytes_to_read)
                result.extend(chunk)
            except Exception as e:
                logger.debug(f"Extent read failed at block {physical_block}: {e}")
                break

        return bytes(result)

    def _read_via_block_pointers(self, record: DeletedInodeRecord) -> bytes:
        """Read file data via direct and single-indirect block pointers."""
        block_data = record.block_pointers
        result = bytearray()
        remaining = record.size_bytes

        # 12 direct pointers
        for i in range(12):
            if remaining <= 0:
                break
            block_ptr = struct.unpack_from("<I", block_data, i * 4)[0]
            if block_ptr == 0:
                continue
            to_read = min(self._block_size, remaining)
            try:
                chunk = self.reader.read_at(block_ptr * self._block_size, to_read)
                result.extend(chunk)
                remaining -= len(chunk)
            except Exception as e:
                logger.debug(f"Direct block {block_ptr} read error: {e}")
                break

        # Single indirect pointer
        if remaining > 0:
            indirect_ptr = struct.unpack_from("<I", block_data, 12 * 4)[0]
            if indirect_ptr != 0:
                try:
                    ptr_block = self.reader.read_at(
                        indirect_ptr * self._block_size, self._block_size
                    )
                    ptrs_per_block = self._block_size // 4
                    for j in range(ptrs_per_block):
                        if remaining <= 0:
                            break
                        block_ptr = struct.unpack_from("<I", ptr_block, j * 4)[0]
                        if block_ptr == 0:
                            continue
                        to_read = min(self._block_size, remaining)
                        chunk = self.reader.read_at(block_ptr * self._block_size, to_read)
                        result.extend(chunk)
                        remaining -= len(chunk)
                except Exception as e:
                    logger.debug(f"Indirect block read error: {e}")

        return bytes(result)
