"""
core/ntfs_recovery.py — NTFS deleted file recovery engine (fixed)
"""
import struct
import logging
from pathlib import Path
from typing import List, Optional

from core.mft_parser import MFTParser, DeletedFileRecord
from core.hash_verifier import HashVerifier
from config.settings import (
    NTFS_MFT_ENTRY_SIZE,
    NTFS_ATTR_DATA,
    NTFS_ATTR_END,
    MAX_RECOVERED_FILE_SIZE_MB,
)

logger = logging.getLogger(__name__)
MAX_RECOVER_BYTES = MAX_RECOVERED_FILE_SIZE_MB * 1024 * 1024


class RecoveryResult:
    """Result of a single file recovery attempt."""

    def __init__(self, record, recovered: bool, output_path=None,
                 recovered_size: int = 0, sha256: str = "", reason: str = ""):
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


class NTFSRecoveryEngine:
    """
    Recovers deleted files from an NTFS forensic image.

    Scans MFT for deleted records, then attempts to recover:
    - Resident files: data stored directly in MFT record
    - Non-resident files: data stored in clusters referenced by data runs
    """

    def __init__(self, reader, output_dir: str):
        self.reader = reader
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mft_parser = MFTParser(reader)
        self.mft_parser._parse_boot_sector()
        self._cluster_size = self.mft_parser._cluster_size
        self._mft_offset = self.mft_parser._mft_offset

    def recover_all(self, max_records: int = 100_000) -> List[RecoveryResult]:
        """Scan the MFT and attempt to recover all deleted files."""
        results = []
        deleted = self.mft_parser.get_all_deleted_files(max_records)
        logger.info(f"NTFS: attempting recovery of {len(deleted)} deleted records...")

        for record in deleted:
            if record.is_directory:
                result = RecoveryResult(record=record, recovered=False,
                                        reason="Directory — no content to recover")
            else:
                result = self._recover_file(record)
            results.append(result)

        recovered = sum(1 for r in results if r.recovered)
        logger.info(f"NTFS Recovery complete: {recovered}/{len(results)} files recovered.")
        return results

    def _recover_file(self, record: DeletedFileRecord) -> RecoveryResult:
        """Attempt to recover a single deleted file."""
        raw = record.raw_record
        offset_to_attrs = struct.unpack_from("<H", raw, 0x14)[0]
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
                if attr_type == NTFS_ATTR_DATA:
                    if not non_resident:
                        return self._recover_resident(record, raw, attr_offset)
                    else:
                        return self._recover_non_resident(record, raw, attr_offset)
                attr_offset += attr_len
            except (struct.error, IndexError):
                break

        return RecoveryResult(record=record, recovered=False,
                              reason="No $DATA attribute found in MFT record")

    def _recover_resident(self, record, raw, attr_offset) -> RecoveryResult:
        try:
            content_offset = struct.unpack_from("<H", raw, attr_offset + 20)[0]
            content_size = struct.unpack_from("<I", raw, attr_offset + 16)[0]
            content = raw[attr_offset + content_offset: attr_offset + content_offset + content_size]
            safe_name = self._safe_filename(record.filename, record.mft_record_number)
            out_path = self.output_dir / "ntfs" / safe_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(content)
            sha256 = HashVerifier.hash_bytes(content)
            return RecoveryResult(record=record, recovered=True, output_path=out_path,
                                  recovered_size=len(content), sha256=sha256,
                                  reason="Resident $DATA attribute recovered")
        except Exception as e:
            return RecoveryResult(record=record, recovered=False,
                                  reason=f"Resident recovery failed: {e}")

    def _recover_non_resident(self, record, raw, attr_offset) -> RecoveryResult:
        try:
            run_list_offset = struct.unpack_from("<H", raw, attr_offset + 0x20)[0]
            actual_size = struct.unpack_from("<Q", raw, attr_offset + 0x38)[0]
            if actual_size == 0 or actual_size > MAX_RECOVER_BYTES:
                return RecoveryResult(record=record, recovered=False,
                                      reason=f"Invalid size: {actual_size}")
            run_list_start = attr_offset + run_list_offset
            data = self._read_data_runs(raw, run_list_start, actual_size)
            if not data:
                return RecoveryResult(record=record, recovered=False,
                                      reason="Data runs empty (clusters possibly overwritten)")
            safe_name = self._safe_filename(record.filename, record.mft_record_number)
            out_path = self.output_dir / "ntfs" / safe_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
            sha256 = HashVerifier.hash_bytes(data)
            return RecoveryResult(record=record, recovered=True, output_path=out_path,
                                  recovered_size=len(data), sha256=sha256,
                                  reason="Non-resident $DATA recovered via run list")
        except Exception as e:
            return RecoveryResult(record=record, recovered=False,
                                  reason=f"Non-resident recovery failed: {e}")

    def _read_data_runs(self, raw: bytes, run_offset: int, max_size: int) -> bytes:
        result = bytearray()
        current_lcn = 0
        pos = run_offset
        while pos < len(raw):
            header = raw[pos]
            if header == 0x00:
                break
            len_bytes = header & 0x0F
            off_bytes = (header >> 4) & 0x0F
            pos += 1
            if len_bytes == 0:
                break
            run_len = int.from_bytes(raw[pos:pos + len_bytes], "little", signed=False)
            pos += len_bytes
            if off_bytes > 0:
                run_off = int.from_bytes(raw[pos:pos + off_bytes], "little", signed=True)
                pos += off_bytes
                current_lcn += run_off
            else:
                result.extend(b"\x00" * run_len * self._cluster_size)
                continue
            bytes_to_read = min(run_len * self._cluster_size, max_size - len(result))
            if bytes_to_read <= 0:
                break
            try:
                chunk = self.reader.read_at(current_lcn * self._cluster_size, bytes_to_read)
                result.extend(chunk)
            except Exception as e:
                logger.debug(f"Run read error at LCN {current_lcn}: {e}")
                break
            if len(result) >= max_size:
                break
        return bytes(result[:max_size])

    @staticmethod
    def _safe_filename(name: str, record_num: int) -> str:
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        safe = "".join(c if c in safe_chars else "_" for c in name)
        if not safe or safe.startswith("."):
            safe = f"recovered_{record_num}"
        return safe
