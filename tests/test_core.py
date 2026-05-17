import pytest
import struct
import tempfile
import os
from pathlib import Path

# ── Helpers to create minimal test images in-memory ──────────────────────────

def make_ntfs_image(tmp_path: Path) -> Path:
    """Create a 2 MB NTFS test image with one deleted record."""
    SIZE = 2 * 1024 * 1024
    data = bytearray(SIZE)
    # Boot sector
    data[3:11] = b"NTFS    "
    struct.pack_into("<H", data, 11, 512)   # bytes/sector
    data[13] = 8                             # sectors/cluster (cluster=4096)
    struct.pack_into("<Q", data, 48, 4)     # MFT LCN = 4 → offset 4*4096=16384
    data[510], data[511] = 0x55, 0xAA

    # One DELETED MFT record at record 0 of MFT (offset 16384)
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x14, 56)   # offset to attrs
    struct.pack_into("<H", rec, 0x16, 0x00) # flags = NOT in-use → deleted

    # $STANDARD_INFORMATION (type 0x10)
    si = 56
    struct.pack_into("<I", rec, si, 0x10)
    struct.pack_into("<I", rec, si + 4, 96)
    rec[si + 8] = 0
    struct.pack_into("<H", rec, si + 20, 24)
    struct.pack_into("<I", rec, si + 16, 48)
    ts = 133495674000000000
    for i in range(4):
        struct.pack_into("<Q", rec, si + 24 + i * 8, ts)

    # $FILE_NAME (type 0x30)
    fn = si + 96
    filename = "test_file.txt"
    fn_bytes = filename.encode("utf-16-le")
    content_size = 66 + len(fn_bytes)
    struct.pack_into("<I", rec, fn, 0x30)
    struct.pack_into("<I", rec, fn + 4, 24 + content_size)
    rec[fn + 8] = 0
    struct.pack_into("<H", rec, fn + 20, 24)
    struct.pack_into("<I", rec, fn + 16, content_size)
    struct.pack_into("<Q", rec, fn + 24, 5)
    for i in range(4):
        struct.pack_into("<Q", rec, fn + 24 + 8 + i * 8, ts)
    struct.pack_into("<Q", rec, fn + 24 + 40, 256)
    rec[fn + 24 + 64] = len(filename)
    rec[fn + 24 + 65] = 1
    rec[fn + 24 + 66: fn + 24 + 66 + len(fn_bytes)] = fn_bytes

    # End sentinel
    end = fn + 24 + content_size
    end = (end + 7) & ~7
    struct.pack_into("<I", rec, end, 0xFFFFFFFF)

    data[16384:16384 + 1024] = rec
    p = tmp_path / "test_ntfs.dd"
    p.write_bytes(bytes(data))
    return p


def make_ext4_image(tmp_path: Path) -> Path:
    """Create a 2 MB EXT4 test image with one deleted inode."""
    SIZE = 2 * 1024 * 1024
    data = bytearray(SIZE)
    sb = 1024
    struct.pack_into("<I", data, sb + 0, 512)
    struct.pack_into("<I", data, sb + 4, 512)
    struct.pack_into("<I", data, sb + 20, 0)
    struct.pack_into("<I", data, sb + 24, 2)    # block size = 4096
    struct.pack_into("<I", data, sb + 32, 32768)
    struct.pack_into("<I", data, sb + 40, 128)
    struct.pack_into("<H", data, sb + 56, 0xEF53)
    struct.pack_into("<H", data, sb + 88, 256)

    # Group descriptor → inode table at block 4 (byte 16384)
    gd = 4096
    struct.pack_into("<I", data, gd + 8, 4)

    # Deleted inode at index 12 (inode 13, 1-indexed)
    ino = 16384 + 12 * 256
    struct.pack_into("<H", data, ino + 0, 0x81A4)  # regular file
    struct.pack_into("<I", data, ino + 4, 100)      # size = 100 bytes
    struct.pack_into("<I", data, ino + 20, 1705315800)  # dtime (non-zero = deleted)
    struct.pack_into("<H", data, ino + 26, 0)       # link_count = 0

    p = tmp_path / "test_ext4.dd"
    p.write_bytes(bytes(data))
    return p


def make_xfs_image(tmp_path: Path) -> Path:
    """Create a 2 MB XFS test image."""
    SIZE = 2 * 1024 * 1024
    data = bytearray(SIZE)
    struct.pack_into(">I", data, 0, 0x58465342)
    struct.pack_into(">I", data, 4, 4096)
    struct.pack_into(">Q", data, 8, 512)
    struct.pack_into(">I", data, 84, 256)
    struct.pack_into(">I", data, 88, 1)
    struct.pack_into(">H", data, 104, 512)
    data[75] = 8
    data[76] = 3
    p = tmp_path / "test_xfs.dd"
    p.write_bytes(bytes(data))
    return p


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestForensicImageReader:
    """Tests for image_reader.ForensicImageReader"""

    def test_open_raw_image(self, tmp_path):
        img = tmp_path / "test.dd"
        img.write_bytes(b"\x00" * 1024)
        from core.image_reader import ForensicImageReader
        reader = ForensicImageReader(str(img))
        reader.open()
        assert reader._is_open
        assert reader.image_size == 1024
        assert reader.image_format == "raw"
        reader.close()

    def test_read_at(self, tmp_path):
        img = tmp_path / "test.dd"
        img.write_bytes(b"HELLO" + b"\x00" * 1019)
        from core.image_reader import ForensicImageReader
        with ForensicImageReader(str(img)) as r:
            assert r.read_at(0, 5) == b"HELLO"

    def test_context_manager(self, tmp_path):
        img = tmp_path / "test.dd"
        img.write_bytes(b"\x00" * 512)
        from core.image_reader import ForensicImageReader
        with ForensicImageReader(str(img)) as r:
            assert r._is_open
        assert not r._is_open

    def test_unsupported_format_raises(self, tmp_path):
        img = tmp_path / "test.iso"
        img.write_bytes(b"\x00" * 512)
        from core.image_reader import ForensicImageReader, ForensicImageError
        with pytest.raises(ForensicImageError, match="Unsupported"):
            ForensicImageReader(str(img))

    def test_missing_file_raises(self, tmp_path):
        from core.image_reader import ForensicImageReader, ForensicImageError
        with pytest.raises(ForensicImageError, match="not found"):
            ForensicImageReader(str(tmp_path / "nonexistent.dd"))

    def test_integrity_hash(self, tmp_path):
        img = tmp_path / "test.dd"
        img.write_bytes(b"A" * 4096)
        from core.image_reader import ForensicImageReader
        with ForensicImageReader(str(img)) as r:
            ok, h1, h2 = r.verify_integrity()
            assert ok
            assert h1 == h2


class TestHashVerifier:
    """Tests for hash_verifier.HashVerifier"""

    def test_hash_bytes_sha256(self):
        from core.hash_verifier import HashVerifier
        h = HashVerifier.hash_bytes(b"hello", "sha256")
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_bytes_md5(self):
        from core.hash_verifier import HashVerifier
        h = HashVerifier.hash_bytes(b"hello", "md5")
        assert h == "5d41402abc4b2a76b9719d911017c592"

    def test_hash_file(self, tmp_path):
        from core.hash_verifier import HashVerifier
        f = tmp_path / "test.bin"
        f.write_bytes(b"forensic data")
        h1 = HashVerifier.hash_file(str(f))
        h2 = HashVerifier.hash_bytes(b"forensic data")
        assert h1 == h2

    def test_verify_file_pass(self, tmp_path):
        from core.hash_verifier import HashVerifier
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        expected = HashVerifier.hash_file(str(f))
        assert HashVerifier.verify_file(str(f), expected)

    def test_verify_file_fail(self, tmp_path):
        from core.hash_verifier import HashVerifier
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        assert not HashVerifier.verify_file(str(f), "wrong_hash")

    def test_unsupported_algorithm_raises(self):
        from core.hash_verifier import HashVerifier
        with pytest.raises(ValueError):
            HashVerifier.hash_bytes(b"data", "sha512")

    def test_hash_all(self, tmp_path):
        from core.hash_verifier import HashVerifier
        f = tmp_path / "t.bin"
        f.write_bytes(b"test")
        result = HashVerifier.hash_file_all(str(f))
        assert "sha256" in result and "md5" in result and "sha1" in result


class TestNTFSDetection:
    """Tests for NTFS filesystem detection"""

    def test_detects_ntfs(self, tmp_path):
        from core.image_reader import ForensicImageReader, detect_filesystem_type
        img = tmp_path / "ntfs.dd"
        data = bytearray(4096)
        data[3:11] = b"NTFS    "
        img.write_bytes(bytes(data))
        with ForensicImageReader(str(img)) as r:
            assert detect_filesystem_type(r) == "ntfs"

    def test_detects_ext4(self, tmp_path):
        from core.image_reader import ForensicImageReader, detect_filesystem_type
        img = tmp_path / "ext4.dd"
        data = bytearray(4096)
        struct.pack_into("<H", data, 1024 + 56, 0xEF53)
        img.write_bytes(bytes(data))
        with ForensicImageReader(str(img)) as r:
            assert detect_filesystem_type(r) == "ext4"

    def test_detects_xfs(self, tmp_path):
        from core.image_reader import ForensicImageReader, detect_filesystem_type
        img = tmp_path / "xfs.dd"
        data = bytearray(4096)
        struct.pack_into(">I", data, 0, 0x58465342)
        img.write_bytes(bytes(data))
        with ForensicImageReader(str(img)) as r:
            assert detect_filesystem_type(r) == "xfs"

    def test_unknown_returns_unknown(self, tmp_path):
        from core.image_reader import ForensicImageReader, detect_filesystem_type
        img = tmp_path / "unknown.dd"
        img.write_bytes(b"\x00" * 4096)
        with ForensicImageReader(str(img)) as r:
            assert detect_filesystem_type(r) == "unknown"


class TestMFTParser:
    """Tests for mft_parser.MFTParser"""

    def test_finds_deleted_record(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.mft_parser import MFTParser
        img = make_ntfs_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = MFTParser(r)
            records = parser.get_all_deleted_files(max_records=200)
        assert len(records) >= 1
        assert records[0].filename == "test_file.txt"
        assert records[0].size_bytes == 256

    def test_deleted_flag_not_in_use(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.mft_parser import MFTParser
        img = make_ntfs_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = MFTParser(r)
            records = parser.get_all_deleted_files(max_records=200)
        for rec in records:
            assert not (rec.flags & 0x0001), "Deleted record should not have in-use flag"


class TestInodeParser:
    """Tests for inode_parser.InodeParser"""

    def test_finds_deleted_inode(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.inode_parser import InodeParser
        img = make_ext4_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = InodeParser(r)
            inodes = parser.get_all_deleted_inodes()
        assert len(inodes) >= 1
        assert inodes[0].link_count == 0
        assert inodes[0].deletion_time is not None

    def test_superblock_parse(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.inode_parser import InodeParser
        img = make_ext4_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = InodeParser(r)
            ok = parser._parse_superblock()
        assert ok
        assert parser._superblock.block_size == 4096


class TestMetadataExtractor:
    """Tests for metadata_extractor.MetadataExtractor"""

    def test_from_ntfs_record(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.mft_parser import MFTParser
        from core.metadata_extractor import MetadataExtractor
        img = make_ntfs_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = MFTParser(r)
            records = parser.get_all_deleted_files(max_records=200)
        if records:
            meta = MetadataExtractor.from_ntfs_record(records[0])
            assert meta.filesystem_type == "ntfs"
            assert meta.filename == "test_file.txt"

    def test_from_ext4_inode(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.inode_parser import InodeParser
        from core.metadata_extractor import MetadataExtractor
        img = make_ext4_image(tmp_path)
        with ForensicImageReader(str(img)) as r:
            parser = InodeParser(r)
            inodes = parser.get_all_deleted_inodes()
        if inodes:
            meta = MetadataExtractor.from_ext4_inode(inodes[0])
            assert meta.filesystem_type == "ext4"
            assert meta.deleted_time is not None


class TestFileIdentification:
    """Tests for magic byte file type identification"""

    def test_png_detection(self):
        from core.metadata_extractor import identify_file_type
        result = identify_file_type(b"\x89PNG\r\n\x1a\n" + b"\x00" * 24)
        assert result["mime_type"] == "image/png"
        assert result["extension"] == "png"

    def test_pdf_detection(self):
        from core.metadata_extractor import identify_file_type
        result = identify_file_type(b"%PDF-1.7\n" + b"\x00" * 20)
        assert result["mime_type"] == "application/pdf"

    def test_exe_detection(self):
        from core.metadata_extractor import identify_file_type
        result = identify_file_type(b"MZ" + b"\x00" * 30)
        assert result["extension"] == "exe"

    def test_text_heuristic(self):
        from core.metadata_extractor import identify_file_type
        result = identify_file_type(b"This is plain text content\n" * 3)
        assert result["mime_type"] == "text/plain"

    def test_empty_data(self):
        from core.metadata_extractor import identify_file_type
        result = identify_file_type(b"")
        assert result["mime_type"] == "application/octet-stream"


class TestValidator:
    """Tests for validator.ArtifactValidator"""

    def _make_meta(self, **kwargs):
        from core.metadata_extractor import ForensicMetadata
        defaults = dict(
            filesystem_type="ntfs", identifier="42", filename="test.txt",
            size_bytes=1024, is_directory=False, uid=None, gid=None, mode=None,
            created=None, modified=None, accessed=None, metadata_changed=None,
            deleted_time=None, recovery_confidence="high",
        )
        defaults.update(kwargs)
        return ForensicMetadata(**defaults)

    def test_valid_artifact_passes(self):
        from core.validator import ArtifactValidator
        meta = self._make_meta()
        v = ArtifactValidator()
        result = v.validate(meta)
        assert result.is_viable
        assert result.confidence_score >= 0.8

    def test_negative_size_anomaly(self):
        from core.validator import ArtifactValidator
        meta = self._make_meta(size_bytes=-1)
        v = ArtifactValidator()
        result = v.validate(meta)
        assert len(result.anomalies) > 0

    def test_magic_mismatch_detected(self):
        from core.validator import ArtifactValidator
        meta = self._make_meta(filename="document.pdf")
        v = ArtifactValidator()
        # PNG data in a .pdf file — magic mismatch
        result = v.validate(meta, recovered_data=b"\x89PNG\r\n\x1a\n" + b"\x00" * 30)
        assert not result.magic_matches_extension

    def test_batch_validation(self):
        from core.validator import ArtifactValidator
        v = ArtifactValidator()
        metas = [self._make_meta(identifier=str(i)) for i in range(5)]
        results = v.validate_batch(metas)
        assert len(results) == 5
        summary = v.generate_summary(results)
        assert summary["total_artifacts"] == 5


class TestEvidenceHandler:
    """Tests for evidence_handler.EvidenceHandler"""

    def test_register_evidence(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.evidence_handler import EvidenceHandler
        img = tmp_path / "t.dd"
        img.write_bytes(b"A" * 4096)
        handler = EvidenceHandler("TEST-001", "Tester")
        with ForensicImageReader(str(img)) as r:
            record = handler.register_evidence(r)
        assert record.case_id == "TEST-001"
        assert record.sha256_hash != ""
        assert len(record.custody_log) >= 1

    def test_log_action(self, tmp_path):
        from core.image_reader import ForensicImageReader
        from core.evidence_handler import EvidenceHandler
        img = tmp_path / "t.dd"
        img.write_bytes(b"\x00" * 2048)
        handler = EvidenceHandler("CASE-X", "Examiner")
        with ForensicImageReader(str(img)) as r:
            handler.register_evidence(r)
        handler.log_action("Test Action", "Testing custody log")
        assert any("Test Action" in e.action for e in handler.record.custody_log)

    def test_save_custody_log(self, tmp_path):
        import json
        from core.image_reader import ForensicImageReader
        from core.evidence_handler import EvidenceHandler
        img = tmp_path / "t.dd"
        img.write_bytes(b"\x00" * 1024)
        handler = EvidenceHandler("CASE-Y", "Examiner")
        with ForensicImageReader(str(img)) as r:
            handler.register_evidence(r)
        log_path = handler.save_custody_log(tmp_path)
        assert log_path.exists()
        content = json.loads(log_path.read_text())
        assert content["case_id"] == "CASE-Y"
