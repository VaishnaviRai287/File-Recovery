import struct
import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple

from config.settings import (
    HASH_CHUNK_SIZE,
    DEFAULT_HASH_ALGORITHM,
    SUPPORTED_IMAGE_FORMATS,
    NTFS_SECTOR_SIZE,
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_MAGIC,
    XFS_SUPERBLOCK_MAGIC,
    FS_TYPE_NTFS, FS_TYPE_EXT4, FS_TYPE_XFS, FS_TYPE_UNKNOWN,
)

logger = logging.getLogger(__name__)


class ForensicImageError(Exception):
    """Raised when a forensic image cannot be opened or read safely."""
    pass


class ForensicImageReader:
    """Read-only forensic evidence image reader (raw DD/IMG, E01)."""

    def __init__(self, image_path: str, sector_size: int = NTFS_SECTOR_SIZE):
        self.image_path = Path(image_path).resolve()
        self.sector_size = sector_size
        self._handle = None
        self._ewf_handle = None
        self.image_format: str = "unknown"
        self.image_size: int = 0
        self.opening_hash: Optional[str] = None
        self._is_open: bool = False
        self._validate_image_path()

    def _validate_image_path(self) -> None:
        if not self.image_path.exists():
            raise ForensicImageError(f"Evidence image not found: {self.image_path}")
        suffix = self.image_path.suffix.lower()
        if suffix not in SUPPORTED_IMAGE_FORMATS:
            raise ForensicImageError(
                f"Unsupported image format: '{suffix}'. "
                f"Supported: {', '.join(SUPPORTED_IMAGE_FORMATS)}"
            )
        logger.info(f"Image path validated: {self.image_path}")

    def open(self) -> "ForensicImageReader":
        """Open the forensic image in read-only mode."""
        try:
            suffix = self.image_path.suffix.lower()
            if suffix == ".e01":
                self._open_e01()
            else:
                self._open_raw()
            self._is_open = True
            logger.info(
                f"Opened {self.image_format.upper()} image: {self.image_path.name} "
                f"({self.image_size:,} bytes)"
            )
            self.opening_hash = self._compute_hash()
            logger.info(f"Opening SHA256: {self.opening_hash}")
            return self
        except ForensicImageError:
            raise
        except Exception as exc:
            raise ForensicImageError(f"Failed to open evidence image: {exc}") from exc

    def _open_raw(self) -> None:
        self._handle = open(self.image_path, "rb")
        self._handle.seek(0, 2)
        self.image_size = self._handle.tell()
        self._handle.seek(0)
        self.image_format = "raw"

    def _open_e01(self) -> None:
        try:
            import pyewf  # type: ignore
            filenames = pyewf.glob(str(self.image_path))
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(filenames)
            self.image_size = self._ewf_handle.get_media_size()
            self.image_format = "e01"
        except ImportError:
            logger.warning("pyewf not installed. Treating E01 as raw.")
            self._open_raw()
            self.image_format = "raw (e01 fallback)"

    def read_at(self, offset: int, length: int) -> bytes:
        """Read raw bytes at an arbitrary byte offset."""
        if not self._is_open:
            raise ForensicImageError("Image is not open. Call open() first.")
        if offset < 0 or offset >= self.image_size:
            raise ForensicImageError(
                f"Read offset {offset} out of range (image size: {self.image_size})"
            )
        try:
            if self._ewf_handle:
                self._ewf_handle.seek(offset)
                return self._ewf_handle.read(length)
            else:
                self._handle.seek(offset)
                return self._handle.read(length)
        except Exception as exc:
            raise ForensicImageError(
                f"Read failed at offset {offset}, length {length}: {exc}"
            ) from exc

    def read_sector(self, sector_number: int) -> bytes:
        """Read a single sector."""
        return self.read_at(sector_number * self.sector_size, self.sector_size)

    def read_sectors(self, start_sector: int, count: int) -> bytes:
        """Read multiple consecutive sectors."""
        return self.read_at(start_sector * self.sector_size, count * self.sector_size)

    def _compute_hash(self, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
        """Compute a streaming hash of the entire image."""
        hasher = hashlib.new(algorithm)
        offset = 0
        while offset < self.image_size:
            chunk_size = min(HASH_CHUNK_SIZE, self.image_size - offset)
            chunk = self.read_at(offset, chunk_size)
            hasher.update(chunk)
            offset += chunk_size
        return hasher.hexdigest()

    def verify_integrity(self) -> Tuple[bool, str, str]:
        """Recompute the image hash and compare to opening hash."""
        current_hash = self._compute_hash()
        is_intact = (current_hash == self.opening_hash)
        if not is_intact:
            logger.critical(
                "EVIDENCE INTEGRITY VIOLATION: Image hash changed!\n"
                f"  Opening: {self.opening_hash}\n  Current: {current_hash}"
            )
        else:
            logger.info("Evidence integrity verified — hash unchanged.")
        return is_intact, self.opening_hash, current_hash

    def get_info(self) -> dict:
        """Return image metadata for reporting."""
        return {
            "path": str(self.image_path),
            "filename": self.image_path.name,
            "format": self.image_format,
            "size_bytes": self.image_size,
            "size_gb": round(self.image_size / (1024 ** 3), 4),
            "sector_size": self.sector_size,
            "opening_sha256": self.opening_hash,
        }

    def close(self) -> None:
        """Close the image file handle."""
        if self._ewf_handle:
            self._ewf_handle.close()
            self._ewf_handle = None
        if self._handle:
            self._handle.close()
            self._handle = None
        self._is_open = False
        logger.info(f"Closed image: {self.image_path.name}")

    def __enter__(self) -> "ForensicImageReader":
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        status = "open" if self._is_open else "closed"
        return (
            f"ForensicImageReader("
            f"path='{self.image_path.name}', "
            f"format='{self.image_format}', "
            f"size={self.image_size:,}B, "
            f"status={status})"
        )


def detect_filesystem_type(reader: "ForensicImageReader") -> str:
    """Heuristically detect the filesystem type by checking known magic bytes."""
    try:
        boot = reader.read_at(0, 512)
        if len(boot) >= 11 and boot[3:11] == b"NTFS    ":
            logger.info("Filesystem detected: NTFS")
            return FS_TYPE_NTFS

        ext4_sb = reader.read_at(EXT4_SUPERBLOCK_OFFSET, 64)
        if len(ext4_sb) >= 58:
            magic = struct.unpack_from("<H", ext4_sb, 56)[0]
            if magic == EXT4_MAGIC:
                logger.info("Filesystem detected: EXT4")
                return FS_TYPE_EXT4

        xfs_sb = reader.read_at(0, 4)
        if len(xfs_sb) >= 4:
            xfs_magic = struct.unpack_from(">I", xfs_sb, 0)[0]
            if xfs_magic == XFS_SUPERBLOCK_MAGIC:
                logger.info("Filesystem detected: XFS")
                return FS_TYPE_XFS
    except ForensicImageError as e:
        logger.warning(f"Filesystem detection error: {e}")

    logger.warning("Filesystem type undetermined.")
    return FS_TYPE_UNKNOWN
