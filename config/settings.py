import os
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# PROJECT PATHS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLE_IMAGES_DIR = BASE_DIR / "sample_images"

# Ensure output directories exist
for _dir in [LOGS_DIR, REPORTS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION METADATA
# ─────────────────────────────────────────────────────────────────────────────

TOOL_NAME = "DeletedFileRecoveryTool"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "DFIR Forensics Platform"
TOOL_DESCRIPTION = (
    "Production-quality deleted file recovery and forensic analysis platform "
    "supporting NTFS, EXT4, and XFS filesystem images."
)

# ─────────────────────────────────────────────────────────────────────────────
# NTFS FILESYSTEM CONSTANTS
# Reference: NTFS specification (Microsoft) and Brian Carrier's "File System Forensics"
# ─────────────────────────────────────────────────────────────────────────────

NTFS_SECTOR_SIZE = 512              # Standard sector size in bytes
NTFS_DEFAULT_CLUSTER_SIZE = 4096    # Default cluster = 8 sectors × 512 bytes
NTFS_MFT_ENTRY_SIZE = 1024          # Each MFT record is 1024 bytes by default
NTFS_MFT_MAGIC = b"FILE"            # MFT record signature
NTFS_BAD_CLUSTER_MAGIC = b"BAAD"    # Indicates a bad/corrupt MFT entry
NTFS_BOOT_SECTOR_SIGNATURE = b"\x55\xAA"  # Standard boot sector end signature
NTFS_MFT_RECORD_IN_USE = 0x0001     # Flags bit: record is allocated/in-use
NTFS_MFT_RECORD_IS_DIR = 0x0002     # Flags bit: record is a directory

# MFT attribute type codes (per NTFS specification)
NTFS_ATTR_STANDARD_INFO = 0x10      # $STANDARD_INFORMATION — timestamps, flags
NTFS_ATTR_ATTR_LIST = 0x20          # $ATTRIBUTE_LIST — for large files
NTFS_ATTR_FILE_NAME = 0x30          # $FILE_NAME — file name and parent ref
NTFS_ATTR_OBJECT_ID = 0x40          # $OBJECT_ID — GUID for the file
NTFS_ATTR_SECURITY = 0x50           # $SECURITY_DESCRIPTOR
NTFS_ATTR_VOLUME_NAME = 0x60        # $VOLUME_NAME
NTFS_ATTR_DATA = 0x80               # $DATA — actual file content
NTFS_ATTR_INDEX_ROOT = 0x90         # $INDEX_ROOT — directory index
NTFS_ATTR_INDEX_ALLOC = 0xA0        # $INDEX_ALLOCATION — large directories
NTFS_ATTR_BITMAP = 0xB0             # $BITMAP — allocation bitmap
NTFS_ATTR_END = 0xFFFFFFFF          # End of attribute list sentinel

# ─────────────────────────────────────────────────────────────────────────────
# EXT4 FILESYSTEM CONSTANTS
# Reference: Linux kernel ext4 source, ext4 wiki, Brian Carrier's analysis
# ─────────────────────────────────────────────────────────────────────────────

EXT4_BLOCK_SIZE = 4096              # Default block size (can be 1024, 2048, 4096)
EXT4_INODE_SIZE = 256               # Default inode size in ext4 (128 in ext2/3)
EXT4_SUPERBLOCK_OFFSET = 1024       # Superblock starts at byte 1024
EXT4_SUPERBLOCK_SIZE = 1024         # Superblock is 1024 bytes
EXT4_MAGIC = 0xEF53                 # EXT filesystem magic number
EXT4_BLOCK_GROUP_DESC_SIZE = 64     # Block group descriptor size (ext4 with 64-bit)
EXT4_INODE_MODE_REGULAR = 0x8000    # Regular file
EXT4_INODE_MODE_DIR = 0x4000        # Directory
EXT4_INODE_MODE_SYMLINK = 0xA000    # Symbolic link
EXT4_INODE_DELETED_DTIME_OFFSET = 20  # dtime field offset in inode struct
EXT4_JOURNAL_SUPERBLOCK_MAGIC = 0xC03B3998  # JBD2 journal magic

# EXT4 Feature flags (for superblock analysis)
EXT4_FEATURE_COMPAT_HAS_JOURNAL = 0x0004
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040    # Uses extent tree (not block maps)
EXT4_FEATURE_INCOMPAT_64BIT = 0x0080      # 64-bit block numbers
EXT4_FEATURE_RO_COMPAT_HUGE_FILE = 0x0008

# ─────────────────────────────────────────────────────────────────────────────
# XFS FILESYSTEM CONSTANTS
# Reference: XFS Filesystem Structure document (kernel.org), xfs-utils source
# ─────────────────────────────────────────────────────────────────────────────

XFS_BLOCK_SIZE = 4096               # Default block size (512 to 65536)
XFS_INODE_SIZE = 512                # XFS inode core size
XFS_SUPERBLOCK_MAGIC = 0x58465342   # "XFSB" in big-endian
XFS_SUPERBLOCK_OFFSET = 0           # Superblock at byte 0 of AG 0
XFS_AGF_MAGIC = 0x58414746          # "XAGF" — AG freespace header
XFS_AGI_MAGIC = 0x58414749          # "XAGI" — AG inode B-tree header
XFS_INODE_MAGIC = 0x494E            # "IN" — XFS inode magic
XFS_DINODE_FMT_EXTENTS = 2          # Inode stores extent list
XFS_DINODE_FMT_BTREE = 3            # Inode stores B-tree root
XFS_ATTR_FORK_OFF = 0               # Attribute fork starts here if present

# ─────────────────────────────────────────────────────────────────────────────
# HASHING CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SUPPORTED_HASH_ALGORITHMS = ["sha256", "md5", "sha1"]
DEFAULT_HASH_ALGORITHM = "sha256"
HASH_CHUNK_SIZE = 65536             # 64 KB chunks for streaming hash computation

# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE HANDLING
# ─────────────────────────────────────────────────────────────────────────────

SUPPORTED_IMAGE_FORMATS = [".dd", ".img", ".raw", ".bin", ".e01"]
MAX_RECOVERED_FILE_SIZE_MB = 512    # Safety cap: don't extract >512MB single file
READ_ONLY_MODE = True               # ALWAYS true — forensic operations are read-only

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
LOG_LEVEL = "DEBUG"                 # Verbose logging for forensic auditability
LOG_FILE_NAME = "investigation.log"

# ─────────────────────────────────────────────────────────────────────────────
# REPORT SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

REPORT_FORMATS = ["html", "json", "txt"]
DEFAULT_REPORT_FORMAT = "html"
REPORT_TEMPLATE_DIR = BASE_DIR / "gui" / "templates"

# ─────────────────────────────────────────────────────────────────────────────
# FILESYSTEM TYPE IDENTIFIERS
# ─────────────────────────────────────────────────────────────────────────────

FS_TYPE_NTFS = "ntfs"
FS_TYPE_EXT4 = "ext4"
FS_TYPE_XFS = "xfs"
FS_TYPE_UNKNOWN = "unknown"
SUPPORTED_FILESYSTEMS = [FS_TYPE_NTFS, FS_TYPE_EXT4, FS_TYPE_XFS]
