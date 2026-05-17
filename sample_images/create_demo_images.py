"""
Synthetic forensic image generator for testing and demonstration.
Creates minimal .dd images with valid NTFS, EXT4, and XFS signatures.
"""
import struct
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

IMAGES_DIR = Path(__file__).parent.parent / "sample_images"
IMAGES_DIR.mkdir(exist_ok=True)

# Image size: 4 MB (8192 sectors of 512 bytes)
IMAGE_SIZE = 4 * 1024 * 1024


def create_ntfs_image():
    """Create a minimal NTFS forensic image with one synthetic deleted MFT record."""
    path = IMAGES_DIR / "ntfs_demo.dd"
    data = bytearray(IMAGE_SIZE)

    # NTFS boot sector at byte 0
    # OEM ID at offset 3
    data[3:11] = b"NTFS    "
    # Bytes per sector: 512
    struct.pack_into("<H", data, 11, 512)
    # Sectors per cluster: 8 → cluster size = 4096
    data[13] = 8
    # MFT LCN at offset 48 → cluster 4 → byte 4*4096 = 16384
    struct.pack_into("<Q", data, 48, 4)
    # Boot signature
    data[510] = 0x55
    data[511] = 0xAA

    # Write a synthetic MFT at byte 16384
    # MFT record 0 (in-use, $MFT itself)
    mft_base = 16384
    rec0 = bytearray(1024)
    rec0[0:4] = b"FILE"
    struct.pack_into("<H", rec0, 0x14, 56)   # offset to attrs
    struct.pack_into("<H", rec0, 0x16, 0x01)  # in-use flag
    data[mft_base:mft_base + 1024] = rec0

    # MFT record 48 — DELETED file
    rec48 = bytearray(1024)
    rec48[0:4] = b"FILE"
    struct.pack_into("<H", rec48, 0x14, 56)    # offset to attrs
    struct.pack_into("<H", rec48, 0x16, 0x00)  # NOT in-use = DELETED

    # $STANDARD_INFORMATION attribute (type 0x10, resident)
    si_offset = 56
    struct.pack_into("<I", rec48, si_offset, 0x10)       # attr type
    struct.pack_into("<I", rec48, si_offset + 4, 96)     # attr length
    rec48[si_offset + 8] = 0                              # resident
    struct.pack_into("<H", rec48, si_offset + 20, 24)    # content offset
    struct.pack_into("<I", rec48, si_offset + 16, 48)    # content size
    # Timestamps (Windows FILETIME for 2024-01-15 10:30:00 UTC ≈ 133495674000000000)
    ts = 133495674000000000
    si_content = si_offset + 24
    for i in range(4):  # 4 MACE timestamps
        struct.pack_into("<Q", rec48, si_content + i * 8, ts)

    # $FILE_NAME attribute (type 0x30, resident)
    fn_offset = si_offset + 96
    filename = "deleted_secret.txt"
    fn_bytes = filename.encode("utf-16-le")
    fn_content_size = 66 + len(fn_bytes)
    struct.pack_into("<I", rec48, fn_offset, 0x30)
    struct.pack_into("<I", rec48, fn_offset + 4, 24 + fn_content_size)
    rec48[fn_offset + 8] = 0
    struct.pack_into("<H", rec48, fn_offset + 20, 24)
    struct.pack_into("<I", rec48, fn_offset + 16, fn_content_size)
    # Parent MFT ref = record 5 (root)
    struct.pack_into("<Q", rec48, fn_offset + 24, 5)
    # Timestamps in $FILE_NAME
    for i in range(4):
        struct.pack_into("<Q", rec48, fn_offset + 24 + 8 + i * 8, ts)
    # File size
    struct.pack_into("<Q", rec48, fn_offset + 24 + 40, 1024)
    # Name length + namespace
    rec48[fn_offset + 24 + 64] = len(filename)
    rec48[fn_offset + 24 + 65] = 1  # Win32 namespace
    rec48[fn_offset + 24 + 66: fn_offset + 24 + 66 + len(fn_bytes)] = fn_bytes

    # End of attributes sentinel
    fn_end = fn_offset + 24 + fn_content_size
    fn_end = (fn_end + 7) & ~7  # align to 8
    struct.pack_into("<I", rec48, fn_end, 0xFFFFFFFF)

    # Place record 48 at correct MFT offset
    rec48_offset = mft_base + 48 * 1024
    if rec48_offset + 1024 <= IMAGE_SIZE:
        data[rec48_offset:rec48_offset + 1024] = rec48

    path.write_bytes(bytes(data))
    print(f"[+] Created: {path} ({IMAGE_SIZE // 1024} KB)")
    return path


def create_ext4_image():
    """Create a minimal EXT4 forensic image with one synthetic deleted inode."""
    path = IMAGES_DIR / "ext4_demo.dd"
    data = bytearray(IMAGE_SIZE)

    # EXT4 superblock at byte 1024
    sb_offset = 1024
    struct.pack_into("<I", data, sb_offset + 0, 1024)    # inode count
    struct.pack_into("<I", data, sb_offset + 4, 1024)    # block count
    struct.pack_into("<I", data, sb_offset + 20, 0)      # first data block (4096 block size)
    struct.pack_into("<I", data, sb_offset + 24, 2)      # log_block_size (1024 << 2 = 4096)
    struct.pack_into("<I", data, sb_offset + 32, 32768)  # blocks per group
    struct.pack_into("<I", data, sb_offset + 40, 256)    # inodes per group
    struct.pack_into("<H", data, sb_offset + 56, 0xEF53) # EXT4 magic
    struct.pack_into("<H", data, sb_offset + 88, 256)    # inode size

    # Group descriptor table at byte 4096 (block 1 for 4096-byte block size)
    gd_offset = 4096
    # inode table at block 4 → byte 16384
    struct.pack_into("<I", data, gd_offset + 8, 4)

    # Write a deleted inode at byte 16384 + 12 * 256 (inode 13)
    inode_table_offset = 16384
    inode_offset = inode_table_offset + 12 * 256  # Inode 13 (1-indexed → index 12)

    # mode = 0x81A4 (regular file, 644)
    struct.pack_into("<H", data, inode_offset + 0, 0x81A4)
    struct.pack_into("<H", data, inode_offset + 2, 1000)   # uid
    struct.pack_into("<I", data, inode_offset + 4, 4096)   # size_lo
    struct.pack_into("<I", data, inode_offset + 8, 1705312200)  # atime (2024-01-15)
    struct.pack_into("<I", data, inode_offset + 12, 1705312200) # ctime
    struct.pack_into("<I", data, inode_offset + 16, 1705312200) # mtime
    struct.pack_into("<I", data, inode_offset + 20, 1705315800) # dtime (deletion time!)
    struct.pack_into("<H", data, inode_offset + 24, 1000)  # gid
    struct.pack_into("<H", data, inode_offset + 26, 0)     # link_count = 0 (deleted)
    struct.pack_into("<I", data, inode_offset + 32, 0)     # flags (no extents = old block pointers)
    # Direct block pointer [0] → block 20 → byte 81920
    struct.pack_into("<I", data, inode_offset + 40, 20)
    # Write some file content at block 20
    content = b"DELETED FILE CONTENT - This is forensic evidence recovered from EXT4 inode\n" * 10
    block20_offset = 20 * 4096
    if block20_offset + len(content) <= IMAGE_SIZE:
        data[block20_offset:block20_offset + len(content)] = content

    path.write_bytes(bytes(data))
    print(f"[+] Created: {path} ({IMAGE_SIZE // 1024} KB)")
    return path


def create_xfs_image():
    """Create a minimal XFS forensic image."""
    path = IMAGES_DIR / "xfs_demo.dd"
    data = bytearray(IMAGE_SIZE)

    # XFS superblock at byte 0 (big-endian)
    struct.pack_into(">I", data, 0, 0x58465342)   # "XFSB" magic
    struct.pack_into(">I", data, 4, 4096)          # block size
    struct.pack_into(">Q", data, 8, 1024)          # total blocks
    # agblocks at offset 84
    struct.pack_into(">I", data, 84, 256)          # ag_blocks
    # ag_count at offset 88
    struct.pack_into(">I", data, 88, 4)            # ag_count = 4
    # inode_size at offset 104
    struct.pack_into(">H", data, 104, 512)         # inode_size
    # agblklog (log2 of ag_blocks: 256 → 8)
    data[75] = 8
    # inopblog (log2 of inodes per block: 4096/512 = 8 → 3)
    data[76] = 3

    # Write a synthetic deleted XFS inode at offset (AG0 + 4 blocks + 0)
    # AG0 start = 0, skip 4 header blocks = offset 4*4096 = 16384
    inode_offset = 16384
    struct.pack_into(">H", data, inode_offset + 0, 0x494E)   # di_magic "IN"
    struct.pack_into(">H", data, inode_offset + 2, 0x81A4)   # di_mode (regular, 644)
    data[inode_offset + 4] = 3                                 # di_version
    data[inode_offset + 5] = XFS_DINODE_FMT_LOCAL = 1        # local format
    struct.pack_into(">I", data, inode_offset + 8, 1000)      # uid
    struct.pack_into(">I", data, inode_offset + 12, 1000)     # gid
    struct.pack_into(">I", data, inode_offset + 16, 0)        # nlink = 0 (deleted)
    struct.pack_into(">q", data, inode_offset + 0x38, 64)     # di_size = 64 bytes
    # Inline data fork after inode core (96 bytes)
    content = b"XFS deleted file content - forensic artifact\n"
    data[inode_offset + 96: inode_offset + 96 + len(content)] = content

    path.write_bytes(bytes(data))
    print(f"[+] Created: {path} ({IMAGE_SIZE // 1024} KB)")
    return path


if __name__ == "__main__":
    print("Creating synthetic forensic test images...")
    create_ntfs_image()
    create_ext4_image()
    create_xfs_image()
    print("\n[OK] All sample images created in sample_images/")
    print("    Use these with: python main.py scan --image sample_images/ntfs_demo.dd ...")
