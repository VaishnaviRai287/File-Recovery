import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional

from config.settings import HASH_CHUNK_SIZE, SUPPORTED_HASH_ALGORITHMS

logger = logging.getLogger(__name__)


class HashVerifier:
    """
    Computes and verifies cryptographic hashes for files and byte buffers.
    """

    @staticmethod
    def hash_file(file_path: str, algorithm: str = "sha256") -> str:
        """Compute the hash of a file using streaming reads."""
        algorithm = algorithm.lower()
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: '{algorithm}'. "
                f"Supported: {SUPPORTED_HASH_ALGORITHMS}"
            )

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        hasher = hashlib.new(algorithm)
        with open(path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                hasher.update(chunk)

        digest = hasher.hexdigest()
        logger.debug(f"{algorithm.upper()} of '{path.name}': {digest}")
        return digest

    @staticmethod
    def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
        """Compute the hash of a byte buffer."""
        algorithm = algorithm.lower()
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: '{algorithm}'")
        digest = hashlib.new(algorithm, data).hexdigest()
        logger.debug(f"{algorithm.upper()} of {len(data)}-byte buffer: {digest}")
        return digest

    @staticmethod
    def hash_file_all(file_path: str) -> Dict[str, str]:
        """Compute SHA256, MD5, and SHA1 in a single streaming pass."""
        path = Path(file_path)
        hashers = {
            "sha256": hashlib.sha256(),
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
        }
        with open(path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                for h in hashers.values():
                    h.update(chunk)

        result = {name: h.hexdigest() for name, h in hashers.items()}
        logger.debug(f"Multi-hash of '{path.name}': SHA256={result['sha256'][:16]}...")
        return result

    @staticmethod
    def verify_file(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        """Verify a file matches an expected hash."""
        computed = HashVerifier.hash_file(file_path, algorithm)
        match = (computed.lower() == expected_hash.lower())
        if match:
            logger.info(f"Hash verified OK: {Path(file_path).name}")
        else:
            logger.warning(
                f"Hash MISMATCH for '{Path(file_path).name}':\n"
                f"  Expected: {expected_hash}\n"
                f"  Computed: {computed}"
            )
        return match

    @staticmethod
    def verify_bytes(data: bytes, expected_hash: str, algorithm: str = "sha256") -> bool:
        """Verify a byte buffer matches an expected hash."""
        computed = HashVerifier.hash_bytes(data, algorithm)
        return computed.lower() == expected_hash.lower()
