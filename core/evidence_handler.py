import json
import hashlib
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from pathlib import Path

from config.settings import (
    HASH_CHUNK_SIZE,
    DEFAULT_HASH_ALGORITHM,
    LOGS_DIR,
    TOOL_VERSION,
)

logger = logging.getLogger(__name__)


@dataclass
class ChainOfCustodyEntry:
    timestamp: str
    examiner: str
    action: str
    detail: str
    result: str = "success"


@dataclass
class EvidenceRecord:
    case_id: str
    examiner: str
    evidence_path: str
    evidence_filename: str
    image_format: str
    image_size_bytes: int
    acquisition_timestamp: str
    sha256_hash: str
    md5_hash: str
    tool_version: str = TOOL_VERSION
    notes: str = ""
    custody_log: List[ChainOfCustodyEntry] = field(default_factory=list)

    def add_custody_entry(self, examiner: str, action: str, detail: str, result: str = "success") -> None:
        """Append a new chain-of-custody event."""
        entry = ChainOfCustodyEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            examiner=examiner,
            action=action,
            detail=detail,
            result=result,
        )
        self.custody_log.append(entry)
        logger.info(f"[CoC] {action} | {examiner} | {detail}")

    def to_dict(self) -> dict:
        """Serialize the record to a dictionary."""
        d = asdict(self)
        return d

    def to_json(self) -> str:
        """Serialize the record to JSON."""
        return json.dumps(self.to_dict(), indent=2)


class EvidenceHandler:

    def __init__(self, case_id: str, examiner: str):
        self.case_id = case_id
        self.examiner = examiner
        self.record: Optional[EvidenceRecord] = None
        logger.info(f"EvidenceHandler initialized — Case: {case_id}, Examiner: {examiner}")

    def register_evidence(self, reader) -> EvidenceRecord:
        """Register a forensic image and compute integrity hashes."""
        logger.info("Registering evidence and computing integrity hashes...")

        sha256 = self._hash_image(reader, "sha256")
        md5 = self._hash_image(reader, "md5")

        info = reader.get_info()
        ts = datetime.now(timezone.utc).isoformat()

        self.record = EvidenceRecord(
            case_id=self.case_id,
            examiner=self.examiner,
            evidence_path=info["path"],
            evidence_filename=info["filename"],
            image_format=info["format"],
            image_size_bytes=info["size_bytes"],
            acquisition_timestamp=ts,
            sha256_hash=sha256,
            md5_hash=md5,
        )

        self.record.add_custody_entry(
            examiner=self.examiner,
            action="Evidence Registration",
            detail=f"Image '{info['filename']}' registered. SHA256: {sha256[:16]}...",
        )

        logger.info(f"Evidence registered. SHA256: {sha256}")
        return self.record

    def log_action(self, action: str, detail: str, result: str = "success") -> None:
        """Log a forensic action to the chain of custody."""
        if not self.record:
            logger.warning("Cannot log action: no evidence registered.")
            return
        self.record.add_custody_entry(
            examiner=self.examiner,
            action=action,
            detail=detail,
            result=result,
        )

    def save_custody_log(self, output_dir: Optional[Path] = None) -> Path:
        """Save the chain-of-custody log as a JSON file."""
        if not self.record:
            raise RuntimeError("No evidence registered. Call register_evidence() first.")

        output_dir = output_dir or LOGS_DIR
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        safe_case = self.case_id.replace("/", "_").replace("\\", "_")
        log_path = output_dir / f"custody_{safe_case}.json"
        log_path.write_text(self.record.to_json(), encoding="utf-8")
        logger.info(f"Chain-of-custody log saved: {log_path}")
        return log_path

    @staticmethod
    def _hash_image(reader, algorithm: str) -> str:
        """Compute a streaming hash of the image using the given algorithm."""
        hasher = hashlib.new(algorithm)
        offset = 0
        while offset < reader.image_size:
            chunk_size = min(HASH_CHUNK_SIZE, reader.image_size - offset)
            chunk = reader.read_at(offset, chunk_size)
            hasher.update(chunk)
            offset += chunk_size
        return hasher.hexdigest()
