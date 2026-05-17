import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from core.image_reader import ForensicImageReader, detect_filesystem_type
from core.evidence_handler import EvidenceHandler, EvidenceRecord
from core.metadata_extractor import MetadataExtractor, ForensicMetadata, build_timeline
from core.validator import ArtifactValidator, ValidationResult
from config.settings import (
    FS_TYPE_NTFS, FS_TYPE_EXT4, FS_TYPE_XFS, FS_TYPE_UNKNOWN,
    TOOL_VERSION, TOOL_NAME,
)

logger = logging.getLogger(__name__)


@dataclass
class RecoveredArtifact:
    metadata: ForensicMetadata
    validation: ValidationResult
    output_path: Optional[Path]
    recovered_size: int
    sha256: str
    recovery_reason: str
    recovered: bool

    def to_dict(self) -> dict:
        return {
            **self.metadata.to_dict(),
            **self.validation.to_dict(),
            "output_path": str(self.output_path) if self.output_path else None,
            "recovered_size_bytes": self.recovered_size,
            "recovered_sha256": self.sha256,
            "recovery_reason": self.recovery_reason,
            "recovered": self.recovered,
        }


@dataclass
class InvestigationResult:
    """Complete result of a forensic investigation on a single image."""
    case_id: str
    examiner: str
    image_info: Dict[str, Any]
    filesystem_type: str
    investigation_start: str
    investigation_end: str
    duration_seconds: float
    tool_name: str = TOOL_NAME
    tool_version: str = TOOL_VERSION

    # Results
    total_records_scanned: int = 0
    total_deleted_found: int = 0
    total_recovered: int = 0
    artifacts: List[RecoveredArtifact] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)
    validation_summary: Dict = field(default_factory=dict)
    custody_log_path: Optional[str] = None

    @property
    def recovery_rate(self) -> float:
        if self.total_deleted_found == 0:
            return 0.0
        return self.total_recovered / self.total_deleted_found

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "examiner": self.examiner,
            "image_info": self.image_info,
            "filesystem_type": self.filesystem_type,
            "investigation_start": self.investigation_start,
            "investigation_end": self.investigation_end,
            "duration_seconds": round(self.duration_seconds, 2),
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "total_records_scanned": self.total_records_scanned,
            "total_deleted_found": self.total_deleted_found,
            "total_recovered": self.total_recovered,
            "recovery_rate": round(self.recovery_rate, 3),
            "validation_summary": self.validation_summary,
            "custody_log_path": self.custody_log_path,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "timeline": self.timeline,
        }


class RecoveryEngine:

    def __init__(self, case_id: str, examiner: str, output_dir: str):
        self.case_id = case_id
        self.examiner = examiner
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._evidence_handler = EvidenceHandler(case_id, examiner)
        self._validator = ArtifactValidator()
        logger.info(
            f"RecoveryEngine initialized — "
            f"Case: {case_id}, Examiner: {examiner}"
        )

    def investigate(
        self,
        image_path: str,
        max_records: int = 100_000,
        filesystem_type: Optional[str] = None,
    ) -> InvestigationResult:
        """Run a complete forensic investigation on a disk image."""
        start_time = time.perf_counter()
        start_ts = datetime.now(timezone.utc).isoformat()

        logger.info(f"=== Investigation started: {image_path} ===")

        with ForensicImageReader(image_path) as reader:
            # Step 1: Register evidence
            evidence_record = self._evidence_handler.register_evidence(reader)
            image_info = reader.get_info()

            # Step 2: Detect filesystem
            fs_type = filesystem_type or detect_filesystem_type(reader)
            logger.info(f"Filesystem type: {fs_type}")
            self._evidence_handler.log_action(
                "Filesystem Detection",
                f"Detected filesystem: {fs_type}"
            )

            if fs_type == FS_TYPE_UNKNOWN:
                logger.warning(
                    "Unknown filesystem type. Cannot proceed with structured recovery."
                )

            # Step 3: Run recovery engine
            raw_results = self._run_engine(reader, fs_type, max_records)

            # Step 4: Normalize and validate
            artifacts = self._process_results(raw_results, fs_type)

            # Step 5: Build timeline
            timeline = build_timeline([a.metadata for a in artifacts])

            # Step 6: Validation summary
            validation_results = [a.validation for a in artifacts]
            val_summary = self._validator.generate_summary(validation_results)

            # Step 7: Save chain-of-custody log
            self._evidence_handler.log_action(
                "Investigation Complete",
                f"Found {len(artifacts)} artifacts, recovered {sum(1 for a in artifacts if a.recovered)}"
            )
            custody_path = self._evidence_handler.save_custody_log(
                self.output_dir / "logs"
            )

        end_time = time.perf_counter()
        end_ts = datetime.now(timezone.utc).isoformat()
        duration = end_time - start_time

        result = InvestigationResult(
            case_id=self.case_id,
            examiner=self.examiner,
            image_info=image_info,
            filesystem_type=fs_type,
            investigation_start=start_ts,
            investigation_end=end_ts,
            duration_seconds=duration,
            total_deleted_found=len(artifacts),
            total_recovered=sum(1 for a in artifacts if a.recovered),
            artifacts=artifacts,
            timeline=timeline,
            validation_summary=val_summary,
            custody_log_path=str(custody_path),
        )

        logger.info(
            f"=== Investigation complete ===\n"
            f"    Deleted found:  {result.total_deleted_found}\n"
            f"    Recovered:      {result.total_recovered}\n"
            f"    Recovery rate:  {result.recovery_rate:.1%}\n"
            f"    Duration:       {duration:.2f}s"
        )
        return result

    def _run_engine(self, reader, fs_type: str, max_records: int) -> list:
        """Dispatch to the correct filesystem-specific recovery engine."""
        if fs_type == FS_TYPE_NTFS:
            return self._run_ntfs(reader, max_records)
        elif fs_type == FS_TYPE_EXT4:
            return self._run_ext4(reader)
        elif fs_type == FS_TYPE_XFS:
            return self._run_xfs(reader)
        else:
            logger.error(f"No recovery engine for filesystem type: {fs_type}")
            return []

    def _run_ntfs(self, reader, max_records: int) -> list:
        from core.ntfs_recovery import NTFSRecoveryEngine
        engine = NTFSRecoveryEngine(reader, str(self.output_dir / "recovered"))
        self._evidence_handler.log_action("NTFS MFT Scan", "Scanning Master File Table for deleted records")
        results = engine.recover_all(max_records)
        self._evidence_handler.log_action(
            "NTFS Recovery",
            f"Recovered {sum(1 for r in results if r.recovered)} files"
        )
        return results

    def _run_ext4(self, reader) -> list:
        from core.ext4_recovery import EXT4RecoveryEngine
        engine = EXT4RecoveryEngine(reader, str(self.output_dir / "recovered"))
        self._evidence_handler.log_action("EXT4 Inode Scan", "Scanning inode table for deleted inodes")
        results = engine.recover_all()
        self._evidence_handler.log_action(
            "EXT4 Recovery",
            f"Recovered {sum(1 for r in results if r.recovered)} files"
        )
        return results

    def _run_xfs(self, reader) -> list:
        from core.xfs_recovery import XFSRecoveryEngine
        engine = XFSRecoveryEngine(reader, str(self.output_dir / "recovered"))
        self._evidence_handler.log_action("XFS AG Scan", "Scanning Allocation Groups for deleted inodes")
        results = engine.recover_all()
        self._evidence_handler.log_action(
            "XFS Recovery",
            f"Recovered {sum(1 for r in results if r.recovered)} files"
        )
        return results

    def _process_results(self, raw_results: list, fs_type: str) -> List[RecoveredArtifact]:
        """Convert raw recovery results to normalized, validated RecoveredArtifact objects."""
        artifacts = []
        for result in raw_results:
            try:
                metadata = self._normalize_metadata(result, fs_type)
                validation = self._validator.validate(metadata)
                artifacts.append(RecoveredArtifact(
                    metadata=metadata,
                    validation=validation,
                    output_path=result.output_path,
                    recovered_size=result.recovered_size,
                    sha256=result.sha256,
                    recovery_reason=result.reason,
                    recovered=result.recovered,
                ))
            except Exception as e:
                logger.debug(f"Result processing error: {e}")
        return artifacts

    def _normalize_metadata(self, result, fs_type: str) -> ForensicMetadata:
        """Convert a raw result to ForensicMetadata."""
        if fs_type == FS_TYPE_NTFS:
            return MetadataExtractor.from_ntfs_record(result.record)
        elif fs_type == FS_TYPE_EXT4:
            return MetadataExtractor.from_ext4_inode(result.record)
        elif fs_type == FS_TYPE_XFS:
            return MetadataExtractor.from_xfs_inode(result.record)
        else:
            raise ValueError(f"Unknown filesystem type: {fs_type}")
