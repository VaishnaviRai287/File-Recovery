import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict

from core.metadata_extractor import ForensicMetadata, identify_file_type

logger = logging.getLogger(__name__)

# Minimum plausible timestamp (January 1, 1980 UTC)
_MIN_VALID_TIMESTAMP = datetime(1980, 1, 1, tzinfo=timezone.utc)
# Maximum plausible timestamp (year 2100)
_MAX_VALID_TIMESTAMP = datetime(2100, 1, 1, tzinfo=timezone.utc)


@dataclass
class ValidationResult:
    """Comprehensive validation report for a single recovered artifact."""
    identifier: str
    filename: Optional[str]
    filesystem_type: str

    # Validation checks
    magic_matches_extension: Optional[bool] = None
    size_plausible: bool = True
    timestamps_valid: bool = True
    timestamps_consistent: bool = True
    recovered_size_matches: bool = True

    # Summary
    confidence_score: float = 1.0     # 0.0 to 1.0
    anomalies: List[str] = field(default_factory=list)
    is_viable: bool = True             # Should this artifact be included in the report?

    def add_anomaly(self, description: str, severity: str = "warning") -> None:
        """Log an anomaly and penalize confidence score."""
        self.anomalies.append(f"[{severity.upper()}] {description}")
        if severity == "critical":
            self.confidence_score -= 0.3
        elif severity == "warning":
            self.confidence_score -= 0.15
        else:
            self.confidence_score -= 0.05
        self.confidence_score = max(0.0, self.confidence_score)

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "filename": self.filename,
            "filesystem_type": self.filesystem_type,
            "magic_matches_extension": self.magic_matches_extension,
            "size_plausible": self.size_plausible,
            "timestamps_valid": self.timestamps_valid,
            "timestamps_consistent": self.timestamps_consistent,
            "recovered_size_matches": self.recovered_size_matches,
            "confidence_score": round(self.confidence_score, 2),
            "anomalies": self.anomalies,
            "is_viable": self.is_viable,
        }


class ArtifactValidator:
    """Validates recovered artifacts against forensic quality criteria."""

    def validate(
        self,
        metadata: ForensicMetadata,
        recovered_data: Optional[bytes] = None,
        reported_size: Optional[int] = None,
    ) -> ValidationResult:
        """Perform all validation checks on a recovered artifact."""
        result = ValidationResult(
            identifier=metadata.identifier,
            filename=metadata.filename,
            filesystem_type=metadata.filesystem_type,
        )

        self._check_timestamps(metadata, result)
        self._check_size(metadata, recovered_data, reported_size, result)
        self._check_magic(metadata, recovered_data, result)
        self._assess_viability(result)

        logger.debug(
            f"Validated {metadata.filesystem_type}:{metadata.identifier} — "
            f"confidence={result.confidence_score:.2f}, "
            f"anomalies={len(result.anomalies)}"
        )
        return result

    def _check_timestamps(self, metadata: ForensicMetadata, result: ValidationResult) -> None:
        """Validate timestamp plausibility and mutual consistency."""
        timestamps = {
            "created": metadata.created,
            "modified": metadata.modified,
            "accessed": metadata.accessed,
            "metadata_changed": metadata.metadata_changed,
        }

        for name, ts in timestamps.items():
            if ts is None:
                continue
            if ts < _MIN_VALID_TIMESTAMP or ts > _MAX_VALID_TIMESTAMP:
                result.add_anomaly(
                    f"Timestamp '{name}' out of plausible range: {ts.isoformat()}",
                    severity="warning"
                )
                result.timestamps_valid = False

        # Temporal consistency: modified should not be before created (if both exist)
        if metadata.created and metadata.modified:
            if metadata.modified < metadata.created:
                result.add_anomaly(
                    "Modified timestamp is before created timestamp — "
                    "possible clock skew, corruption, or anti-forensics",
                    severity="warning"
                )
                result.timestamps_consistent = False

        # Deletion time should be after creation time
        if metadata.created and metadata.deleted_time:
            if metadata.deleted_time < metadata.created:
                result.add_anomaly(
                    "Deletion time is before creation time — likely metadata corruption",
                    severity="critical"
                )

    def _check_size(
        self,
        metadata: ForensicMetadata,
        recovered_data: Optional[bytes],
        reported_size: Optional[int],
        result: ValidationResult,
    ) -> None:
        """Validate file size plausibility."""
        if metadata.size_bytes < 0:
            result.add_anomaly("Negative file size in metadata", severity="critical")
            result.size_plausible = False
            return

        if metadata.size_bytes > 100 * 1024 * 1024 * 1024:  # 100 GB
            result.add_anomaly(
                f"Implausibly large file size: {metadata.size_bytes:,} bytes",
                severity="warning"
            )

        if recovered_data is not None and reported_size is not None:
            rec_size = len(recovered_data)
            if rec_size < reported_size * 0.9:  # Less than 90% recovered
                result.add_anomaly(
                    f"Recovered {rec_size:,} bytes but metadata reports {reported_size:,} — "
                    "likely partial overwrite",
                    severity="warning"
                )
                result.recovered_size_matches = False

    def _check_magic(
        self,
        metadata: ForensicMetadata,
        recovered_data: Optional[bytes],
        result: ValidationResult,
    ) -> None:
        """Check that file magic bytes match the file extension (if known)."""
        if not recovered_data or len(recovered_data) < 4:
            return
        if not metadata.filename:
            return

        # Get extension from filename
        parts = metadata.filename.rsplit(".", 1)
        if len(parts) != 2:
            return
        declared_ext = parts[1].lower()

        # Identify from content
        magic_result = identify_file_type(recovered_data)
        magic_ext = magic_result.get("extension", "").lower()

        if magic_result["confidence"] == "high":
            result.magic_matches_extension = (declared_ext == magic_ext)
            if not result.magic_matches_extension:
                result.add_anomaly(
                    f"Extension '.{declared_ext}' does not match magic bytes "
                    f"(detected as '.{magic_ext}'/{magic_result['mime_type']}) — "
                    "possible extension spoofing or overwrite",
                    severity="warning"
                )

    def _assess_viability(self, result: ValidationResult) -> None:
        """Determine if the artifact is viable for inclusion in report."""
        if result.confidence_score < 0.2:
            result.is_viable = False
        elif len([a for a in result.anomalies if "[CRITICAL]" in a]) >= 2:
            result.is_viable = False

    def validate_batch(
        self, metadata_list: List[ForensicMetadata]
    ) -> List[ValidationResult]:
        """Validate a list of metadata records."""
        results = []
        for meta in metadata_list:
            r = self.validate(meta)
            results.append(r)

        viable = sum(1 for r in results if r.is_viable)
        logger.info(
            f"Batch validation: {viable}/{len(results)} artifacts viable."
        )
        return results

    def generate_summary(self, results: List[ValidationResult]) -> Dict:
        """Generate a validation summary for reporting."""
        total = len(results)
        viable = sum(1 for r in results if r.is_viable)
        anomaly_count = sum(len(r.anomalies) for r in results)
        avg_confidence = (
            sum(r.confidence_score for r in results) / total if total > 0 else 0
        )
        return {
            "total_artifacts": total,
            "viable_artifacts": viable,
            "non_viable_artifacts": total - viable,
            "total_anomalies": anomaly_count,
            "average_confidence": round(avg_confidence, 3),
        }
