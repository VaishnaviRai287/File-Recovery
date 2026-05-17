import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import REPORTS_DIR, TOOL_NAME, TOOL_VERSION

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Investigation Report — {case_id}</title>
    <style>
        :root {{
            --primary: #1a2332;
            --accent: #00d4aa;
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --bg: #0f1923;
            --card: #1e2d3d;
            --text: #e8f4fd;
            --muted: #8899aa;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, var(--primary) 0%, #0d1b2a 100%);
            border-bottom: 2px solid var(--accent);
            padding: 2rem 3rem;
        }}
        .header h1 {{ font-size: 1.8rem; color: var(--accent); letter-spacing: 2px; }}
        .header h2 {{ font-size: 1.1rem; color: var(--muted); font-weight: 400; margin-top: 0.3rem; }}
        .badge {{
            display: inline-block;
            background: var(--accent);
            color: var(--primary);
            padding: 0.2rem 0.8rem;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-top: 0.5rem;
        }}
        .container {{ max-width: 1400px; margin: 2rem auto; padding: 0 2rem; }}
        .section {{
            background: var(--card);
            border-radius: 8px;
            border: 1px solid #2a3d52;
            margin-bottom: 2rem;
            overflow: hidden;
        }}
        .section-header {{
            background: rgba(0, 212, 170, 0.1);
            border-bottom: 1px solid #2a3d52;
            padding: 1rem 1.5rem;
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--accent);
        }}
        .section-body {{ padding: 1.5rem; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
        .stat-card {{
            background: var(--primary);
            border-radius: 6px;
            padding: 1.2rem;
            text-align: center;
            border: 1px solid #2a3d52;
        }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
        .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 0.3rem; }}
        .kv {{ display: flex; margin-bottom: 0.5rem; }}
        .kv-key {{ color: var(--muted); width: 220px; flex-shrink: 0; font-size: 0.85rem; }}
        .kv-val {{ font-family: 'Courier New', monospace; font-size: 0.85rem; word-break: break-all; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
        th {{
            background: var(--primary);
            color: var(--accent);
            text-align: left;
            padding: 0.7rem 1rem;
            font-size: 0.75rem;
            letter-spacing: 1px;
            text-transform: uppercase;
            border-bottom: 2px solid var(--accent);
        }}
        td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #2a3d52; }}
        tr:hover td {{ background: rgba(0, 212, 170, 0.05); }}
        .confidence-high {{ color: var(--success); font-weight: 600; }}
        .confidence-medium {{ color: var(--warning); font-weight: 600; }}
        .confidence-low {{ color: var(--danger); font-weight: 600; }}
        .recovered-yes {{ color: var(--success); }}
        .recovered-no {{ color: var(--muted); }}
        .hash {{ font-family: 'Courier New', monospace; font-size: 0.75rem; color: var(--muted); }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--muted);
            font-size: 0.8rem;
            border-top: 1px solid #2a3d52;
            margin-top: 3rem;
        }}
        .anomaly {{ color: var(--warning); font-size: 0.75rem; }}
        .tag {{
            display: inline-block;
            background: rgba(0,212,170,0.1);
            color: var(--accent);
            padding: 0.1rem 0.5rem;
            border-radius: 3px;
            font-size: 0.7rem;
            border: 1px solid rgba(0,212,170,0.3);
        }}
    </style>
</head>
<body>
<div class="header">
    <h1>🔍 FORENSIC INVESTIGATION REPORT</h1>
    <h2>{case_id} — {filesystem_type} Filesystem Analysis</h2>
    <span class="badge">CONFIDENTIAL</span>
    <span class="badge" style="background:#ff4757; margin-left:0.5rem;">RESTRICTED</span>
</div>

<div class="container">

    <!-- Stats -->
    <div class="section">
        <div class="section-header">Investigation Summary</div>
        <div class="section-body">
            <div class="grid-4">
                <div class="stat-card">
                    <div class="stat-value">{total_deleted}</div>
                    <div class="stat-label">Deleted Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_recovered}</div>
                    <div class="stat-label">Recovered</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{recovery_rate}%</div>
                    <div class="stat-label">Recovery Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{duration}s</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Evidence Details -->
    <div class="section">
        <div class="section-header">Evidence Details</div>
        <div class="section-body grid-2">
            <div>
                <div class="kv"><span class="kv-key">Case ID</span><span class="kv-val">{case_id}</span></div>
                <div class="kv"><span class="kv-key">Examiner</span><span class="kv-val">{examiner}</span></div>
                <div class="kv"><span class="kv-key">Image File</span><span class="kv-val">{image_filename}</span></div>
                <div class="kv"><span class="kv-key">Image Format</span><span class="kv-val">{image_format}</span></div>
                <div class="kv"><span class="kv-key">Image Size</span><span class="kv-val">{image_size_gb} GB ({image_size_bytes:,} bytes)</span></div>
            </div>
            <div>
                <div class="kv"><span class="kv-key">Filesystem</span><span class="kv-val">{filesystem_type}</span></div>
                <div class="kv"><span class="kv-key">Analysis Start</span><span class="kv-val">{investigation_start}</span></div>
                <div class="kv"><span class="kv-key">Analysis End</span><span class="kv-val">{investigation_end}</span></div>
                <div class="kv"><span class="kv-key">Tool</span><span class="kv-val">{tool_name} v{tool_version}</span></div>
                <div class="kv"><span class="kv-key">SHA256 (Image)</span><span class="kv-val hash">{image_sha256}</span></div>
            </div>
        </div>
    </div>

    <!-- Artifacts Table -->
    <div class="section">
        <div class="section-header">Recovered Artifacts ({artifact_count} total)</div>
        <div class="section-body" style="padding:0; overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Identifier</th>
                        <th>Filename</th>
                        <th>FS Type</th>
                        <th>Size</th>
                        <th>Modified</th>
                        <th>Deleted</th>
                        <th>MIME Type</th>
                        <th>Confidence</th>
                        <th>Recovered</th>
                    </tr>
                </thead>
                <tbody>
                {artifact_rows}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Timeline -->
    <div class="section">
        <div class="section-header">Forensic Timeline (most recent 50 events)</div>
        <div class="section-body" style="padding:0; overflow-x:auto;">
            <table>
                <thead>
                    <tr><th>Timestamp</th><th>Event</th><th>Artifact</th><th>Filesystem</th><th>Size</th></tr>
                </thead>
                <tbody>
                {timeline_rows}
                </tbody>
            </table>
        </div>
    </div>

</div>

<div class="footer">
    Generated by {tool_name} v{tool_version} &nbsp;|&nbsp;
    {generation_time} &nbsp;|&nbsp;
    This report contains sensitive forensic evidence. Handle according to your organization's evidence policies.
</div>
</body>
</html>
"""


class ReportGenerator:
    """Generates professional forensic investigation reports in HTML, JSON, and TXT."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, result, formats: list = None) -> dict:
        """Generate reports for an InvestigationResult."""
        formats = formats or ["html", "json", "txt"]
        paths = {}
        safe_case = result.case_id.replace("/", "_").replace("\\", "_").replace(" ", "_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"report_{safe_case}_{ts}"

        if "json" in formats:
            paths["json"] = self._generate_json(result, base_name)
        if "html" in formats:
            paths["html"] = self._generate_html(result, base_name)
        if "txt" in formats:
            paths["txt"] = self._generate_txt(result, base_name)

        logger.info(f"Reports generated: {', '.join(str(p) for p in paths.values())}")
        return paths

    def _generate_json(self, result, base_name: str) -> Path:
        out = self.output_dir / f"{base_name}.json"
        out.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
        return out

    def _generate_html(self, result, base_name: str) -> Path:
        # Build artifact rows
        rows = []
        for i, art in enumerate(result.artifacts, 1):
            m = art.metadata
            v = art.validation
            conf_class = f"confidence-{m.recovery_confidence}"
            rec_class = "recovered-yes" if art.recovered else "recovered-no"
            rec_text = "✓ YES" if art.recovered else "✗ NO"
            rows.append(
                f"<tr>"
                f"<td>{i}</td>"
                f"<td class='hash'>{m.identifier}</td>"
                f"<td>{m.filename or '<em style=\'color:#8899aa\'>unknown</em>'}</td>"
                f"<td><span class='tag'>{m.filesystem_type.upper()}</span></td>"
                f"<td>{m.size_bytes:,}</td>"
                f"<td class='hash'>{m.modified.strftime('%Y-%m-%d %H:%M') if m.modified else '—'}</td>"
                f"<td class='hash'>{m.deleted_time.strftime('%Y-%m-%d %H:%M') if m.deleted_time else '—'}</td>"
                f"<td class='hash'>{m.mime_type}</td>"
                f"<td class='{conf_class}'>{m.recovery_confidence}</td>"
                f"<td class='{rec_class}'>{rec_text}</td>"
                f"</tr>"
            )

        # Timeline rows (last 50)
        tl_rows = []
        for event in result.timeline[-50:]:
            tl_rows.append(
                f"<tr>"
                f"<td class='hash'>{event['timestamp']}</td>"
                f"<td><span class='tag'>{event['event_type']}</span></td>"
                f"<td>{event['artifact']}</td>"
                f"<td>{event['filesystem']}</td>"
                f"<td>{event['size_bytes']:,}</td>"
                f"</tr>"
            )

        img = result.image_info
        html = HTML_TEMPLATE.format(
            case_id=result.case_id,
            examiner=result.examiner,
            filesystem_type=result.filesystem_type.upper(),
            total_deleted=result.total_deleted_found,
            total_recovered=result.total_recovered,
            recovery_rate=f"{result.recovery_rate * 100:.1f}",
            duration=f"{result.duration_seconds:.1f}",
            image_filename=img.get("filename", "N/A"),
            image_format=img.get("format", "N/A"),
            image_size_gb=img.get("size_gb", 0),
            image_size_bytes=img.get("size_bytes", 0),
            image_sha256=img.get("opening_sha256", "N/A"),
            investigation_start=result.investigation_start,
            investigation_end=result.investigation_end,
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            artifact_count=len(result.artifacts),
            artifact_rows="\n".join(rows) or "<tr><td colspan='10' style='text-align:center;color:#8899aa;'>No artifacts found</td></tr>",
            timeline_rows="\n".join(tl_rows) or "<tr><td colspan='5' style='text-align:center;color:#8899aa;'>No timeline events</td></tr>",
            generation_time=datetime.now(timezone.utc).isoformat(),
        )

        out = self.output_dir / f"{base_name}.html"
        out.write_text(html, encoding="utf-8")
        return out

    def _generate_txt(self, result, base_name: str) -> Path:
        lines = [
            "=" * 80,
            f"  FORENSIC INVESTIGATION REPORT",
            f"  Case ID:    {result.case_id}",
            f"  Examiner:   {result.examiner}",
            f"  Tool:       {TOOL_NAME} v{TOOL_VERSION}",
            "=" * 80,
            "",
            "EVIDENCE",
            "-" * 40,
            f"  Image:      {result.image_info.get('filename', 'N/A')}",
            f"  Format:     {result.image_info.get('format', 'N/A')}",
            f"  Size:       {result.image_info.get('size_bytes', 0):,} bytes",
            f"  SHA256:     {result.image_info.get('opening_sha256', 'N/A')}",
            f"  Filesystem: {result.filesystem_type.upper()}",
            "",
            "RESULTS",
            "-" * 40,
            f"  Deleted found:  {result.total_deleted_found}",
            f"  Recovered:      {result.total_recovered}",
            f"  Recovery rate:  {result.recovery_rate:.1%}",
            f"  Duration:       {result.duration_seconds:.2f}s",
            "",
            "ARTIFACTS",
            "-" * 40,
        ]
        for i, art in enumerate(result.artifacts, 1):
            m = art.metadata
            lines.append(
                f"  [{i:04d}] {m.filesystem_type.upper()}:{m.identifier} | "
                f"{'RECOVERED' if art.recovered else 'NOT RECOVERED'} | "
                f"{m.filename or 'unknown'} | "
                f"{m.size_bytes:,} bytes | "
                f"confidence={m.recovery_confidence}"
            )
        lines += [
            "",
            "=" * 80,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            "=" * 80,
        ]

        out = self.output_dir / f"{base_name}.txt"
        out.write_text("\n".join(lines), encoding="utf-8")
        return out
