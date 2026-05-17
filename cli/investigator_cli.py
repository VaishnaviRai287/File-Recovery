import sys
import os
import argparse
import logging
import json
from pathlib import Path
from datetime import datetime, timezone

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import (
    TOOL_NAME, TOOL_VERSION, SUPPORTED_IMAGE_FORMATS,
    SUPPORTED_FILESYSTEMS, LOG_FORMAT, LOG_DATE_FORMAT,
    LOGS_DIR,
)

# ─────────────────────────────────────────────────────────────────────────────
# RICH CONSOLE SUPPORT (optional — graceful fallback if not installed)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import print as rprint
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def setup_logging(level: str = "INFO", log_file: bool = True) -> None:
    """Configure structured logging."""
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOGS_DIR / f"cli_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
    )


def print_banner() -> None:
    """Print the tool banner."""
    banner = (
        "\n"
        "+" + "=" * 68 + "+\n"
        f"|  {TOOL_NAME:<65} |\n"
        f"|  Version {TOOL_VERSION:<61} |\n"
        "|  NTFS | EXT4 | XFS Forensic Recovery Platform"
        + " " * 22 + "|\n"
        "+" + "=" * 68 + "+\n"
    )
    if RICH_AVAILABLE:
        try:
            console.print(banner, style="bold cyan")
        except Exception:
            print(banner)
    else:
        print(banner)


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute a forensic scan and recovery operation."""
    from core.recovery_engine import RecoveryEngine
    from core.report_generator import ReportGenerator

    print_banner()

    if RICH_AVAILABLE:
        console.print(f"\n[bold green]> Starting Investigation[/bold green]")
        console.print(f"  Case ID:   [cyan]{args.case_id}[/cyan]")
        console.print(f"  Examiner:  [cyan]{args.examiner}[/cyan]")
        console.print(f"  Image:     [yellow]{args.image}[/yellow]")
        if args.filesystem:
            console.print(f"  FS Type:   [yellow]{args.filesystem}[/yellow] (manual)")
        console.print()
    else:
        print(f"[*] Case ID: {args.case_id}")
        print(f"[*] Examiner: {args.examiner}")
        print(f"[*] Image: {args.image}")

    try:
        engine = RecoveryEngine(
            case_id=args.case_id,
            examiner=args.examiner,
            output_dir=args.output,
        )
        result = engine.investigate(
            image_path=args.image,
            max_records=args.max_records,
            filesystem_type=args.filesystem,
        )
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"\n[bold red]x Investigation failed:[/bold red] {e}")
        else:
            print(f"[ERROR] Investigation failed: {e}")
        return 1

    # Print summary
    _print_summary(result)

    # Generate reports
    if not args.no_report:
        reporter = ReportGenerator(args.output)
        formats = args.format.split(",") if args.format else ["html", "json", "txt"]
        paths = reporter.generate(result, formats)

        if RICH_AVAILABLE:
            console.print("\n[bold green]> Reports Generated:[/bold green]")
            for fmt, path in paths.items():
                console.print(f"  [{fmt.upper()}] {path}")
        else:
            for fmt, path in paths.items():
                print(f"[*] Report ({fmt}): {path}")

    return 0 if result.total_deleted_found > 0 else 2


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the integrity of a forensic image."""
    from core.image_reader import ForensicImageReader

    print_banner()

    if RICH_AVAILABLE:
        console.print(f"\n[bold yellow]> Verifying Image Integrity[/bold yellow]")
        console.print(f"  Image: [cyan]{args.image}[/cyan]\n")

    try:
        with ForensicImageReader(args.image) as reader:
            info = reader.get_info()
            if RICH_AVAILABLE:
                console.print(f"  [green]+[/green] Image opened successfully")
                console.print(f"  Format:   {info['format']}")
                console.print(f"  Size:     {info['size_gb']:.4f} GB ({info['size_bytes']:,} bytes)")
                console.print(f"  SHA256:   {info['opening_sha256']}")
            else:
                print(f"[*] Format: {info['format']}")
                print(f"[*] Size: {info['size_gb']:.4f} GB")
                print(f"[*] SHA256: {info['opening_sha256']}")

            if args.verify_hash:
                is_ok, opening, current = reader.verify_integrity()
                if RICH_AVAILABLE:
                    if is_ok:
                        console.print(f"\n  [bold green]+ INTEGRITY VERIFIED — Hash unchanged[/bold green]")
                    else:
                        console.print(f"\n  [bold red]x INTEGRITY VIOLATION — Hash changed![/bold red]")
                        console.print(f"    Opening: {opening}")
                        console.print(f"    Current: {current}")
                else:
                    status = "OK" if is_ok else "VIOLATION"
                    print(f"[*] Integrity: {status}")

            if args.json_output:
                print(json.dumps(info, indent=2))

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"\n[red]x Error: {e}[/red]")
        else:
            print(f"[ERROR] {e}")
        return 1

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Show filesystem information from a forensic image without full scanning."""
    from core.image_reader import ForensicImageReader, detect_filesystem_type

    print_banner()
    try:
        with ForensicImageReader(args.image) as reader:
            info = reader.get_info()
            fs_type = detect_filesystem_type(reader)
            info["detected_filesystem"] = fs_type

            if args.json_output:
                print(json.dumps(info, indent=2))
            else:
                if RICH_AVAILABLE:
                    table = Table(title="Image Information", show_header=True)
                    table.add_column("Field", style="cyan")
                    table.add_column("Value", style="white")
                    for k, v in info.items():
                        table.add_row(k, str(v))
                    console.print(table)
                else:
                    for k, v in info.items():
                        print(f"  {k}: {v}")
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1
    return 0


def _print_summary(result) -> None:
    """Print a formatted investigation summary."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold green]=== Investigation Complete ===[/bold green]")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="cyan", width=25)
        table.add_column("Value", style="white")

        table.add_row("Filesystem", result.filesystem_type.upper())
        table.add_row("Deleted Records Found", str(result.total_deleted_found))
        table.add_row("Files Recovered", f"[green]{result.total_recovered}[/green]")
        table.add_row("Recovery Rate", f"{result.recovery_rate:.1%}")
        table.add_row("Duration", f"{result.duration_seconds:.2f}s")
        table.add_row("Avg Confidence", str(result.validation_summary.get("average_confidence", "N/A")))

        console.print(table)

        # Top artifacts
        recovered = [a for a in result.artifacts if a.recovered][:10]
        if recovered:
            console.print(f"\n[bold cyan]Top Recovered Artifacts:[/bold cyan]")
            for art in recovered:
                m = art.metadata
                name = m.filename or f"{m.filesystem_type}:inode:{m.identifier}"
                console.print(
                    f"  [green]+[/green] {name} "
                    f"[dim]({m.size_bytes:,} bytes, {m.recovery_confidence} confidence)[/dim]"
                )
    else:
        print(f"\n[*] Deleted Found: {result.total_deleted_found}")
        print(f"[*] Recovered: {result.total_recovered}")
        print(f"[*] Recovery Rate: {result.recovery_rate:.1%}")
        print(f"[*] Duration: {result.duration_seconds:.2f}s")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="investigator",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Deleted File Recovery Forensics Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python investigator_cli.py scan --image evidence.dd --case IR-2024-001 --examiner "J. Smith"
  python investigator_cli.py scan --image disk.img --filesystem ntfs --format html,json
  python investigator_cli.py verify --image evidence.dd --verify-hash
  python investigator_cli.py info --image disk.img --json

Supported image formats: .dd  .img  .raw  .bin  .e01
Supported filesystems:   ntfs  ext4  xfs  (auto-detected if not specified)
        """
    )

    subparsers = parser.add_subparsers(title="commands", dest="command")

    # ── scan ──
    scan_parser = subparsers.add_parser(
        "scan", help="Run a forensic scan and recovery operation"
    )
    scan_parser.add_argument("--image", "-i", required=True, help="Path to forensic image file")
    scan_parser.add_argument("--case", "-c", dest="case_id", required=True, help="Case ID (e.g. IR-2024-001)")
    scan_parser.add_argument("--examiner", "-e", required=True, help="Examiner name")
    scan_parser.add_argument("--output", "-o", default="./reports", help="Output directory [default: ./reports]")
    scan_parser.add_argument("--filesystem", "-f", choices=SUPPORTED_FILESYSTEMS, help="Force filesystem type (auto-detected if omitted)")
    scan_parser.add_argument("--max-records", type=int, default=100_000, help="Max records to scan [default: 100000]")
    scan_parser.add_argument("--format", default="html,json,txt", help="Report formats (comma-separated: html,json,txt)")
    scan_parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # ── verify ──
    verify_parser = subparsers.add_parser(
        "verify", help="Verify integrity of a forensic image"
    )
    verify_parser.add_argument("--image", "-i", required=True, help="Path to forensic image file")
    verify_parser.add_argument("--verify-hash", action="store_true", help="Recompute and verify SHA256 hash")
    verify_parser.add_argument("--json-output", action="store_true", help="Output as JSON")
    verify_parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # ── info ──
    info_parser = subparsers.add_parser(
        "info", help="Show image metadata and detected filesystem type"
    )
    info_parser.add_argument("--image", "-i", required=True, help="Path to forensic image file")
    info_parser.add_argument("--json-output", "--json", action="store_true", help="Output as JSON")
    info_parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    log_level = getattr(args, "log_level", "INFO")
    setup_logging(log_level)

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "info":
        return cmd_info(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
