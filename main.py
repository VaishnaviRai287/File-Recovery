import sys
import argparse
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config.settings import TOOL_NAME, TOOL_VERSION, LOG_FORMAT, LOG_DATE_FORMAT


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main():
    parser = argparse.ArgumentParser(
        prog="forensics_tool",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Deleted File Recovery for NTFS, EXT4, XFS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  CLI mode (default):
    python main.py scan --image evidence.dd --case IR-001 --examiner "J. Smith"
    python main.py verify --image evidence.dd
    python main.py info --image evidence.dd

  GUI mode:
    python main.py --gui

Examples:
  python main.py scan --image sample_images/ntfs_demo.dd --case TEST-001 --examiner Demo
  python main.py --gui
        """
    )
    parser.add_argument("--gui", action="store_true", help="Launch the PyQt GUI dashboard")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")

    # Parse only the first argument to check for --gui
    args, remaining = parser.parse_known_args()

    setup_logging()

    if args.gui:
        from gui.forensic_gui import launch_gui
        launch_gui()
    else:
        # Pass all remaining args to the CLI
        sys.argv = [sys.argv[0]] + remaining
        from cli.investigator_cli import main as cli_main
        sys.exit(cli_main())


if __name__ == "__main__":
    main()
