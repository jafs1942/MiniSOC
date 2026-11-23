
import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent


def run_monitor():
    print("Starting MiniSOC monitoring engine...")
    subprocess.run(
        [sys.executable, str(PROJECT_DIR / "monitor.py")],
        cwd=PROJECT_DIR,
        check=False
    )


def run_dashboard():
    print("Starting MiniSOC dashboard...")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(PROJECT_DIR / "dashboard.py")
        ],
        cwd=PROJECT_DIR,
        check=False
    )


def main():
    parser = argparse.ArgumentParser(
        description="MiniSOC - Windows Security Monitoring Platform"
    )

    parser.add_argument(
        "service",
        choices=["monitor", "dashboard"],
        help="Choose which MiniSOC component to start"
    )

    args = parser.parse_args()

    if args.service == "monitor":
        run_monitor()
    elif args.service == "dashboard":
        run_dashboard()


if __name__ == "__main__":
    main()
