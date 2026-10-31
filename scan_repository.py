import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parent
SCANNER = PROJECT_ROOT / "scanner.py"


def validate_github_url(source):
    parsed = urlparse(source)

    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname not in {"github.com", "www.github.com"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Public GitHub repository ka HTTPS URL do, "
            "jaise https://github.com/owner/repository"
        )

    parts = [part for part in parsed.path.strip("/").split("/") if part]

    if len(parts) != 2:
        raise ValueError(
            "Repository page URL do; branch ya file ka URL nahi."
        )

    return source.rstrip("/")


def run_scanner(project_path, args):
    json_report = Path(args.json_report).expanduser().resolve()
    markdown_report = Path(args.markdown_report).expanduser().resolve()
    sarif_report = Path(args.sarif_report).expanduser().resolve()

    for report_path in (json_report, markdown_report, sarif_report):
        report_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(SCANNER),
        str(project_path),
        str(json_report),
        "--markdown-report",
        str(markdown_report),
        "--sarif-report",
        str(sarif_report),
    ]

    if args.ai:
        command.append("--ai")

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
    )

    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Local folder ya public GitHub repository scan karo."
    )
    parser.add_argument(
        "source",
        help="Local project folder ya public GitHub repository HTTPS URL",
    )
    parser.add_argument(
        "--json-report",
        default="audit_report.json",
        help="JSON report ka path",
    )
    parser.add_argument(
        "--markdown-report",
        default="audit_report.md",
        help="Markdown report ka path",
    )
    parser.add_argument(
        "--sarif-report",
        default="audit_report.sarif",
        help="SARIF report ka path",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Optional Ollama explanation enable karo",
    )
    args = parser.parse_args()

    if not SCANNER.is_file():
        print(f"scanner.py nahi mili: {SCANNER}")
        return 2

    source = args.source.strip()

    if "://" in source or source.startswith("git@"):
        try:
            github_url = validate_github_url(source)
        except ValueError as error:
            print(f"URL error: {error}")
            return 2

        try:
            with tempfile.TemporaryDirectory(
                prefix="security_auditor_repo_"
            ) as temporary_directory:
                clone_path = Path(temporary_directory) / "repository"

                print(f"GitHub repository clone ho rahi hai: {github_url}")
                clone_result = subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--single-branch",
                        github_url,
                        str(clone_path),
                    ],
                    check=False,
                )

                if clone_result.returncode != 0:
                    print("GitHub repository clone nahi ho payi.")
                    return clone_result.returncode

                print("Temporary clone par scan shuru...")
                return run_scanner(clone_path, args)

        except FileNotFoundError:
            print("Git command nahi mili. Git install karke dobara try karo.")
            return 2

    local_path = Path(source).expanduser().resolve()

    if not local_path.is_dir():
        print(f"Project folder nahi mila: {local_path}")
        return 2

    print(f"Local project scan ho raha hai: {local_path}")
    return run_scanner(local_path, args)


if __name__ == "__main__":
    raise SystemExit(main())