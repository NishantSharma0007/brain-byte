import argparse
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath


PIN_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]+\])?\s*==\s*([^\s;#]+)"
)


def get_patch_paths(patch_text):
    """Patch me badle ja rahe requirements*.txt files dhoondhta hai."""
    paths = []

    for line in patch_text.splitlines():
        if not line.startswith("+++ b/"):
            continue

        relative_path = line[len("+++ b/"):].strip()
        if relative_path == "/dev/null":
            continue

        posix_path = PurePosixPath(relative_path)

        # Project folder ke bahar jaane wale paths ko reject karo.
        if posix_path.is_absolute() or ".." in posix_path.parts:
            raise ValueError(f"Patch me unsafe file path mila: {relative_path}")

        filename = posix_path.name.lower()
        if filename.startswith("requirements") and filename.endswith(".txt"):
            paths.append(posix_path.as_posix())

    return sorted(set(paths))


def read_pins(manifest_paths):
    """Requirements files se exactly pinned package versions padhta hai."""
    packages = {}

    for relative_path, file_path in manifest_paths.items():
        if not file_path.exists():
            continue

        try:
            lines = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        except OSError as error:
            print(f"File nahi padh paayi: {relative_path}: {error}")
            continue

        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue

            match = PIN_PATTERN.match(line)
            if not match:
                continue

            package_name = match.group(1)
            version = match.group(2).strip()
            normalized_name = re.sub(r"[-_.]+", "-", package_name).lower()

            packages[normalized_name] = {
                "name": package_name,
                "version": version,
                "file": relative_path,
                "line": line_number,
            }

    return packages


def query_osv(package_name, version):
    """OSV database se Python package/version ke advisories mangta hai."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        },
        "version": version,
    }

    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.loads(response.read().decode("utf-8"))

    advisories = []
    for vulnerability in result.get("vulns", []):
        advisories.append({
            "id": vulnerability.get("id"),
            "aliases": vulnerability.get("aliases", []),
            "summary": vulnerability.get("summary", ""),
        })

    return advisories


def main():
    parser = argparse.ArgumentParser(
        description="Dependency patch ko temporary copy me apply karke validate karein."
    )
    parser.add_argument("project_folder", help="Project folder, jaise .\\demo_project")
    parser.add_argument("patch_file", help="Patch file, jaise .\\dependency_update_suggestions.patch")
    args = parser.parse_args()

    project_folder = Path(args.project_folder).resolve()
    patch_file = Path(args.patch_file).resolve()

    if not project_folder.is_dir():
        raise SystemExit(f"Project folder nahi mila: {project_folder}")

    if not patch_file.is_file():
        raise SystemExit(f"Patch file nahi mili: {patch_file}")

    git_path = shutil.which("git")
    if not git_path:
        raise SystemExit("Git install nahi hai ya PATH me nahi mila.")

    patch_text = patch_file.read_text(encoding="utf-8", errors="replace")
    target_paths = get_patch_paths(patch_text)

    if not target_paths:
        raise SystemExit(
            "Patch me requirements*.txt file nahi mili. "
            "Yeh validator requirements.txt patch ke liye hai."
        )

    original_manifests = {}

    for relative_path in target_paths:
        source_path = (project_folder / Path(*PurePosixPath(relative_path).parts)).resolve()

        try:
            source_path.relative_to(project_folder)
        except ValueError:
            raise SystemExit(f"Project folder ke bahar ka path reject hua: {relative_path}")

        if not source_path.is_file():
            raise SystemExit(f"Project me file nahi mili: {source_path}")

        original_manifests[relative_path] = source_path

    before_packages = read_pins(original_manifests)

    # Patch ko asli project par nahi, temporary folder ki copy par apply karte hain.
    with tempfile.TemporaryDirectory(prefix="patch_validator_") as temporary_folder:
        temporary_root = Path(temporary_folder)
        temporary_manifests = {}

        for relative_path, source_path in original_manifests.items():
            destination = temporary_root / Path(*PurePosixPath(relative_path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
            temporary_manifests[relative_path] = destination

        init_result = subprocess.run(
            [git_path, "init", "--quiet"],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )
        if init_result.returncode != 0:
            raise SystemExit(f"Temporary Git setup fail hua: {init_result.stderr.strip()}")

        check_result = subprocess.run(
            [git_path, "apply", "--check", str(patch_file)],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )
        if check_result.returncode != 0:
            message = check_result.stderr.strip() or check_result.stdout.strip()
            raise SystemExit(f"Patch check fail hua:\n{message}")

        apply_result = subprocess.run(
            [git_path, "apply", str(patch_file)],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )
        if apply_result.returncode != 0:
            message = apply_result.stderr.strip() or apply_result.stdout.strip()
            raise SystemExit(f"Temporary copy par patch apply nahi hua:\n{message}")

        after_packages = read_pins(temporary_manifests)

        changed_names = sorted(
            name
            for name in set(before_packages) | set(after_packages)
            if (
                before_packages.get(name, {}).get("version")
                != after_packages.get(name, {}).get("version")
            )
        )

        if not changed_names:
            raise SystemExit("Patch ke baad koi pinned package version change nahi mila.")

        package_results = []
        all_queries_succeeded = True

        for normalized_name in changed_names:
            before = before_packages.get(normalized_name)
            after = after_packages.get(normalized_name)

            item = {
                "package": (
                    after.get("name") if after else before.get("name")
                ),
                "version_before": before.get("version") if before else None,
                "version_after": after.get("version") if after else None,
                "advisories_before": [],
                "advisories_after": [],
                "errors": [],
            }

            if before:
                try:
                    item["advisories_before"] = query_osv(
                        before["name"],
                        before["version"],
                    )
                except Exception as error:
                    all_queries_succeeded = False
                    item["errors"].append(f"Before OSV lookup: {error}")

            if after:
                try:
                    item["advisories_after"] = query_osv(
                        after["name"],
                        after["version"],
                    )
                except Exception as error:
                    all_queries_succeeded = False
                    item["errors"].append(f"After OSV lookup: {error}")

            package_results.append(item)

    remaining_advisories = any(
        item["advisories_after"] for item in package_results
    )
    previous_advisories = any(
        item["advisories_before"] for item in package_results
    )

    if not all_queries_succeeded:
        status = "patch_applied_but_osv_check_incomplete"
    elif remaining_advisories:
        status = "patch_applied_but_advisories_remain"
    elif previous_advisories:
        status = "no_matching_advisories_found_after_patch"
    else:
        status = "patch_applied_no_matching_advisories_found"

    report = {
        "project_folder": str(project_folder),
        "patch_file": str(patch_file),
        "patch_applied_to": "temporary copy only",
        "status": status,
        "packages": package_results,
    }

    report_path = Path.cwd() / "patch_validation_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Patch temporary copy par apply hui. Asli project change nahi hua.")
    print(f"Validation status: {status}")

    for item in package_results:
        print(
            f"\n{item['package']}: "
            f"{item['version_before']} -> {item['version_after']}"
        )
        print(f"  Advisories before: {len(item['advisories_before'])}")
        print(f"  Advisories after:  {len(item['advisories_after'])}")

        for advisory in item["advisories_after"]:
            print(f"  Remaining: {advisory.get('id')} - {advisory.get('summary')}")

        for error in item["errors"]:
            print(f"  OSV check issue: {error}")

    print(f"\nJSON report save hui: {report_path}")


if __name__ == "__main__":
    main()