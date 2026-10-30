import argparse
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

from dependencies import parse_requirements


PIN_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]+\])?\s*==\s*([^\s;#]+)"
)

SUPPORTED_LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
}


def is_supported_manifest(relative_path):
    """Sirf supported dependency manifest aur lockfiles allow karta hai."""
    filename = relative_path.name.lower()

    if filename in SUPPORTED_LOCKFILES or filename == "package.json":
        return True

    return (
        filename.startswith("requirements")
        and relative_path.suffix.lower() == ".txt"
    )


def get_patch_paths(patch_text):
    """Patch mein badle ja rahe supported files dhoondhta hai."""
    paths = []

    for line in patch_text.splitlines():
        if not line.startswith("+++ b/"):
            continue

        value = line[len("+++ b/"):].strip()

        if value == "/dev/null":
            continue

        relative_path = PurePosixPath(value)

        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(
                f"Patch mein unsafe file path mila: {value}"
            )

        if is_supported_manifest(relative_path):
            paths.append(relative_path.as_posix())

    return sorted(set(paths))


def paths_needed_for_validation(patch_paths):
    """
    Lockfile ke saath usi folder ka package.json bhi copy karta hai,
    chahe patch ne package.json ko badla na ho.
    """
    result = set(patch_paths)

    for value in patch_paths:
        relative_path = PurePosixPath(value)

        if relative_path.name.lower() in SUPPORTED_LOCKFILES:
            sibling_manifest = (
                relative_path.parent / "package.json"
            ).as_posix()
            result.add(sibling_manifest)

    return sorted(result)


def source_parts(source_value):
    """Merged source field ko alag relative paths mein baantta hai."""
    if isinstance(source_value, list):
        values = source_value
    else:
        values = str(source_value or "").split(",")

    return {
        str(value).strip()
        for value in values
        if str(value).strip()
    }


def package_inventory(project_root, package_sources):
    """
    Supported lockfiles/requirements files se package version inventory banata hai.

    Key mein ecosystem, package name aur source file hain.
    """
    inventory = {}

    for package in parse_requirements(project_root):
        package_sources_found = (
            source_parts(package.get("source", ""))
            & package_sources
        )

        for source in package_sources_found:
            key = (
                package.get("ecosystem", "PyPI"),
                package.get("name", ""),
                source,
            )

            inventory.setdefault(key, set()).add(
                str(package.get("version", ""))
            )

    return inventory


def query_osv(package_name, version, ecosystem):
    """OSV se ecosystem-specific package/version advisories mangta hai."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "security-test-scanner",
        },
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


def validate_lockfile_json(project_root, relative_paths):
    """Changed npm lockfiles ka JSON parse check karta hai."""
    checked = []

    for value in relative_paths:
        relative_path = PurePosixPath(value)

        if relative_path.name.lower() not in SUPPORTED_LOCKFILES:
            continue

        file_path = project_root.joinpath(
            *relative_path.parts
        )

        try:
            data = json.loads(
                file_path.read_text(encoding="utf-8-sig")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"{value} valid JSON nahi hai: {error}"
            ) from error

        if not isinstance(data, dict):
            raise RuntimeError(
                f"{value} ka root JSON object nahi hai."
            )

        if not (
            isinstance(data.get("packages"), dict)
            or isinstance(data.get("dependencies"), dict)
        ):
            raise RuntimeError(
                f"{value} mein npm package records nahi mile."
            )

        checked.append(value)

    return checked


def npm_name_from_lock_path(package_path):
    """package-lock ke node_modules path se npm package name nikalta hai."""
    parts = str(package_path).replace("\\", "/").split("/")
    indexes = [
        index
        for index, part in enumerate(parts)
        if part == "node_modules"
    ]

    if not indexes:
        return None

    package_parts = parts[indexes[-1] + 1:]

    if not package_parts:
        return None

    if package_parts[0].startswith("@"):
        if len(package_parts) < 2:
            return None
        return f"{package_parts[0]}/{package_parts[1]}"

    return package_parts[0]


def find_deprecated_npm_packages(project_root, relative_paths):
    """Lockfile mein deprecated package versions report karta hai."""
    deprecated = []

    def inspect_package(package_name, item, source):
        if not isinstance(item, dict) or not package_name:
            return

        reason = item.get("deprecated")

        if reason:
            deprecated.append({
                "ecosystem": "npm",
                "package": package_name,
                "version": str(item.get("version", "unknown")),
                "source": source,
                "reason": str(reason),
            })

    for value in relative_paths:
        relative_path = PurePosixPath(value)

        if relative_path.name.lower() not in SUPPORTED_LOCKFILES:
            continue

        lock_path = project_root.joinpath(*relative_path.parts)

        try:
            data = json.loads(
                lock_path.read_text(encoding="utf-8-sig")
            )
        except (OSError, json.JSONDecodeError):
            continue

        lock_packages = data.get("packages")

        if isinstance(lock_packages, dict) and lock_packages:
            for package_path, item in lock_packages.items():
                if not package_path or not isinstance(item, dict):
                    continue

                package_name = (
                    item.get("name")
                    or npm_name_from_lock_path(package_path)
                )
                inspect_package(package_name, item, value)
            continue

        def walk_legacy(dependencies):
            if not isinstance(dependencies, dict):
                return

            for package_name, item in dependencies.items():
                if not isinstance(item, dict):
                    continue

                inspect_package(package_name, item, value)
                walk_legacy(item.get("dependencies", {}))

        walk_legacy(data.get("dependencies", {}))

    return deprecated


def pair_changed_versions(before_inventory, after_inventory):
    """Version inventory mein aaye aur gaye versions nikaalta hai."""
    changes = []

    all_keys = set(before_inventory) | set(after_inventory)

    for ecosystem, package_name, source in sorted(all_keys):
        before_versions = before_inventory.get(
            (ecosystem, package_name, source),
            set(),
        )
        after_versions = after_inventory.get(
            (ecosystem, package_name, source),
            set(),
        )

        removed_versions = sorted(before_versions - after_versions)
        added_versions = sorted(after_versions - before_versions)

        if not removed_versions and not added_versions:
            continue

        for index, old_version in enumerate(removed_versions):
            if added_versions:
                new_version = added_versions[
                    min(index, len(added_versions) - 1)
                ]
            else:
                new_version = None

            changes.append({
                "ecosystem": ecosystem,
                "package": package_name,
                "source": source,
                "version_before": old_version,
                "version_after": new_version,
                "advisories_before": [],
                "advisories_after": [],
                "errors": [],
            })

        # Agar package pehle nahi tha aur patch mein add hua ho.
        if not removed_versions:
            for new_version in added_versions:
                changes.append({
                    "ecosystem": ecosystem,
                    "package": package_name,
                    "source": source,
                    "version_before": None,
                    "version_after": new_version,
                    "advisories_before": [],
                    "advisories_after": [],
                    "errors": [],
                })

    return changes


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Dependency patch ko temporary copy mein apply karke "
            "Python/npm package versions ko OSV se validate karein."
        )
    )
    parser.add_argument(
        "project_folder",
        help=r"Project folder, jaise .\demo_npm",
    )
    parser.add_argument(
        "patch_file",
        help=r"Patch file, jaise .\dependency_update_suggestions.patch",
    )
    args = parser.parse_args()

    project_folder = Path(args.project_folder).resolve()
    patch_file = Path(args.patch_file).resolve()

    if not project_folder.is_dir():
        raise SystemExit(
            f"Project folder nahi mila: {project_folder}"
        )

    if not patch_file.is_file():
        raise SystemExit(
            f"Patch file nahi mili: {patch_file}"
        )

    git_path = shutil.which("git")

    if not git_path:
        raise SystemExit(
            "Git install nahi hai ya PATH mein nahi mila."
        )

    patch_text = patch_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    try:
        patch_paths = get_patch_paths(patch_text)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    if not patch_paths:
        raise SystemExit(
            "Patch mein supported requirements ya npm files nahi mili."
        )

    copy_paths = paths_needed_for_validation(patch_paths)
    original_files = {}

    for value in copy_paths:
        relative_path = PurePosixPath(value)
        source_path = project_folder.joinpath(
            *relative_path.parts
        ).resolve()

        try:
            source_path.relative_to(project_folder)
        except ValueError:
            raise SystemExit(
                f"Project folder ke bahar ka path reject hua: {value}"
            )

        # package.json sibling absent ho sakta hai agar sirf lockfile patch ho.
        if not source_path.is_file():
            is_required_patch_file = value in patch_paths

            if is_required_patch_file:
                raise SystemExit(
                    f"Project mein file nahi mili: {source_path}"
                )

            continue

        original_files[value] = source_path

    package_sources = {
        value
        for value in patch_paths
        if (
            PurePosixPath(value).name.lower()
            in SUPPORTED_LOCKFILES
            or (
                PurePosixPath(value).name.lower().startswith("requirements")
                and PurePosixPath(value).suffix.lower() == ".txt"
            )
        )
    }

    if not package_sources:
        raise SystemExit(
            "Patch mein requirements file ya npm lockfile nahi mili."
        )

    before_inventory = package_inventory(
        project_folder,
        package_sources,
    )

    with tempfile.TemporaryDirectory(
        prefix="patch_validator_",
    ) as temporary_folder:
        temporary_root = Path(temporary_folder)
        deprecated_packages = []
        checked_lockfiles = []
        package_results = []
        all_queries_succeeded = True

        for value, source_path in original_files.items():
            relative_path = PurePosixPath(value)
            destination = temporary_root.joinpath(
                *relative_path.parts
            )
            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            # Temporary copy ko LF mein normalize karo, warna Windows
            # CRLF/core.autocrlf settings unified diff context mismatch kar
            # sakti hain. Asli project file untouched rehti hai.
            source_text = source_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            with destination.open(
                "w",
                encoding="utf-8",
                newline="\n",
            ) as destination_file:
                destination_file.write(source_text)

        normalized_patch = temporary_root / ".validation.patch"
        normalized_patch_text = (
            patch_text.replace("\r\n", "\n").replace("\r", "\n")
        )
        with normalized_patch.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as patch_handle:
            patch_handle.write(normalized_patch_text)

        init_result = subprocess.run(
            [
                git_path,
                "-c",
                "core.autocrlf=false",
                "init",
                "--quiet",
            ],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )

        if init_result.returncode != 0:
            raise SystemExit(
                "Temporary Git setup fail hua: "
                f"{init_result.stderr.strip()}"
            )

        check_result = subprocess.run(
            [
                git_path,
                "-c",
                "core.autocrlf=false",
                "apply",
                "--recount",
                "--ignore-space-change",
                "--check",
                str(normalized_patch),
            ],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )

        if check_result.returncode != 0:
            message = (
                check_result.stderr.strip()
                or check_result.stdout.strip()
            )
            raise SystemExit(
                f"Patch check fail hua:\n{message}"
            )

        apply_result = subprocess.run(
            [
                git_path,
                "-c",
                "core.autocrlf=false",
                "apply",
                "--recount",
                "--ignore-space-change",
                str(normalized_patch),
            ],
            cwd=temporary_root,
            capture_output=True,
            text=True,
        )

        if apply_result.returncode != 0:
            message = (
                apply_result.stderr.strip()
                or apply_result.stdout.strip()
            )
            raise SystemExit(
                f"Temporary copy par patch apply nahi hua:\n{message}"
            )

        checked_lockfiles = validate_lockfile_json(
            temporary_root,
            patch_paths,
        )

        all_deprecated_packages = find_deprecated_npm_packages(
            temporary_root,
            checked_lockfiles,
        )

        after_inventory = package_inventory(
            temporary_root,
            package_sources,
        )

        package_results = pair_changed_versions(
            before_inventory,
            after_inventory,
        )

        if not package_results:
            raise SystemExit(
                "Patch apply hui, lekin package version change detect nahi hua."
            )

        changed_npm_versions = {
            (item["ecosystem"], item["package"], item["version_after"])
            for item in package_results
            if (
                str(item["ecosystem"]).lower() == "npm"
                and item["version_after"]
            )
        }
        deprecated_packages = [
            item
            for item in all_deprecated_packages
            if (
                "npm",
                item["package"],
                item["version"],
            ) in changed_npm_versions
        ]

        if not deprecated_packages:
            for item in package_results:
                ecosystem = item["ecosystem"]
                package_name = item["package"]

                if item["version_before"]:
                    try:
                        item["advisories_before"] = query_osv(
                            package_name,
                            item["version_before"],
                            ecosystem,
                        )
                    except Exception as error:
                        all_queries_succeeded = False
                        item["errors"].append(
                            f"Before OSV lookup: {error}"
                        )

                if item["version_after"]:
                    try:
                        item["advisories_after"] = query_osv(
                            package_name,
                            item["version_after"],
                            ecosystem,
                        )
                    except Exception as error:
                        all_queries_succeeded = False
                        item["errors"].append(
                            f"After OSV lookup: {error}"
                        )

    advisories_remain = any(
        item["advisories_after"]
        for item in package_results
    )
    advisories_were_present = any(
        item["advisories_before"]
        for item in package_results
    )

    if deprecated_packages:
        status = "patch_rejected_deprecated_npm_version"
    elif not all_queries_succeeded:
        status = "patch_applied_but_osv_check_incomplete"
    elif advisories_remain:
        status = "patch_applied_but_advisories_remain"
    elif advisories_were_present:
        status = "no_matching_advisories_found_after_patch"
    else:
        status = "patch_applied_no_matching_advisories_found"

    report = {
        "project_folder": str(project_folder),
        "patch_file": str(patch_file),
        "patch_applied_to": "temporary copy only",
        "checked_lockfiles": checked_lockfiles,
        "deprecated_packages": deprecated_packages,
        "status": status,
        "packages": package_results,
    }

    report_path = Path.cwd() / "patch_validation_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        "Patch temporary copy par apply hui. "
        "Asli project change nahi hua."
    )
    print(f"Validation status: {status}")

    for package in deprecated_packages:
        print(
            f"  REJECTED: {package['package']}@{package['version']} "
            f"deprecated hai: {package['reason']}"
        )

    for item in package_results:
        ecosystem = item["ecosystem"]
        print(
            f"\n[{ecosystem}] {item['package']}: "
            f"{item['version_before']} -> {item['version_after']}"
        )
        print(
            f"  Advisories before: "
            f"{len(item['advisories_before'])}"
        )
        print(
            f"  Advisories after:  "
            f"{len(item['advisories_after'])}"
        )

        for advisory in item["advisories_after"]:
            print(
                f"  Remaining: {advisory.get('id')} - "
                f"{advisory.get('summary')}"
            )

        for error in item["errors"]:
            print(f"  OSV check issue: {error}")

    print(f"\nJSON report save hui: {report_path}")

    if deprecated_packages:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
