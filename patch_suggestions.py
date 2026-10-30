import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from dependencies import normalize_name, parse_requirements
from osv_lookup import lookup_osv


REQUIREMENT_PIN_PATTERN = re.compile(
    r"^(?P<prefix>\s*"
    r"(?P<name>[A-Za-z0-9_.-]+)"
    r"(?:\[[A-Za-z0-9_,.-]+\])?"
    r"\s*==\s*)"
    r"(?P<version>[^\s;#]+)"
    r"(?P<suffix>.*)$"
)

NPM_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

COPY_IGNORE_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
}


def version_key(version):
    """Version string se numeric parts nikaal kar compare karta hai."""
    parts = re.findall(r"\d+", str(version))

    if not parts:
        return None

    return tuple(int(part) for part in parts)


def package_key(ecosystem, package_name):
    """Package key mein ecosystem rakhta hai, taaki PyPI/npm mix na hon."""
    ecosystem = str(ecosystem or "PyPI")

    if ecosystem.lower() == "pypi":
        return "PyPI", normalize_name(package_name)

    if ecosystem.lower() == "npm":
        return "npm", str(package_name).strip()

    return ecosystem, str(package_name).strip()


def split_sources(source_value):
    """Advisory ke ek ya kai source paths ko list mein badalta hai."""
    if isinstance(source_value, list):
        values = source_value
    else:
        values = str(source_value or "").split(",")

    return [
        str(value).strip()
        for value in values
        if str(value).strip()
    ]


def safe_project_path(project_root, source):
    """Project ke bahar jaane wale advisory paths ko reject karta hai."""
    candidate = Path(source)

    if not candidate.is_absolute():
        candidate = project_root / candidate

    try:
        resolved = candidate.resolve()
        relative = resolved.relative_to(project_root.resolve())
    except (OSError, ValueError):
        return None, None

    if not resolved.is_file():
        return None, None

    return relative, resolved


def highest_fixed_version(advisory):
    """OSV fixed events mein se highest numeric fixed version chunta hai."""
    fixed_versions = []

    for event in advisory.get("fixed_events", []):
        range_type = str(event.get("range_type", "")).upper()
        value = event.get("value")

        if not value or range_type not in {"ECOSYSTEM", "SEMVER"}:
            continue

        key = version_key(value)

        if key:
            fixed_versions.append((key, str(value)))

    if not fixed_versions:
        return None

    fixed_versions.sort(key=lambda item: item[0])
    return fixed_versions[-1][1]


def build_update_targets(advisories):
    """
    Advisory records ko package update targets mein group karta hai.

    Ek package ke kai advisories hon to un sabko cover karne wala
    highest fixed version target banta hai.
    """
    targets = {}

    for advisory in advisories:
        package_name = advisory.get("package")

        if not package_name:
            continue

        ecosystem = advisory.get("ecosystem", "PyPI")
        key = package_key(ecosystem, package_name)
        fixed_version = highest_fixed_version(advisory)

        if not fixed_version:
            continue

        old_version = advisory.get("version")
        existing = targets.get(key)

        if existing is None:
            existing = {
                "ecosystem": ecosystem,
                "name": package_name,
                "version": fixed_version,
                "old_versions": set(),
            }
            targets[key] = existing
        else:
            current_key = version_key(existing["version"])
            new_key = version_key(fixed_version)

            if current_key and new_key and new_key > current_key:
                existing["version"] = fixed_version

        if old_version:
            existing["old_versions"].add(str(old_version))

    return targets


def requirement_sources(advisory, project_root):
    """Advisory source mein se requirements*.txt files dhoondhta hai."""
    for source in split_sources(advisory.get("source", "")):
        relative_path, full_path = safe_project_path(
            project_root,
            source,
        )

        if relative_path is None:
            continue

        filename = relative_path.name.lower()

        if (
            filename.startswith("requirements")
            and relative_path.suffix.lower() == ".txt"
        ):
            yield relative_path, full_path


def npm_lock_sources(advisory, project_root):
    """Advisory source mein se npm lockfile dhoondhta hai."""
    for source in split_sources(advisory.get("source", "")):
        relative_path, full_path = safe_project_path(
            project_root,
            source,
        )

        if relative_path is None:
            continue

        if relative_path.name.lower() in {
            "package-lock.json",
            "npm-shrinkwrap.json",
        }:
            yield relative_path, full_path


def update_requirements_text(text, targets):
    """requirements file mein exact == version pins update karta hai."""
    updated_lines = []
    changes = []

    for line_number, original_line in enumerate(
        text.splitlines(keepends=True),
        start=1,
    ):
        if original_line.endswith("\r\n"):
            line_content = original_line[:-2]
            line_ending = "\r\n"
        elif original_line.endswith("\n"):
            line_content = original_line[:-1]
            line_ending = "\n"
        elif original_line.endswith("\r"):
            line_content = original_line[:-1]
            line_ending = "\r"
        else:
            line_content = original_line
            line_ending = ""

        match = REQUIREMENT_PIN_PATTERN.match(line_content)

        if not match:
            updated_lines.append(original_line)
            continue

        key = normalize_name(match.group("name"))
        target = targets.get(key)

        if not target:
            updated_lines.append(original_line)
            continue

        old_version = match.group("version")
        new_version = target["version"]

        if old_version == new_version:
            updated_lines.append(original_line)
            continue

        updated_lines.append(
            f"{match.group('prefix')}"
            f"{new_version}"
            f"{match.group('suffix')}"
            f"{line_ending}"
        )

        changes.append({
            "package": target["name"],
            "old_version": old_version,
            "new_version": new_version,
            "line": line_number,
        })

    return "".join(updated_lines), changes


def update_npm_manifest(manifest_path, targets):
    """
    Temporary package.json mein direct dependency ya npm override set karta hai.

    Direct dependencies exact fixed version par set hoti hain.
    Transitive dependencies ke liye root-level npm override use hota hai.
    """
    try:
        original_text = manifest_path.read_text(
            encoding="utf-8-sig",
        )
        data = json.loads(original_text)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"package.json parse nahi hui: {error}") from error

    if not isinstance(data, dict):
        raise RuntimeError("package.json ka root JSON object nahi hai.")

    for package_name, target in targets.items():
        fixed_version = target["version"]
        is_direct = False

        for section_name in NPM_DEPENDENCY_SECTIONS:
            section = data.get(section_name)

            if isinstance(section, dict) and package_name in section:
                section[package_name] = fixed_version
                is_direct = True

        overrides = data.get("overrides")

        if not isinstance(overrides, dict):
            overrides = {}
            data["overrides"] = overrides

        # Existing conflicting override ko bhi fixed version par set karo.
        current_override = overrides.get(package_name)

        if isinstance(current_override, dict):
            current_override["."] = fixed_version
        else:
            overrides[package_name] = fixed_version

        if is_direct:
            # Direct package exact version par set hai. NPM override bhi wahi
            # version rakhta hai, taaki transitive copies bhi update ho saken.
            pass

    updated_text = json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    return original_text, updated_text


def unified_file_diff(relative_path, original_text, updated_text):
    """Do text versions ke beech git apply compatible diff banata hai."""
    if original_text == updated_text:
        return ""

    diff_lines = difflib.unified_diff(
        original_text.splitlines(),
        updated_text.splitlines(),
        fromfile=f"a/{relative_path.as_posix()}",
        tofile=f"b/{relative_path.as_posix()}",
        lineterm="",
    )

    result = "\n".join(diff_lines)

    if result:
        path = relative_path.as_posix()
        result = (
            f"diff --git a/{path} b/{path}\n"
            f"{result}\n"
        )

    return result


def copy_ignore(directory, names):
    """Temporary npm copy mein heavy/generated folders skip karta hai."""
    ignored = []

    for name in names:
        if name in COPY_IGNORE_NAMES:
            ignored.append(name)

    return ignored


def npm_command(npm_path):
    """Windows par npm.cmd ko cmd ke through chalata hai."""
    if os.name == "nt" and npm_path.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", npm_path]

    return [npm_path]


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


def deprecated_npm_entries(lock_text, targets):
    """Find OSV-target npm versions marked deprecated by the registry."""
    try:
        data = json.loads(lock_text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"npm-generated lockfile JSON parse nahi hui: {error}"
        ) from error

    entries = []

    def record_if_deprecated(package_name, item):
        if not package_name or not isinstance(item, dict):
            return

        target = targets.get(package_name)

        if not target:
            return

        if str(item.get("version", "")) != target["version"]:
            return

        reason = item.get("deprecated")

        if reason:
            entries.append({
                "package": package_name,
                "version": target["version"],
                "reason": str(reason),
            })

    lock_packages = data.get("packages")

    if isinstance(lock_packages, dict) and lock_packages:
        for package_path, item in lock_packages.items():
            if not package_path or not isinstance(item, dict):
                continue

            package_name = (
                item.get("name")
                or npm_name_from_lock_path(package_path)
            )
            record_if_deprecated(package_name, item)
    else:
        def walk_legacy(dependencies):
            if not isinstance(dependencies, dict):
                return

            for package_name, item in dependencies.items():
                if not isinstance(item, dict):
                    continue

                record_if_deprecated(package_name, item)
                walk_legacy(item.get("dependencies", {}))

        walk_legacy(data.get("dependencies", {}))

    return entries


def create_npm_patch(
    project_root,
    lock_relative_path,
    lock_full_path,
    npm_targets,
):
    """
    Temporary project copy mein package.json update karta hai,
    npm se lockfile regenerate karta hai, phir patch text return karta hai.
    """
    npm_path = shutil.which("npm")

    if not npm_path:
        print(
            "npm patch skip hui: npm command install/PATH mein nahi mila."
        )
        return ""

    package_root = lock_full_path.parent
    manifest_path = package_root / "package.json"

    if not manifest_path.is_file():
        print(
            f"npm patch skip hui: {manifest_path} nahi mili."
        )
        return ""

    try:
        manifest_relative = manifest_path.resolve().relative_to(
            project_root.resolve()
        )
        lock_relative = lock_full_path.resolve().relative_to(
            project_root.resolve()
        )
    except ValueError:
        print("npm patch skip hui: lockfile project folder ke bahar hai.")
        return ""

    try:
        with tempfile.TemporaryDirectory(
            prefix="security_auditor_npm_",
        ) as temporary_folder:
            temporary_root = Path(temporary_folder) / "project"

            shutil.copytree(
                package_root,
                temporary_root,
                ignore=copy_ignore,
            )

            temporary_manifest = temporary_root / "package.json"
            temporary_lock = temporary_root / lock_full_path.name

            original_manifest, updated_manifest = update_npm_manifest(
                temporary_manifest,
                npm_targets,
            )

            temporary_manifest.write_text(
                updated_manifest,
                encoding="utf-8",
            )

            if not temporary_lock.is_file():
                print(
                    f"npm patch skip hui: temporary copy mein "
                    f"{lock_full_path.name} nahi mili."
                )
                return ""

            environment = os.environ.copy()
            environment["npm_config_ignore_scripts"] = "true"
            environment["npm_config_audit"] = "false"
            environment["npm_config_fund"] = "false"
            environment["npm_config_update_notifier"] = "false"

            command = npm_command(npm_path) + [
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--no-progress",
            ]

            try:
                result = subprocess.run(
                    command,
                    cwd=temporary_root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                print("npm patch skip hui: npm lockfile update timeout ho gayi.")
                return ""

            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                if detail:
                    detail = detail[-1500:]
                    print(f"npm lockfile update fail hui:\n{detail}")
                else:
                    print("npm lockfile update fail hui.")
                return ""

            generated_lock = temporary_lock.read_text(
                encoding="utf-8-sig",
            )

            deprecated_entries = deprecated_npm_entries(
                generated_lock,
                npm_targets,
            )

            if deprecated_entries:
                for entry in deprecated_entries:
                    print(
                        "npm patch reject hui: "
                        f"{entry['package']}@{entry['version']} "
                        f"deprecated hai: {entry['reason']}"
                    )
                print(
                    "Deprecated target ke liye automatic patch nahi bani. "
                    "Version ko manually review karo."
                )
                return ""

            original_lock = lock_full_path.read_text(
                encoding="utf-8-sig",
            )

            parts = []

            manifest_diff = unified_file_diff(
                manifest_relative,
                original_manifest,
                updated_manifest,
            )
            if manifest_diff:
                parts.append(manifest_diff)

            lock_diff = unified_file_diff(
                lock_relative,
                original_lock,
                generated_lock,
            )
            if lock_diff:
                parts.append(lock_diff)

            return "\n".join(parts)

    except (OSError, RuntimeError, shutil.Error) as error:
        print(f"npm patch create nahi hui: {error}")
        return ""


def create_patch(project_folder, advisories, output_file):
    project_root = Path(project_folder).resolve()
    targets = build_update_targets(advisories)

    if not targets:
        print("OSV se koi fixed version nahi mila; patch nahi bani.")
        return None

    python_targets = {
        key_name: target
        for (ecosystem, key_name), target in targets.items()
        if ecosystem == "PyPI"
    }

    npm_targets = {
        key_name: target
        for (ecosystem, key_name), target in targets.items()
        if ecosystem.lower() == "npm"
    }

    requirements_plans = {}

    for advisory in advisories:
        ecosystem = advisory.get("ecosystem", "PyPI")

        if str(ecosystem).lower() != "pypi":
            continue

        package_name = advisory.get("package")

        if not package_name:
            continue

        key = normalize_name(package_name)

        if key not in python_targets:
            continue

        for relative_path, full_path in requirement_sources(
            advisory,
            project_root,
        ):
            relative_key = relative_path.as_posix()

            plan = requirements_plans.setdefault(
                relative_key,
                {
                    "path": full_path,
                    "packages": {},
                },
            )
            plan["packages"][key] = python_targets[key]

    patch_parts = []
    all_changes = []

    for relative_key in sorted(requirements_plans):
        plan = requirements_plans[relative_key]

        try:
            original_text = plan["path"].read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            print(f"File read nahi hui: {relative_key}: {error}")
            continue

        updated_text, changes = update_requirements_text(
            original_text,
            plan["packages"],
        )

        if not changes:
            continue

        diff_text = unified_file_diff(
            Path(relative_key),
            original_text,
            updated_text,
        )

        if diff_text:
            patch_parts.append(diff_text)

            for change in changes:
                all_changes.append({
                    **change,
                    "file": relative_key,
                    "ecosystem": "PyPI",
                })

    npm_plans = {}

    for advisory in advisories:
        if str(advisory.get("ecosystem", "")).lower() != "npm":
            continue

        package_name = advisory.get("package")

        if not package_name or package_name not in npm_targets:
            continue

        for relative_path, full_path in npm_lock_sources(
            advisory,
            project_root,
        ):
            relative_key = relative_path.as_posix()

            plan = npm_plans.setdefault(
                relative_key,
                {
                    "lock_path": full_path,
                    "packages": {},
                },
            )
            plan["packages"][package_name] = npm_targets[package_name]

    for relative_key in sorted(npm_plans):
        plan = npm_plans[relative_key]

        diff_text = create_npm_patch(
            project_root=project_root,
            lock_relative_path=Path(relative_key),
            lock_full_path=plan["lock_path"],
            npm_targets=plan["packages"],
        )

        if diff_text:
            patch_parts.append(diff_text)

            for package_name, target in plan["packages"].items():
                all_changes.append({
                    "package": package_name,
                    "old_version": ", ".join(
                        sorted(target["old_versions"])
                    ) or "unknown",
                    "new_version": target["version"],
                    "file": relative_key,
                    "ecosystem": "npm",
                })

    if not patch_parts:
        print(
            "Koi safe update patch generate nahi hui. "
            "Fixed version deprecated, unavailable, ya supported manifest se unmatched ho sakti hai."
        )
        return None

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as output_handle:
        output_handle.write("\n".join(patch_parts))

    print("Reviewable dependency patch bani:")
    print(f"  File: {output_path.resolve()}")

    for change in all_changes:
        if change["ecosystem"] == "PyPI":
            print(
                f"  {change['file']}:{change['line']} "
                f"{change['package']}=={change['old_version']} "
                f"-> {change['new_version']}"
            )
        else:
            print(
                f"  {change['file']} "
                f"{change['package']} "
                f"{change['old_version']} -> {change['new_version']}"
            )

    print("\nOriginal project files automatically change nahi hui.")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description=(
            "OSV advisories se reviewable Python/npm dependency patch banao."
        )
    )
    parser.add_argument(
        "project_folder",
        help="Project folder ka path",
    )
    parser.add_argument(
        "--output",
        default="dependency_update_suggestions.patch",
        help="Patch file ka output path",
    )

    args = parser.parse_args()
    project_folder = Path(args.project_folder)

    if not project_folder.is_dir():
        print(f"Folder nahi mila: {project_folder}")
        raise SystemExit(1)

    packages = parse_requirements(project_folder)

    if not packages:
        print("Koi pinned package ya lockfile package nahi mila.")
        raise SystemExit(0)

    print(f"{len(packages)} package(s) mile. OSV lookup shuru...")
    advisories, warnings = lookup_osv(packages)

    for warning in warnings:
        print(f"Warning: {warning}")

    if not advisories:
        print("OSV se koi advisory nahi mili; patch nahi bani.")
        raise SystemExit(0)

    generated_patch = create_patch(
        project_folder=project_folder,
        advisories=advisories,
        output_file=args.output,
    )

    if generated_patch is None:
        stale_patch = Path(args.output)

        if stale_patch.is_file():
            try:
                stale_text = stale_patch.read_text(
                    encoding="utf-8-sig",
                    errors="replace",
                )
            except OSError:
                stale_text = ""

            if (stale_text.lstrip().startswith("--- a/") or "diff --git a/" in stale_text) and "+++ b/" in stale_text:
                stale_patch.unlink()
                print(
                    "Purani generated patch remove hui, taaki invalid patch "
                    "galti se reuse na ho."
                )


if __name__ == "__main__":
    main()
