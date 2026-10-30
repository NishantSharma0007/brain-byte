import argparse
import difflib
import re
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


def version_key(version):
    """Version string se numeric parts nikaal kar compare karo."""
    parts = re.findall(r"\d+", str(version))

    if not parts:
        return None

    return tuple(int(part) for part in parts)


def highest_fixed_version(advisory):
    """OSV fixed events mein se highest numeric version chuno."""
    fixed_versions = []

    for event in advisory.get("fixed_events", []):
        range_type = str(event.get("range_type", "")).upper()
        value = event.get("value")

        if not value:
            continue

        if range_type not in {"ECOSYSTEM", "SEMVER"}:
            continue

        key = version_key(value)

        if key:
            fixed_versions.append((key, str(value)))

    if not fixed_versions:
        return None

    fixed_versions.sort(key=lambda item: item[0])
    return fixed_versions[-1][1]


def requirement_sources(advisory, project_root):
    """Advisory source mein se requirements*.txt files dhoondo."""
    source_value = advisory.get("source", "")

    if isinstance(source_value, list):
        sources = source_value
    else:
        sources = str(source_value).split(",")

    root = Path(project_root).resolve()

    for source in sources:
        source = str(source).strip()

        if not source:
            continue

        candidate = Path(source)

        if not candidate.is_absolute():
            candidate = root / candidate

        try:
            candidate = candidate.resolve()
            relative_path = candidate.relative_to(root)
        except (OSError, ValueError):
            continue

        filename = relative_path.name.lower()

        if (
            filename.startswith("requirements")
            and relative_path.suffix.lower() == ".txt"
            and candidate.is_file()
        ):
            yield relative_path, candidate


def build_update_targets(advisories):
    """
    Har package ke liye OSV se reported highest fixed version chuno.

    Agar ek package ke multiple advisories hain, toh un sabko cover karne
    ke liye highest listed fixed version use hota hai.
    """
    targets = {}

    for advisory in advisories:
        package_name = advisory.get("package")

        if not package_name:
            continue

        package_key = normalize_name(package_name)
        fixed_version = highest_fixed_version(advisory)

        if not fixed_version:
            continue

        existing = targets.get(package_key)

        if existing is None:
            targets[package_key] = {
                "name": package_name,
                "version": fixed_version,
            }
            continue

        existing_key = version_key(existing["version"])
        new_key = version_key(fixed_version)

        if new_key and existing_key and new_key > existing_key:
            targets[package_key] = {
                "name": package_name,
                "version": fixed_version,
            }

    return targets


def update_requirements_text(text, targets):
    """Exact == version pins ko naye version se replace karo."""
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

        package_key = normalize_name(match.group("name"))
        target = targets.get(package_key)

        if not target:
            updated_lines.append(original_line)
            continue

        old_version = match.group("version")
        new_version = target["version"]

        if old_version == new_version:
            updated_lines.append(original_line)
            continue

        updated_line = (
            f"{match.group('prefix')}"
            f"{new_version}"
            f"{match.group('suffix')}"
            f"{line_ending}"
        )
        updated_lines.append(updated_line)

        changes.append({
            "package": target["name"],
            "old_version": old_version,
            "new_version": new_version,
            "line": line_number,
        })

    return "".join(updated_lines), changes


def create_patch(project_folder, advisories, output_file):
    project_root = Path(project_folder).resolve()
    targets = build_update_targets(advisories)

    if not targets:
        print("OSV se koi fixed version nahi mila; patch nahi bani.")
        return None

    plans = {}

    for advisory in advisories:
        package_name = advisory.get("package")

        if not package_name:
            continue

        package_key = normalize_name(package_name)

        if package_key not in targets:
            continue

        for relative_path, full_path in requirement_sources(
            advisory,
            project_root,
        ):
            key = relative_path.as_posix()
            plans.setdefault(key, {
                "path": full_path,
                "packages": {},
            })
            plans[key]["packages"][package_key] = targets[package_key]

    patch_parts = []
    all_changes = []

    for relative_path in sorted(plans):
        plan = plans[relative_path]
        file_path = plan["path"]

        try:
            original_text = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            print(f"File read nahi hui: {relative_path}: {error}")
            continue

        updated_text, changes = update_requirements_text(
            original_text,
            plan["packages"],
        )

        if not changes:
            continue

        old_lines = original_text.splitlines()
        new_lines = updated_text.splitlines()

        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{relative_path}",
                tofile=f"b/{relative_path}",
                lineterm="",
            )
        )

        if diff_lines:
            patch_parts.append("\n".join(diff_lines))
            all_changes.extend(
                {
                    **change,
                    "file": relative_path,
                }
                for change in changes
            )

    if not patch_parts:
        print(
            "requirements*.txt mein matching exact package pin nahi mila. "
            "Lockfiles ke liye manager-specific update chahiye."
        )
        return None

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(patch_parts) + "\n",
        encoding="utf-8",
    )

    print("Reviewable dependency patch bani:")
    print(f"  File: {output_path.resolve()}")

    for change in all_changes:
        print(
            f"  {change['file']}:{change['line']} "
            f"{change['package']}=={change['old_version']} "
            f"-> {change['new_version']}"
        )

    print("\nOriginal requirements file automatically change nahi hui.")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description=(
            "OSV fixed versions se reviewable requirements patch banao."
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

    create_patch(
        project_folder=project_folder,
        advisories=advisories,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()