import re
import tomllib
import warnings
from pathlib import Path


SKIP_FOLDERS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
}

REQUIREMENT_PATTERN = re.compile(
    r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?"
    r"\s*==\s*([A-Za-z0-9_.+!-]+)$"
)

PACKAGE_NAME_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)"
)


def normalize_name(name):
    """PyPI package names are case-insensitive and normalize _, . and -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def should_skip(path):
    return any(part in SKIP_FOLDERS for part in path.parts)


def read_toml(path):
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        warnings.warn(f"{path} parse nahi hui: {error}")
        return {}


def parse_dependency_name(requirement):
    match = PACKAGE_NAME_PATTERN.match(str(requirement))
    if not match:
        return None
    return normalize_name(match.group(1))


def package_record(name, version, source, dependencies=None, direct=False):
    return {
        "name": normalize_name(name),
        "version": str(version),
        "ecosystem": "PyPI",
        "source": source,
        "direct": direct,
        "dependencies": dependencies or [],
    }


def parse_requirements_file(path, root):
    packages = []
    source = path.relative_to(root).as_posix()

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError as error:
        warnings.warn(f"{source} read nahi hui: {error}")
        return packages

    for line in lines:
        line = line.split("#", 1)[0]
        line = line.split(";", 1)[0].strip()

        if not line or line.startswith("-"):
            continue

        match = REQUIREMENT_PATTERN.match(line)
        if not match:
            continue

        packages.append(
            package_record(
                name=match.group(1),
                version=match.group(2),
                source=source,
                direct=True,
            )
        )

    return packages


def parse_uv_lock(path, root):
    data = read_toml(path)
    source = path.relative_to(root).as_posix()
    packages = []

    for item in data.get("package", []):
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        version = item.get("version")

        if not name or not version:
            continue

        dependencies = []

        for dependency in item.get("dependencies", []):
            if isinstance(dependency, str):
                dependency_name = dependency
                marker = None
            elif isinstance(dependency, dict):
                dependency_name = dependency.get("name")
                marker = dependency.get("marker")
            else:
                continue

            if dependency_name:
                dependencies.append({
                    "name": normalize_name(dependency_name),
                    "marker": marker,
                })

        packages.append(
            package_record(
                name=name,
                version=version,
                source=source,
                dependencies=dependencies,
            )
        )

    return packages


def parse_poetry_lock(path, root):
    data = read_toml(path)
    source = path.relative_to(root).as_posix()
    packages = []

    for item in data.get("package", []):
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        version = item.get("version")

        if not name or not version:
            continue

        dependencies = []
        dependency_table = item.get("dependencies", {})

        if isinstance(dependency_table, dict):
            for dependency_name, details in dependency_table.items():
                marker = None

                if isinstance(details, dict):
                    marker = details.get("markers") or details.get("marker")

                dependencies.append({
                    "name": normalize_name(dependency_name),
                    "marker": marker,
                })

        packages.append(
            package_record(
                name=name,
                version=version,
                source=source,
                dependencies=dependencies,
            )
        )

    return packages


def collect_direct_names(root):
    """Read declared direct dependency names from pyproject.toml files."""
    direct_names = set()

    for path in root.rglob("pyproject.toml"):
        if should_skip(path):
            continue

        data = read_toml(path)
        project = data.get("project", {})

        for requirement in project.get("dependencies", []):
            name = parse_dependency_name(requirement)
            if name:
                direct_names.add(name)

        optional_dependencies = project.get("optional-dependencies", {})
        if isinstance(optional_dependencies, dict):
            for requirements in optional_dependencies.values():
                for requirement in requirements:
                    name = parse_dependency_name(requirement)
                    if name:
                        direct_names.add(name)

        dependency_groups = data.get("dependency-groups", {})
        if isinstance(dependency_groups, dict):
            for requirements in dependency_groups.values():
                for requirement in requirements:
                    name = parse_dependency_name(requirement)
                    if name:
                        direct_names.add(name)

        poetry = data.get("tool", {}).get("poetry", {})

        for name in poetry.get("dependencies", {}):
            if name.lower() != "python":
                direct_names.add(normalize_name(name))

        for group in poetry.get("group", {}).values():
            if not isinstance(group, dict):
                continue

            for name in group.get("dependencies", {}):
                if name.lower() != "python":
                    direct_names.add(normalize_name(name))

    return direct_names


def merge_package_records(records):
    merged = {}

    for package in records:
        key = (
            package["ecosystem"],
            package["name"],
            package["version"],
        )

        if key not in merged:
            merged[key] = {
                **package,
                "sources": {package["source"]},
                "dependencies_by_key": {},
            }

        entry = merged[key]
        entry["sources"].add(package["source"])
        entry["direct"] = entry["direct"] or package.get("direct", False)

        for dependency in package.get("dependencies", []):
            dep_name = dependency["name"]
            dep_marker = dependency.get("marker")
            dep_key = (dep_name, dep_marker)
            entry["dependencies_by_key"][dep_key] = {
                "name": dep_name,
                "marker": dep_marker,
            }

    result = []

    for package in merged.values():
        package["source"] = ", ".join(sorted(package.pop("sources")))
        package["dependencies"] = sorted(
            package.pop("dependencies_by_key").values(),
            key=lambda item: (item["name"], item.get("marker") or ""),
        )
        result.append(package)

    return sorted(
        result,
        key=lambda item: (
            item["ecosystem"],
            item["name"],
            item["version"],
        ),
    )


def parse_requirements(project_folder):
    """
    Read exact pins from requirements files and resolved packages
    from Poetry/uv lockfiles.
    """
    root = Path(project_folder).resolve()
    records = []
    direct_names = collect_direct_names(root)

    # requirements files: exact pins are direct dependencies.
    for path in root.rglob("requirements*.txt"):
        if should_skip(path):
            continue

        parsed = parse_requirements_file(path, root)
        records.extend(parsed)
        direct_names.update(package["name"] for package in parsed)

    # Poetry lockfile: contains resolved package versions and dependencies.
    for path in root.rglob("poetry.lock"):
        if should_skip(path):
            continue
        records.extend(parse_poetry_lock(path, root))

    # uv lockfile: TOML parsing is best-effort because uv manages this format.
    for path in root.rglob("uv.lock"):
        if should_skip(path):
            continue
        records.extend(parse_uv_lock(path, root))

    # Mark lockfile packages declared directly in project metadata.
    for package in records:
        if package["name"] in direct_names:
            package["direct"] = True

    return merge_package_records(records)