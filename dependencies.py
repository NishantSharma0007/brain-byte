import json
import re
import tomllib
import warnings
from pathlib import Path, PurePosixPath


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

NPM_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


def normalize_name(name):
    """PyPI package names ke case aur separators normalize karta hai."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def should_skip(path):
    return any(part in SKIP_FOLDERS for part in path.parts)


def read_toml(path):
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        warnings.warn(f"{path} parse nahi hui: {error}")
        return {}


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        warnings.warn(f"{path} JSON parse nahi hui: {error}")
        return {}


def parse_dependency_name(requirement):
    match = PACKAGE_NAME_PATTERN.match(str(requirement))
    if not match:
        return None
    return normalize_name(match.group(1))


def package_record(
    name,
    version,
    source,
    dependencies=None,
    direct=False,
    ecosystem="PyPI",
):
    if ecosystem == "PyPI":
        package_name = normalize_name(name)
    else:
        # npm names ko OSV ko unke original form me bhejna hai,
        # khaaskar @scope/package names ko.
        package_name = str(name).strip()

    return {
        "name": package_name,
        "version": str(version),
        "ecosystem": ecosystem,
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
                ecosystem="PyPI",
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
                ecosystem="PyPI",
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
                ecosystem="PyPI",
            )
        )

    return packages


def collect_direct_names(root):
    """pyproject.toml files se direct PyPI dependencies padhta hai."""
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


def collect_npm_direct_names(root):
    """package.json files se direct npm dependency names padhta hai."""
    direct_names = set()

    for path in root.rglob("package.json"):
        if should_skip(path):
            continue

        data = read_json(path)
        if not isinstance(data, dict):
            continue

        for section_name in NPM_DEPENDENCY_SECTIONS:
            section = data.get(section_name, {})
            if isinstance(section, dict):
                direct_names.update(str(name) for name in section)

    return direct_names


def npm_name_from_lock_path(package_path):
    """
    package-lock ke node_modules path se package name nikalta hai.

    Examples:
      node_modules/left-pad -> left-pad
      node_modules/@scope/name -> @scope/name
      node_modules/a/node_modules/b -> b
    """
    normalized_path = str(package_path).replace("\\", "/")
    parts = PurePosixPath(normalized_path).parts

    node_modules_indexes = [
        index
        for index, part in enumerate(parts)
        if part == "node_modules"
    ]

    if not node_modules_indexes:
        return None

    index = node_modules_indexes[-1]
    package_parts = parts[index + 1:]

    if not package_parts:
        return None

    if package_parts[0].startswith("@"):
        if len(package_parts) < 2:
            return None
        return f"{package_parts[0]}/{package_parts[1]}"

    return package_parts[0]


def npm_dependency_records(dependencies):
    if not isinstance(dependencies, dict):
        return []

    return [
        {
            "name": str(dependency_name),
            "marker": None,
        }
        for dependency_name in dependencies
    ]


def parse_legacy_npm_dependencies(
    dependencies,
    source,
    direct_names,
    top_level=True,
):
    """Purane package-lock v1 dependency tree ko recursively parse karta hai."""
    packages = []

    if not isinstance(dependencies, dict):
        return packages

    for name, item in dependencies.items():
        if not isinstance(item, dict):
            continue

        version = item.get("version")
        if version:
            packages.append(
                package_record(
                    name=name,
                    version=version,
                    source=source,
                    dependencies=npm_dependency_records(
                        item.get("requires", {})
                    ),
                    direct=top_level and name in direct_names,
                    ecosystem="npm",
                )
            )

        nested = item.get("dependencies", {})
        packages.extend(
            parse_legacy_npm_dependencies(
                dependencies=nested,
                source=source,
                direct_names=direct_names,
                top_level=False,
            )
        )

    return packages


def parse_package_lock(path, root, direct_names):
    """package-lock.json ya npm-shrinkwrap.json se resolved npm packages padhta hai."""
    data = read_json(path)

    if not isinstance(data, dict):
        return []

    source = path.relative_to(root).as_posix()
    packages = []
    lock_packages = data.get("packages")

    if isinstance(lock_packages, dict) and lock_packages:
        root_package = lock_packages.get("", {})

        if isinstance(root_package, dict):
            for section_name in NPM_DEPENDENCY_SECTIONS:
                section = root_package.get(section_name, {})
                if isinstance(section, dict):
                    direct_names.update(str(name) for name in section)

        for package_path, item in lock_packages.items():
            if not package_path or not isinstance(item, dict):
                continue

            path_name = npm_name_from_lock_path(package_path)
            package_name = item.get("name") or path_name
            version = item.get("version")

            if not package_name or not version or item.get("link"):
                continue

            is_direct = (
                str(package_name) in direct_names
                or (path_name is not None and path_name in direct_names)
            )

            packages.append(
                package_record(
                    name=package_name,
                    version=version,
                    source=source,
                    dependencies=npm_dependency_records(
                        item.get("dependencies", {})
                    ),
                    direct=is_direct,
                    ecosystem="npm",
                )
            )

        return packages

    # package-lock v1 me resolved packages dependencies tree me hote hain.
    legacy_dependencies = data.get("dependencies", {})
    if isinstance(legacy_dependencies, dict):
        direct_names.update(
            str(name) for name in legacy_dependencies
        )

    return parse_legacy_npm_dependencies(
        dependencies=legacy_dependencies,
        source=source,
        direct_names=direct_names,
        top_level=True,
    )


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
            dependency_name = dependency["name"]
            dependency_marker = dependency.get("marker")
            dependency_key = (dependency_name, dependency_marker)

            entry["dependencies_by_key"][dependency_key] = {
                "name": dependency_name,
                "marker": dependency_marker,
            }

    result = []

    for package in merged.values():
        package["source"] = ", ".join(sorted(package.pop("sources")))
        package["dependencies"] = sorted(
            package.pop("dependencies_by_key").values(),
            key=lambda item: (
                item["name"],
                item.get("marker") or "",
            ),
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
    Python requirements/lockfiles aur npm package-lock files se packages padhta hai.
    """
    root = Path(project_folder).resolve()
    records = []

    pypi_direct_names = collect_direct_names(root)
    npm_direct_names = collect_npm_direct_names(root)

    # Python requirements files: exact pins direct dependencies hain.
    for path in root.rglob("requirements*.txt"):
        if should_skip(path):
            continue

        parsed = parse_requirements_file(path, root)
        records.extend(parsed)
        pypi_direct_names.update(
            package["name"] for package in parsed
        )

    # Python Poetry lockfile.
    for path in root.rglob("poetry.lock"):
        if should_skip(path):
            continue
        records.extend(parse_poetry_lock(path, root))

    # Python uv lockfile.
    for path in root.rglob("uv.lock"):
        if should_skip(path):
            continue
        records.extend(parse_uv_lock(path, root))

    # npm v2/v3 package-lock aur npm shrinkwrap.
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        for path in root.rglob(lock_name):
            if should_skip(path):
                continue

            records.extend(
                parse_package_lock(
                    path,
                    root,
                    npm_direct_names,
                )
            )

    # Direct dependency flags ecosystem ke hisaab se set karo.
    for package in records:
        if (
            package["ecosystem"] == "PyPI"
            and package["name"] in pypi_direct_names
        ):
            package["direct"] = True

        elif (
            package["ecosystem"] == "npm"
            and package["name"] in npm_direct_names
        ):
            package["direct"] = True

    return merge_package_records(records)