from pathlib import Path


def package_key(package):
    return (
        package.get("ecosystem", "PyPI"),
        package["name"],
        str(package["version"]),
    )


def package_node_id(ecosystem, name, version):
    return f"package:{ecosystem}:{name}@{version}"


def manifest_node_id(source):
    return f"manifest:{source}"


def normalize_source(source, project_root):
    source = str(source).strip()

    if not source:
        return ""

    source_path = Path(source)

    if source_path.is_absolute():
        try:
            return source_path.resolve().relative_to(project_root).as_posix()
        except ValueError:
            return source_path.as_posix()

    return source_path.as_posix()


def split_sources(source, project_root):
    if not source:
        return []

    return sorted({
        normalized
        for item in str(source).split(",")
        if (normalized := normalize_source(item, project_root))
    })


def add_node(nodes_by_id, node):
    nodes_by_id.setdefault(node["id"], node)


def add_edge(edges, seen_edges, edge):
    edge_key = (
        edge["from"],
        edge["to"],
        edge["type"],
        edge.get("dependency_version"),
        edge.get("marker"),
    )

    if edge_key not in seen_edges:
        edges.append(edge)
        seen_edges.add(edge_key)


def build_dependency_graph(project_folder, packages, advisories):
    """
    Package manifests, installed packages, dependency links, aur OSV findings
    ka ecosystem-aware graph banata hai.
    """
    project_root = Path(project_folder).resolve()
    nodes_by_id = {}
    edges = []
    seen_edges = set()

    advisories_by_package = {}

    for advisory in advisories:
        ecosystem = advisory.get("ecosystem", "PyPI")
        key = (
            ecosystem,
            advisory.get("package"),
            str(advisory.get("version")),
        )

        advisories_by_package.setdefault(key, []).append(advisory)

    packages_by_key = {}
    packages_by_ecosystem_name = {}

    # Package nodes aur manifest nodes.
    for package in packages:
        ecosystem, name, version = package_key(package)
        package_id = package_node_id(ecosystem, name, version)

        matching_advisories = advisories_by_package.get(
            (ecosystem, name, version),
            [],
        )

        advisory_ids = sorted({
            advisory_id
            for advisory in matching_advisories
            for advisory_id in (
                advisory.get("ids")
                or [advisory.get("id", "Unknown ID")]
            )
        })

        sources = split_sources(
            package.get("source", ""),
            project_root,
        )

        package_node = {
            "id": package_id,
            "type": "PACKAGE",
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "direct": bool(package.get("direct", False)),
            "sources": sources,
            "vulnerable": bool(matching_advisories),
            "advisory_ids": advisory_ids,
        }

        add_node(nodes_by_id, package_node)
        packages_by_key[(ecosystem, name, version)] = package

        packages_by_ecosystem_name.setdefault(
            (ecosystem, name),
            [],
        ).append(package_id)

        for source in sources:
            file_id = manifest_node_id(source)

            add_node(
                nodes_by_id,
                {
                    "id": file_id,
                    "type": "MANIFEST",
                    "file": source,
                },
            )

            add_edge(
                edges,
                seen_edges,
                {
                    "from": file_id,
                    "to": package_id,
                    "type": "DECLARES",
                },
            )

    # Package-to-package dependency edges.
    for package in packages:
        ecosystem, name, version = package_key(package)
        parent_id = package_node_id(ecosystem, name, version)
        parent_sources = set(
            split_sources(package.get("source", ""), project_root)
        )

        for dependency in package.get("dependencies", []):
            dependency_name = dependency.get("name")

            if not dependency_name:
                continue

            dependency_ecosystem = dependency.get(
                "ecosystem",
                ecosystem,
            )
            requested_version = dependency.get("version")
            marker = dependency.get("marker")

            candidates = packages_by_ecosystem_name.get(
                (dependency_ecosystem, dependency_name),
                [],
            )

            # Agar dependency parser exact version deta hai to usse prefer karo.
            if requested_version:
                exact_candidates = [
                    candidate_id
                    for candidate_id in candidates
                    if candidate_id.endswith(f"@{requested_version}")
                ]
                if exact_candidates:
                    candidates = exact_candidates

            # Same lockfile se aane wale resolved packages ko preference do.
            same_source_candidates = []

            for candidate_id in candidates:
                candidate_node = nodes_by_id[candidate_id]
                candidate_sources = set(candidate_node.get("sources", []))

                if parent_sources.intersection(candidate_sources):
                    same_source_candidates.append(candidate_id)

            if same_source_candidates:
                candidates = same_source_candidates

            if not candidates:
                reference_version = requested_version or "*"
                reference_id = (
                    f"dependency-ref:{dependency_ecosystem}:"
                    f"{dependency_name}@{reference_version}"
                )

                add_node(
                    nodes_by_id,
                    {
                        "id": reference_id,
                        "type": "DEPENDENCY_REFERENCE",
                        "ecosystem": dependency_ecosystem,
                        "name": dependency_name,
                        "requested_version": requested_version,
                        "resolved": False,
                    },
                )

                add_edge(
                    edges,
                    seen_edges,
                    {
                        "from": parent_id,
                        "to": reference_id,
                        "type": "DEPENDS_ON",
                        "resolved": False,
                        "dependency_version": requested_version,
                        "marker": marker,
                    },
                )
                continue

            multiple_candidates = len(candidates) > 1

            for candidate_id in sorted(candidates):
                add_edge(
                    edges,
                    seen_edges,
                    {
                        "from": parent_id,
                        "to": candidate_id,
                        "type": "DEPENDS_ON",
                        "resolved": not multiple_candidates,
                        "resolution": (
                            "multiple_versions"
                            if multiple_candidates
                            else "matched"
                        ),
                        "dependency_version": requested_version,
                        "marker": marker,
                    },
                )

    return {
        "scope": (
            "Manifest-to-package and package-to-dependency graph. "
            "Package IDs include ecosystem. If a dependency name matches "
            "multiple installed versions and no exact version is available, "
            "all matching versions are shown as ambiguous candidates."
        ),
        "nodes": sorted(
            nodes_by_id.values(),
            key=lambda node: node["id"],
        ),
        "edges": edges,
    }