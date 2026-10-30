from pathlib import Path


def build_dependency_graph(project_folder, packages, advisories):
    project_folder = Path(project_folder).resolve()
    repository_id = f"REPO:{project_folder.name}"

    nodes = [{
        "id": repository_id,
        "type": "REPOSITORY",
        "name": project_folder.name,
    }]

    edges = []
    package_nodes = {}
    packages_by_name = {}

    # Advisory IDs ko package/version ke saath map karo.
    advisories_by_package = {}

    for advisory in advisories:
        key = (
            "PyPI",
            advisory["package"],
            advisory["version"],
        )

        ids = advisory.get(
            "ids",
            [advisory.get("id", "Unknown ID")],
        )

        advisories_by_package.setdefault(key, set()).update(ids)

    # Package nodes banao.
    for package in packages:
        package_id = (
            f"{package['ecosystem']}:"
            f"{package['name']}@{package['version']}"
        )

        package_nodes[package_id] = package
        packages_by_name.setdefault(
            (package["ecosystem"], package["name"]),
            [],
        ).append(package_id)

        sources = package.get("source", "").split(", ")

        nodes.append({
            "id": package_id,
            "type": "PACKAGE",
            "ecosystem": package["ecosystem"],
            "name": package["name"],
            "version": package["version"],
            "direct": package.get("direct", False),
            "sources": sources,
            "advisory_ids": sorted(
                advisories_by_package.get(
                    (
                        package["ecosystem"],
                        package["name"],
                        package["version"],
                    ),
                    set(),
                )
            ),
        })

    # Repository -> direct package edges.
    direct_packages = [
        package for package in packages
        if package.get("direct", False)
    ]

    for package in direct_packages:
        package_id = (
            f"{package['ecosystem']}:"
            f"{package['name']}@{package['version']}"
        )

        edges.append({
            "from": repository_id,
            "to": package_id,
            "type": "DECLARES",
        })

    # If a lockfile is present without project metadata, infer roots
    # from packages that no other locked package references.
    if packages and not direct_packages:
        referenced_names = set()

        for package in packages:
            for dependency in package.get("dependencies", []):
                referenced_names.add(dependency["name"])

        inferred_roots = [
            package for package in packages
            if package["name"] not in referenced_names
        ]

        for package in inferred_roots:
            package_id = (
                f"{package['ecosystem']}:"
                f"{package['name']}@{package['version']}"
            )

            edges.append({
                "from": repository_id,
                "to": package_id,
                "type": "ROOT_INFERRED",
            })

    # Package -> transitive dependency edges.
    unresolved_nodes = {}

    for package in packages:
        source_id = (
            f"{package['ecosystem']}:"
            f"{package['name']}@{package['version']}"
        )

        for dependency in package.get("dependencies", []):
            dependency_name = dependency["name"]
            dependency_key = (
                package["ecosystem"],
                dependency_name,
            )
            candidates = packages_by_name.get(dependency_key, [])
            marker = dependency.get("marker")

            if len(candidates) == 1:
                edge = {
                    "from": source_id,
                    "to": candidates[0],
                    "type": "DEPENDS_ON",
                }
                if marker:
                    edge["marker"] = marker
                edges.append(edge)

            elif len(candidates) > 1:
                # Multiple locked versions may apply under different markers.
                for target_id in candidates:
                    edge = {
                        "from": source_id,
                        "to": target_id,
                        "type": "DEPENDS_ON_POSSIBLE",
                        "resolution": "Multiple locked versions; conditions not evaluated",
                    }
                    if marker:
                        edge["marker"] = marker
                    edges.append(edge)

            else:
                unresolved_id = (
                    f"{package['ecosystem']}:"
                    f"{dependency_name}@unresolved"
                )

                if unresolved_id not in unresolved_nodes:
                    unresolved_nodes[unresolved_id] = {
                        "id": unresolved_id,
                        "type": "UNRESOLVED_PACKAGE",
                        "ecosystem": package["ecosystem"],
                        "name": dependency_name,
                    }

                edge = {
                    "from": source_id,
                    "to": unresolved_id,
                    "type": "DEPENDS_ON_UNRESOLVED",
                }
                if marker:
                    edge["marker"] = marker
                edges.append(edge)

    nodes.extend(unresolved_nodes.values())

    # Remove duplicate edges.
    unique_edges = []
    seen_edges = set()

    for edge in edges:
        edge_key = (
            edge["from"],
            edge["to"],
            edge["type"],
            edge.get("marker"),
        )

        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            unique_edges.append(edge)

    return {
        "scope": (
            "Direct and lockfile dependency relationships. "
            "Environment markers are recorded but not evaluated."
        ),
        "nodes": nodes,
        "edges": unique_edges,
    }