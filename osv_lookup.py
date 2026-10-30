import json
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/"


def get_advisory_details(advisory_id):
    url = OSV_DETAIL_URL + quote(advisory_id, safe="")
    request = Request(url, headers={"User-Agent": "security-test-scanner"})

    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_severity(advisory):
    labels = []
    scores = []

    # Kuch records severity ko text label mein rakhte hain.
    for affected in advisory.get("affected", []):
        for section_name in ("ecosystem_specific", "database_specific"):
            section = affected.get(section_name) or {}
            label = section.get("severity")

            if isinstance(label, str):
                labels.append(label.upper())

        # Package-specific severity score, agar ho.
        for score in affected.get("severity", []):
            if score.get("type") and score.get("score"):
                scores.append({
                    "type": score["type"],
                    "score": score["score"],
                    "source": score.get("source"),
                })

    # Vulnerability-level severity score, agar ho.
    for score in advisory.get("severity", []):
        if score.get("type") and score.get("score"):
            scores.append({
                "type": score["type"],
                "score": score["score"],
                "source": score.get("source"),
            })

    if labels:
        severity = labels[0]
    elif scores:
        severity = "CVSS vector available; numeric level not calculated"
    else:
        severity = "Not provided"

    return severity, unique_items(scores)


def extract_fixed_events(advisory):
    fixed_events = []

    for affected in advisory.get("affected", []):
        for version_range in affected.get("ranges", []):
            range_type = version_range.get("type", "unknown")

            for event in version_range.get("events", []):
                if "fixed" in event:
                    fixed_events.append({
                        "range_type": range_type,
                        "value": event["fixed"],
                    })

    return unique_items(fixed_events)


def unique_items(items):
    result = []
    seen = set()

    for item in items:
        key = json.dumps(item, sort_keys=True)

        if key not in seen:
            seen.add(key)
            result.append(item)

    return result


def preferred_id(ids):
    priorities = {
        "GHSA": 0,
        "CVE": 1,
        "PYSEC": 2,
    }

    return sorted(
        ids,
        key=lambda value: (
            priorities.get(value.split("-", 1)[0].upper(), 3),
            value,
        ),
    )[0]


def merge_alias_duplicates(records):
    groups = []

    for record in records:
        identifiers = {record["id"], *record.get("aliases", [])}

        matching_groups = [
            group for group in groups
            if group["package"] == record["package"]
            and group["version"] == record["version"]
            and group["_identifiers"].intersection(identifiers)
        ]

        if not matching_groups:
            group = {
                "package": record["package"],
                "version": record["version"],
                "source": record["source"],
                "_identifiers": set(),
                "_summaries": [],
                "_severity_labels": [],
                "_severity_scores": [],
                "_fixed_events": [],
                "_references": [],
            }
            groups.append(group)
        else:
            group = matching_groups[0]

            # Alias links can connect records already in separate groups.
            for other_group in matching_groups[1:]:
                group["_identifiers"].update(other_group["_identifiers"])
                group["_summaries"].extend(other_group["_summaries"])
                group["_severity_labels"].extend(other_group["_severity_labels"])
                group["_severity_scores"].extend(other_group["_severity_scores"])
                group["_fixed_events"].extend(other_group["_fixed_events"])
                group["_references"].extend(other_group["_references"])
                groups.remove(other_group)

        group["_identifiers"].update(identifiers)

        if record.get("summary"):
            group["_summaries"].append(record["summary"])

        if record.get("severity") != "Not provided":
            group["_severity_labels"].append(record["severity"])

        group["_severity_scores"].extend(record.get("severity_scores", []))
        group["_fixed_events"].extend(record.get("fixed_events", []))
        group["_references"].extend(record.get("references", []))

    merged = []

    for group in groups:
        ids = sorted(group["_identifiers"], key=lambda value: (
            {"GHSA": 0, "CVE": 1, "PYSEC": 2}.get(
                value.split("-", 1)[0].upper(), 3
            ),
            value,
        ))

        summaries = group["_summaries"]
        summary = max(summaries, key=len) if summaries else ""

        labels = group["_severity_labels"]
        scores = unique_items(group["_severity_scores"])

        if labels:
            severity = labels[0]
        elif scores:
            severity = "CVSS vector available; numeric level not calculated"
        else:
            severity = "Not provided"

        merged.append({
            "package": group["package"],
            "version": group["version"],
            "source": group["source"],
            "id": preferred_id(ids),
            "ids": ids,
            "aliases": [item for item in ids if item != preferred_id(ids)],
            "summary": summary,
            "severity": severity,
            "severity_scores": scores,
            "fixed_events": unique_items(group["_fixed_events"]),
            "references": sorted(set(group["_references"])),
        })

    return merged


def lookup_osv(packages):
    records = []
    warnings = []
    detail_cache = {}

    for start in range(0, len(packages), 100):
        batch = packages[start:start + 100]

        payload = {
            "queries": [
                {
                    "package": {
                        "name": package["name"],
                        "ecosystem": package["ecosystem"],
                    },
                    "version": package["version"],
                }
                for package in batch
            ]
        }

        request = Request(
            OSV_QUERY_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            warnings.append(f"OSV package lookup nahi ho saka: {error}")
            continue

        for package, result in zip(batch, data.get("results", [])):
            for vulnerability in result.get("vulns", []):
                advisory_id = vulnerability.get("id", "Unknown ID")

                if advisory_id not in detail_cache:
                    try:
                        detail_cache[advisory_id] = get_advisory_details(advisory_id)
                    except (URLError, TimeoutError, json.JSONDecodeError) as error:
                        warnings.append(
                            f"{advisory_id} ki details nahi mil saki: {error}"
                        )
                        detail_cache[advisory_id] = {}

                details = detail_cache[advisory_id]
                severity, severity_scores = extract_severity(details)

                records.append({
                    "package": package["name"],
                    "version": package["version"],
                    "source": package["source"],
                    "id": advisory_id,
                    "aliases": details.get("aliases", []),
                    "summary": details.get("summary", ""),
                    "severity": severity,
                    "severity_scores": severity_scores,
                    "fixed_events": extract_fixed_events(details),
                    "references": [
                        reference.get("url")
                        for reference in details.get("references", [])
                        if reference.get("url")
                    ][:10],
                })

    return merge_alias_duplicates(records), warnings