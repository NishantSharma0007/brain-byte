import json
from pathlib import Path
from urllib.parse import quote


TOOL_NAME = "Automated Codebase Security Auditor"
TOOL_VERSION = "0.1.0"
DEPENDENCY_RULE_ID = "OSV-DEPENDENCY-ADVISORY"


def _relative_uri(file_path, project_root):
    """Project file ko SARIF ke liye relative URI mein badlo."""
    if not file_path:
        return None

    root = Path(project_root).resolve()
    candidate = Path(str(file_path))

    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        relative_path = candidate.resolve().relative_to(root)
    except (OSError, ValueError):
        return None

    return quote(relative_path.as_posix(), safe="/-_.~")


def _artifact_location(file_path, project_root):
    uri = _relative_uri(file_path, project_root)

    if not uri:
        return None

    return {
        "uri": uri,
        "uriBaseId": "%SRCROOT%",
    }


def _level_from_severity(severity):
    severity_text = str(severity or "").upper()

    if "CRITICAL" in severity_text or "HIGH" in severity_text:
        return "error"

    if "MEDIUM" in severity_text or "MODERATE" in severity_text:
        return "warning"

    if "LOW" in severity_text:
        return "note"

    # Unknown severity ya CVSS vector ko warning rakho.
    return "warning"


def _rule_descriptor(rule_id, name, description, level="warning"):
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {
            "text": description,
        },
        "fullDescription": {
            "text": description,
        },
        "defaultConfiguration": {
            "level": level,
        },
    }


def _source_list(advisory):
    sources = advisory.get("sources")

    if isinstance(sources, list):
        return [
            str(source).strip()
            for source in sources
            if str(source).strip()
        ]

    source = advisory.get("source", "")

    if not source:
        return []

    return [
        item.strip()
        for item in str(source).split(",")
        if item.strip()
    ]


def _make_code_result(finding, project_root, rule_indexes, triage_by_id):
    rule_id = str(getattr(finding, "rule_id", "UNKNOWN"))
    finding_file = str(getattr(finding, "file", ""))
    finding_line = getattr(finding, "line", None)
    title = str(getattr(finding, "title", "Code finding"))
    message_text = str(getattr(finding, "message", ""))

    full_message = title
    if message_text:
        full_message = f"{title}: {message_text}"

    result = {
        "ruleId": rule_id,
        "ruleIndex": rule_indexes[rule_id],
        "level": "warning",
        "message": {
            "text": full_message,
        },
        "locations": [],
        "properties": {
            "category": "code",
            "status": "suspected",
            "file": finding_file,
            "line": finding_line,
            "evidence": list(getattr(finding, "evidence", []) or []),
        },
    }

    finding_key = f"{rule_id}:{finding_file}:{finding_line}"
    triage = triage_by_id.get(finding_key, {})

    if triage.get("review_priority"):
        result["properties"]["reviewPriority"] = (
            triage["review_priority"]
        )

    if triage.get("priority_reason"):
        result["properties"]["priorityReason"] = (
            triage["priority_reason"]
        )

    artifact = _artifact_location(finding_file, project_root)

    if artifact:
        physical_location = {
            "artifactLocation": artifact,
        }

        try:
            line_number = max(1, int(finding_line))
        except (TypeError, ValueError):
            line_number = None

        if line_number is not None:
            physical_location["region"] = {
                "startLine": line_number,
            }

        result["locations"] = [{
            "physicalLocation": physical_location,
        }]

    return result


def _make_dependency_result(
    advisory,
    project_root,
    rule_indexes,
    triage_by_id,
):
    package = str(advisory.get("package", "unknown"))
    version = str(advisory.get("version", "unknown"))
    summary = str(advisory.get("summary") or "OSV advisory match")
    severity = str(advisory.get("severity") or "Not provided")
    advisory_ids = advisory.get("ids") or [
        advisory.get("id", "Unknown ID")
    ]
    sources = _source_list(advisory)

    result = {
        "ruleId": DEPENDENCY_RULE_ID,
        "ruleIndex": rule_indexes[DEPENDENCY_RULE_ID],
        "level": _level_from_severity(severity),
        "message": {
            "text": f"{package}=={version}: {summary}",
        },
        "locations": [],
        "properties": {
            "category": "dependency",
            "status": "advisory_match_review_needed",
            "package": package,
            "version": version,
            "severity": severity,
            "advisoryIds": advisory_ids,
            "fixedEvents": advisory.get("fixed_events", []),
            "severityScores": advisory.get("severity_scores", []),
            "references": advisory.get("references", []),
            "sourceFiles": sources,
        },
    }

    advisory_id = advisory.get("id", "Unknown ID")
    finding_key = f"OSV:{package}:{version}:{advisory_id}"
    triage = triage_by_id.get(finding_key, {})

    if triage.get("review_priority"):
        result["properties"]["reviewPriority"] = (
            triage["review_priority"]
        )

    # Dependency scanner package ko manifest se jodta hai,
    # lekin abhi manifest ki exact line number record nahi karta.
    if sources:
        artifact = _artifact_location(sources[0], project_root)

        if artifact:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": artifact,
                },
            }]

    return result


def save_sarif_report(
    code_findings,
    advisories,
    project_root,
    agent_workflow=None,
    output_file="audit_report.sarif",
):
    project_root = Path(project_root).resolve()
    agent_workflow = agent_workflow or {}

    workflow_findings = agent_workflow.get("findings", [])
    triage_by_id = {
        finding.get("id"): finding
        for finding in workflow_findings
        if finding.get("id")
    }

    rules_by_id = {}

    for finding in code_findings:
        rule_id = str(getattr(finding, "rule_id", "UNKNOWN"))
        title = str(getattr(finding, "title", "Code finding"))

        rules_by_id.setdefault(
            rule_id,
            _rule_descriptor(
                rule_id=rule_id,
                name=rule_id,
                description=title,
                level="warning",
            ),
        )

    if advisories:
        rules_by_id[DEPENDENCY_RULE_ID] = _rule_descriptor(
            rule_id=DEPENDENCY_RULE_ID,
            name="OSVDependencyAdvisory",
            description=(
                "A dependency version has a matching OSV advisory."
            ),
            level="warning",
        )

    rules = [
        rules_by_id[rule_id]
        for rule_id in sorted(rules_by_id)
    ]
    rule_indexes = {
        rule["id"]: index
        for index, rule in enumerate(rules)
    }

    results = []

    for finding in code_findings:
        results.append(
            _make_code_result(
                finding=finding,
                project_root=project_root,
                rule_indexes=rule_indexes,
                triage_by_id=triage_by_id,
            )
        )

    for advisory in advisories:
        results.append(
            _make_dependency_result(
                advisory=advisory,
                project_root=project_root,
                rule_indexes=rule_indexes,
                triage_by_id=triage_by_id,
            )
        )

    root_uri = project_root.as_uri()
    if not root_uri.endswith("/"):
        root_uri += "/"

    sarif_report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "rules": rules,
                    },
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": root_uri,
                        "description": {
                            "text": "Root folder of the scanned project.",
                        },
                    },
                },
                "results": results,
            },
        ],
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sarif_report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return output_path