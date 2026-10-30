import json
from dataclasses import asdict
from pathlib import Path


def save_json(
    findings,
    advisories,
    warnings,
    output_file="audit_report.json",
    dependency_graph=None,
    code_graph=None,
    agent_workflow=None,
):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "code_findings": [
            asdict(finding) for finding in findings
        ],
        "dependency_advisories": advisories,
        "dependency_graph": dependency_graph or {
            "scope": "No dependency graph created",
            "nodes": [],
            "edges": [],
        },
        "code_call_graph": code_graph or {
            "scope": "No code call graph created",
            "nodes": [],
            "edges": [],
        },
        "agent_workflow": agent_workflow or {
            "mode": "Not run",
            "agent_runs": [],
            "findings": [],
        },
        "warnings": warnings,
    }

    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return output_path