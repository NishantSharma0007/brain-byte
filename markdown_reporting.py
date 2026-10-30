from datetime import datetime
from pathlib import Path


def _safe_text(value):
    """Markdown mein text ko safely dikhane ke liye."""
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Text ke andar Markdown formatting ya nayi headings na banne dein.
    for character in r"\`*_{}[]()#+-.!|>":
        text = text.replace(character, "\\" + character)

    return text.replace("\n", "<br>")


def _as_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def save_markdown_report(
    code_findings,
    advisories,
    warnings,
    dependency_graph=None,
    code_graph=None,
    agent_workflow=None,
    project_folder=".",
    output_file="audit_report.md",
):
    dependency_graph = dependency_graph or {}
    code_graph = code_graph or {}
    agent_workflow = agent_workflow or {}

    dependency_nodes = dependency_graph.get("nodes", [])
    dependency_edges = dependency_graph.get("edges", [])

    function_nodes = [
        node
        for node in code_graph.get("nodes", [])
        if node.get("type") == "FUNCTION"
    ]
    call_edges = [
        edge
        for edge in code_graph.get("edges", [])
        if edge.get("type") == "CALLS"
    ]

    workflow_findings = agent_workflow.get("findings", [])
    triage_by_id = {
        finding.get("id"): finding
        for finding in workflow_findings
        if finding.get("id")
    }

    lines = [
        "# Codebase Security Audit Report",
        "",
        f"- **Project:** {_safe_text(project_folder)}",
        (
            "- **Generated:** "
            f"{_safe_text(datetime.now().astimezone().isoformat(timespec='seconds'))}"
        ),
        "",
        "## Summary",
        "",
        "| Item | Count |",
        "| --- | ---: |",
        f"| Python code findings | {len(code_findings)} |",
        f"| Dependency advisory groups | {len(advisories)} |",
        f"| Warnings | {len(warnings)} |",
        f"| Dependency graph nodes | {len(dependency_nodes)} |",
        f"| Dependency graph edges | {len(dependency_edges)} |",
        f"| Python functions in call graph | {len(function_nodes)} |",
        f"| Function calls in call graph | {len(call_edges)} |",
        "",
        "## Code Findings",
        "",
    ]

    if not code_findings:
        lines.append("No code findings were reported.")
        lines.append("")
    else:
        for index, finding in enumerate(code_findings, start=1):
            finding_id = (
                f"{finding.rule_id}:{finding.file}:{finding.line}"
            )
            triage = triage_by_id.get(finding_id, {})

            lines.extend([
                (
                    f"### {index}. "
                    f"{_safe_text(finding.rule_id)} — "
                    f"{_safe_text(finding.title)}"
                ),
                "",
                (
                    f"- **File:** {_safe_text(finding.file)} "
                    f"(line {_safe_text(finding.line)})"
                ),
                f"- **Details:** {_safe_text(finding.message)}",
            ])

            if triage.get("review_priority"):
                lines.append(
                    "- **Review priority:** "
                    f"{_safe_text(triage.get('review_priority'))}"
                )

            if triage.get("recommendation"):
                lines.append(
                    "- **Recommendation:** "
                    f"{_safe_text(triage.get('recommendation'))}"
                )

            evidence = _as_list(getattr(finding, "evidence", []))

            if evidence:
                lines.extend(["- **Evidence:**"])
                for item in evidence:
                    lines.append(f"  - {_safe_text(item)}")

            lines.append("")

    lines.extend([
        "## Dependency Advisories",
        "",
    ])

    if not advisories:
        lines.append("No dependency advisory groups were reported.")
        lines.append("")
    else:
        for index, advisory in enumerate(advisories, start=1):
            package = advisory.get("package", "unknown package")
            version = advisory.get("version", "unknown version")
            severity = advisory.get("severity", "Not provided")
            summary = advisory.get("summary", "")
            advisory_ids = advisory.get("ids") or [
                advisory.get("id", "Unknown ID")
            ]

            lines.extend([
                (
                    f"### {index}. {_safe_text(package)}"
                    f"=={_safe_text(version)}"
                ),
                "",
                f"- **Severity:** {_safe_text(severity)}",
                (
                    "- **Advisory IDs:** "
                    f"{_safe_text(', '.join(advisory_ids))}"
                ),
            ])

            if summary:
                lines.append(f"- **Summary:** {_safe_text(summary)}")

            fixed_events = advisory.get("fixed_events", [])

            if fixed_events:
                lines.append("- **Fixed versions/events:**")
                for event in fixed_events:
                    range_type = event.get("range_type", "unknown")
                    value = event.get("value", "unknown")
                    lines.append(
                        f"  - {_safe_text(range_type)}: "
                        f"{_safe_text(value)}"
                    )

            severity_scores = advisory.get("severity_scores", [])

            if severity_scores:
                lines.append("- **Severity scores:**")
                for score in severity_scores:
                    score_type = score.get("type", "Severity")
                    score_value = score.get("score", "")
                    lines.append(
                        f"  - {_safe_text(score_type)}: "
                        f"{_safe_text(score_value)}"
                    )

            references = advisory.get("references", [])

            if references:
                lines.append("- **References:**")
                for reference in references:
                    lines.append(f"  - {_safe_text(reference)}")

            lines.append("")

    lines.extend([
        "## Local AI Explanation",
        "",
    ])

    explanation = agent_workflow.get("assistant_explanation", {})
    explanation_status = explanation.get("status", "not available")

    lines.append(f"- **Status:** {_safe_text(explanation_status)}")

    if explanation.get("model"):
        lines.append(
            f"- **Model:** {_safe_text(explanation.get('model'))}"
        )

    if explanation_status == "generated" and explanation.get("text"):
        lines.extend([
            "",
            _safe_text(explanation["text"]),
            "",
            (
                "> This explanation is AI-generated. "
                "Review the code evidence and advisory records separately."
            ),
            "",
        ])
    elif explanation.get("reason"):
        lines.append(
            f"- **Details:** {_safe_text(explanation.get('reason'))}"
        )
        lines.append("")

    lines.extend([
        "## Specialist Agent Workflow",
        "",
    ])

    agent_runs = agent_workflow.get("agent_runs", [])

    if not agent_runs:
        lines.append("No agent workflows details were available.")
        lines.append("")
    else:
        lines.extend([
            "| Agent | Status | Input count | Output count |",
            "| --- | --- | ---: | ---: |",
        ])

        for agent in agent_runs:
            status = agent.get("status", "completed")
            input_count = agent.get("input_count", "")
            output_count = agent.get("output_count", "")

            lines.append(
                f"| {_safe_text(agent.get('agent', 'Unknown'))} "
                f"| {_safe_text(status)} "
                f"| {input_count} "
                f"| {output_count} |"
            )

        lines.append("")

    lines.extend([
        "## Warnings",
        "",
    ])

    if warnings:
        for warning in warnings:
            lines.append(f"- {_safe_text(warning)}")
    else:
        lines.append("No warnings.")

    lines.append("")

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return output_path