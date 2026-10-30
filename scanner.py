import argparse
import os
from pathlib import Path

from inventory import find_python_files, find_javascript_files
from code_analysis import analyze_file
from javascript_analysis import analyze_javascript_file
from dependencies import parse_requirements
from osv_lookup import lookup_osv
from dependency_graph import build_dependency_graph
from call_graph import build_call_graph
from agent_workflow import run_agent_workflow
from reporting import save_json
from markdown_reporting import save_markdown_report
from sarif_reporting import save_sarif_report


def scan_project(project_folder, enable_ai=False, model=None):
    project_folder = Path(project_folder).resolve()

    # Python aur JavaScript files alag dhoondho.
    python_files = find_python_files(project_folder)
    javascript_files = find_javascript_files(project_folder)
    code_findings = []

    print(
        f"{len(python_files)} Python file(s) aur "
        f"{len(javascript_files)} JavaScript file(s) mili hain. "
        "Code scan shuru..."
    )

    # Existing Python analyzer.
    for file_path in python_files:
        code_findings.extend(analyze_file(file_path))

    # Tree-sitter JavaScript analyzer.
    for file_path in javascript_files:
        code_findings.extend(analyze_javascript_file(file_path))

    # Requirements aur lockfiles se packages padho.
    packages = parse_requirements(project_folder)
    print(f"{len(packages)} pinned package(s) mile.")

    # OSV advisory lookup.
    advisories, warnings = lookup_osv(packages)

    # Dependency graph.
    dependency_graph = build_dependency_graph(
        project_folder,
        packages,
        advisories,
    )

    # Call graph abhi Python files ke liye hi banta hai.
    code_graph = build_call_graph(
        project_folder,
        python_files,
    )

    # Specialist agents ko dono languages ki findings do.
    agent_workflow = run_agent_workflow(
        code_findings,
        advisories,
        enable_ai=enable_ai,
        model=model,
    )

    # Code findings print karo.
    if code_findings:
        print(f"\n{len(code_findings)} code finding(s):")

        for finding in code_findings:
            print(f"\n[{finding.rule_id}] {finding.title}")
            print(f"  File: {finding.file}:{finding.line}")
            print(f"  Details: {finding.message}")

            for evidence in finding.evidence:
                print(f"  Evidence: {evidence}")
    else:
        print("\nKoi code finding nahi mili.")

    # OSV results print karo.
    if advisories:
        print(f"\n{len(advisories)} dependency advisory group(s):")

        for advisory in advisories:
            advisory_ids = advisory.get("ids") or [
                advisory.get("id", "Unknown ID")
            ]

            print(
                f"\n[OSV][{advisory.get('severity', 'Not provided')}] "
                f"{advisory['package']}=={advisory['version']}"
            )
            print(f"  IDs: {', '.join(advisory_ids)}")

            if advisory.get("summary"):
                print(f"  Summary: {advisory['summary']}")

            for score in advisory.get("severity_scores", []):
                print(
                    f"  {score.get('type', 'Severity')}: "
                    f"{score.get('score', '')}"
                )

            for fixed_event in advisory.get("fixed_events", []):
                print(
                    f"  Fixed event "
                    f"({fixed_event.get('range_type', 'unknown')}): "
                    f"{fixed_event.get('value', 'unknown')}"
                )
    elif packages:
        print("\nOSV se koi advisory result nahi mila.")
    else:
        print("\nPinned packages nahi mile, isliye OSV lookup nahi hua.")

    # Graph summaries.
    dependency_nodes = dependency_graph.get("nodes", [])
    dependency_edges = dependency_graph.get("edges", [])

    function_nodes = [
        node for node in code_graph.get("nodes", [])
        if node.get("type") == "FUNCTION"
    ]
    call_edges = [
        edge for edge in code_graph.get("edges", [])
        if edge.get("type") == "CALLS"
    ]

    print(
        f"\nDependency graph bana: "
        f"{len(dependency_nodes)} nodes, {len(dependency_edges)} edges."
    )
    print(
        f"Python call graph bana: "
        f"{len(function_nodes)} functions, {len(call_edges)} calls."
    )

    # Agent results.
    print("\nSpecialist agent workflows:")

    for agent_run in agent_workflow["agent_runs"]:
        print(
            f"  {agent_run['agent']}: "
            f"{agent_run.get('status', agent_run.get('output_count', 0))}"
        )

    # Optional local Ollama explanation.
    assistant_explanation = agent_workflow["assistant_explanation"]

    if assistant_explanation["status"] == "generated":
        print(
            f"\nLocal Ollama explanation "
            f"({assistant_explanation['model']}):\n"
        )
        print(assistant_explanation["text"])
    elif enable_ai:
        print(
            f"\nLocal explanation nahi bani: "
            f"{assistant_explanation['reason']}"
        )

    # Warnings print karo.
    if warnings:
        print("\nWarnings:")

        for warning in warnings:
            print(f"  - {warning}")

    return (
        code_findings,
        advisories,
        warnings,
        dependency_graph,
        code_graph,
        agent_workflow,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan a repository for selected code and dependency risks."
        )
    )
    parser.add_argument(
        "project_folder",
        help="Scan karne wale project folder ka path",
    )
    parser.add_argument(
        "report_file",
        nargs="?",
        default="audit_report.json",
        help="JSON report ka path",
    )
    parser.add_argument(
        "--markdown-report",
        help=(
            "Markdown report ka path. Default JSON file ke "
            "naam ke saath .md hoga."
        ),
    )
    parser.add_argument(
        "--sarif-report",
        help=(
            "SARIF report ka path. Default JSON file ke "
            "naam ke saath .sarif hoga."
        ),
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Local Ollama model se explanation generate karo",
    )
    parser.add_argument(
        "--model",
        default=os.getenv(
            "OLLAMA_MODEL",
            "qwen2.5-coder:3b",
        ),
        help=(
            "Local Ollama model name; default OLLAMA_MODEL "
            "ya qwen2.5-coder:3b"
        ),
    )

    args = parser.parse_args()
    project_folder = Path(args.project_folder)

    if not project_folder.is_dir():
        print(f"Folder nahi mila: {project_folder}")
        raise SystemExit(1)

    (
        findings,
        advisories,
        warnings,
        dependency_graph,
        code_graph,
        agent_workflow,
    ) = scan_project(
        project_folder,
        enable_ai=args.ai,
        model=args.model,
    )

    report_path = save_json(
        findings,
        advisories,
        warnings,
        args.report_file,
        dependency_graph=dependency_graph,
        code_graph=code_graph,
        agent_workflow=agent_workflow,
    )

    if args.markdown_report:
        markdown_output = Path(args.markdown_report)
    else:
        markdown_output = report_path.with_suffix(".md")

    markdown_path = save_markdown_report(
        code_findings=findings,
        advisories=advisories,
        warnings=warnings,
        dependency_graph=dependency_graph,
        code_graph=code_graph,
        agent_workflow=agent_workflow,
        project_folder=project_folder,
        output_file=markdown_output,
    )

    if args.sarif_report:
        sarif_output = Path(args.sarif_report)
    else:
        sarif_output = report_path.with_suffix(".sarif")

    sarif_path = save_sarif_report(
        code_findings=findings,
        advisories=advisories,
        project_root=project_folder,
        agent_workflow=agent_workflow,
        output_file=sarif_output,
    )

    print(f"\nJSON report save hui: {report_path.resolve()}")
    print(f"Markdown report save hui: {markdown_path.resolve()}")
    print(f"SARIF report save hui: {sarif_path.resolve()}")


if __name__ == "__main__":
    main()