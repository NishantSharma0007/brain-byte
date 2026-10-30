# Automated Codebase Security Auditor

A Python command-line prototype that scans a local codebase for selected security issues and known vulnerable dependencies. It can trace supported input-to-command flows, build code and dependency graphs, and produce evidence-linked reports.

## Features

- Scans Python and JavaScript files for selected security patterns.
- Tracks selected tainted input flows, including supported JavaScript calls across named relative imports.
- Reads pinned Python dependencies from `requirements*.txt` and npm dependencies from `package-lock.json`.
- Checks dependency versions against OSV advisories.
- Builds code call graphs and dependency graphs.
- Coordinates rule-based code, dependency, and triage agents.
- Optionally uses a locally running Ollama model to explain findings.
- Creates JSON, Markdown, and SARIF reports.
- Suggests reviewable dependency update patches and validates them in a temporary copy.
- Runs a labeled benchmark from the command line and in GitHub Actions.

## Requirements

- Python 3.11 or newer
- Git
- Network access for OSV advisory lookups
- Node.js and npm for npm dependency patch suggestions
- Ollama is optional and used only for local AI explanations

## Installation

From the project folder, create and activate a virtual environment, then install the project dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-auditor.txt
```

## Scan a Project

Scan the included demo project:

```powershell
python scanner.py .\demo_project
```

To choose report paths explicitly:

```powershell
python scanner.py .\demo_project audit_report.json `
  --markdown-report audit_report.md `
  --sarif-report audit_report.sarif
```

The scanner prints findings and saves JSON, Markdown, and SARIF reports. It needs network access to query OSV when pinned dependencies are present.

## Local AI Explanations

Ollama is optional. Start Ollama and make sure the configured model is available, then run:

```powershell
python scanner.py .\demo_project --ai
```

AI explanations provide context for findings; they do not prove that a finding is exploitable or that code is secure.

## Dependency Patch Suggestions

Generate a reviewable patch for the included Python demo:

```powershell
python patch_suggestions.py .\demo_project
```

Validate the generated patch in a temporary copy:

```powershell
python patch_validator.py .\demo_project .\dependency_update_suggestions.patch
```

Patch validation checks whether the updated dependency still matches OSV advisories. It does not automatically prove project compatibility or run all project-specific tests. The original project files are not changed during validation. Review any generated patch before applying it.

## Labeled Benchmark

Run the benchmark examples:

```powershell
python benchmark.py
```

The current benchmark contains five small examples:

- Three vulnerable examples: Python, JavaScript, and JavaScript across two files.
- Two safe examples: Python and JavaScript.

A sample run produced `TP=3`, `TN=2`, `FP=0`, and `FN=0`. These results describe only the five included examples; they do not represent the scanner's general accuracy.

## GitHub Actions

The `Security Audit` workflow runs on pushes, pull requests, and manual dispatch. It runs the benchmark and scanner, can validate a dependency patch, uploads SARIF findings to GitHub Code Scanning, and saves reports as a downloadable workflow artifact.

The dependency draft pull request workflow can propose a reviewable dependency update. It does not automatically merge the proposed change.

## Project Structure

```text
.
├── .github/
│   └── workflows/
├── benchmarks/
├── demo_project/
├── agent_workflow.py
├── benchmark.py
├── call_graph.py
├── code_analysis.py
├── dependencies.py
├── dependency_graph.py
├── inventory.py
├── javascript_analysis.py
├── markdown_reporting.py
├── models.py
├── osv_lookup.py
├── patch_suggestions.py
├── patch_validator.py
├── reporting.py
├── requirements-auditor.txt
├── sarif_reporting.py
└── scanner.py
```

## Scope and Limitations

- This is a prototype using selected rules, not a complete replacement for a dedicated SAST or software composition analysis platform.
- Python code-flow analysis covers selected same-file patterns and calls.
- JavaScript code-flow analysis covers selected same-file calls and nested closures, plus named relative CommonJS and ESM imports.
- Dynamic imports, namespace or default imports, Python cross-file flows, and service-to-service data flows are not covered.
- Dependency scanning depends on the supported manifests, package data, and OSV responses.
- Findings and AI explanations require developer review. Passing the included benchmark does not guarantee that a codebase is secure.
- The vulnerable examples are for scanning demonstrations. Do not run them as applications.