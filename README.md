# Automated Codebase Security Auditor

A Python command-line prototype that scans local codebases for selected security patterns and known vulnerable dependencies. It traces supported input-to-command flows, builds code and dependency graphs, and creates evidence-linked reports.

## Features

- Scans Python and JavaScript files for selected security patterns.
- Tracks selected tainted input flows through supported function calls.
- Supports JavaScript same-file flows and named relative CommonJS and ESM imports.
- Reads pinned Python dependencies from `requirements*.txt` and npm dependencies from `package-lock.json`.
- Checks dependencies against OSV advisories.
- Builds code call graphs and dependency graphs.
- Coordinates rule-based code, dependency, and triage agents.
- Optionally uses a local Ollama model to explain findings.
- Produces JSON, Markdown, and SARIF reports.
- Suggests dependency update patches and validates them in a temporary copy.
- Runs labeled code and dependency benchmarks from the command line and GitHub Actions.

## Requirements

- Python 3.11 or newer
- Git
- Network access for OSV advisory lookups
- Node.js and npm for npm dependency patch suggestions
- Ollama is optional and needed only for local AI explanations

## Installation

From the project folder, create and activate a virtual environment, then install the auditor dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-auditor.txt
```

## Scan a Project

Scan the included Python demo project:

```powershell
python scanner.py .\demo_project
```

Scan the included npm dependency demo:

```powershell
python scanner.py .\demo_npm
```

To choose report paths explicitly:

```powershell
python scanner.py .\demo_project audit_report.json `
  --markdown-report audit_report.md `
  --sarif-report audit_report.sarif
```

The scanner prints findings and saves JSON, Markdown, and SARIF reports. OSV lookups need network access when pinned dependencies are present.

## Local AI Explanations

Ollama is optional. Make sure Ollama is running and the configured model is available, then run:

```powershell
python scanner.py .\demo_project --ai
```

AI explanations use the scanner's findings as input. They do not prove that a finding is exploitable or that an application is secure.

## Dependency Patch Suggestions

Generate a reviewable patch for the included Python demo:

```powershell
python patch_suggestions.py .\demo_project
```

Validate the patch in a temporary copy:

```powershell
python patch_validator.py .\demo_project .\dependency_update_suggestions.patch
```

Validation checks whether the updated dependency still matches OSV advisories. It does not prove compatibility or automatically run all project-specific tests. The original project files are not changed during validation. Review any proposed patch before applying it.

## Benchmarking

Run the labeled examples with:

```powershell
python benchmark.py
```

The benchmark evaluates code findings and dependency advisories separately:

- Code set: five examples—three vulnerable and two safe.
- Dependency set: two examples—one vulnerable package and one updated package.

The latest run produced:

- Code: TP=3, TN=2, FP=0, FN=0.
- Dependencies: TP=1, TN=1, FP=0, FN=0.

These results describe only the included demo examples; they do not represent the scanner's general accuracy. Dependency benchmark results use live OSV data and require network access.

## GitHub Actions

The `Security Audit` workflow runs on pushes, pull requests, and manual dispatch. It runs the benchmark and scanner, can validate a dependency patch, uploads SARIF findings to GitHub Code Scanning, and saves reports as a downloadable workflow artifact.

The dependency draft pull request workflow can propose a reviewable dependency update. It does not automatically merge the proposed change.

## Project Structure

```text
.
├── .github/
│   └── workflows/
├── benchmarks/
│   ├── dep_py_safe/
│   ├── dep_py_vulnerable/
│   ├── js_cross_file/
│   ├── js_safe/
│   ├── js_vulnerable/
│   ├── py_safe/
│   └── py_vulnerable/
├── demo_npm/
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

- This is a prototype that checks selected patterns; it is not a complete replacement for a dedicated SAST or software composition analysis platform.
- Python code-flow analysis covers selected same-file patterns and calls.
- JavaScript code-flow analysis covers selected same-file calls and nested closures, plus named relative CommonJS and ESM imports.
- Dynamic imports, namespace or default imports, Python cross-file flows, and service-to-service data flows are not covered.
- Dependency scanning depends on supported manifests, package data, and OSV responses.
- Findings and AI explanations need developer review. Passing the included benchmark does not guarantee a codebase is secure.
- The vulnerable examples are for scanner demonstrations. Do not run them as applications.