# Automated Codebase Security Auditor

A Python command-line tool that scans a codebase for selected security patterns and known vulnerable dependencies. It creates JSON, Markdown, and SARIF reports, and can suggest a dependency update patch for review.

## Features

- Scans Python files for selected risky code patterns.
- Performs limited source-to-sink analysis for selected cases, such as user input reaching a shell command.
- Reads exactly pinned packages from `requirements*.txt` files.
- Looks up package versions in the OSV vulnerability database.
- Builds code call and dependency graphs.
- Produces JSON, Markdown, and SARIF reports.
- Optionally asks a locally running Ollama model to explain findings.
- Generates a reviewable dependency patch.
- Validates that patch in a temporary copy without changing the original project.

## Requirements

- Python 3.11 or newer
- Git
- Network access for OSV advisory lookups
- Ollama is optional and needed only for local AI explanations

Install the Python packages used by the project in your virtual environment:

```powershell
python -m pip install networkx requests