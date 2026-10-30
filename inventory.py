import os
from pathlib import Path


SKIP_FOLDERS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    ".next",
}

JAVASCRIPT_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
}


def find_python_files(project_folder):
    root = Path(project_folder).resolve()
    python_files = []

    for current_folder, folders, filenames in os.walk(root):
        folders[:] = [
            folder for folder in folders
            if folder not in SKIP_FOLDERS
        ]

        for filename in filenames:
            if Path(filename).suffix.lower() == ".py":
                python_files.append(Path(current_folder) / filename)

    return python_files


def find_javascript_files(project_folder):
    root = Path(project_folder).resolve()
    javascript_files = []

    for current_folder, folders, filenames in os.walk(root):
        folders[:] = [
            folder for folder in folders
            if folder not in SKIP_FOLDERS
        ]

        for filename in filenames:
            if Path(filename).suffix.lower() in JAVASCRIPT_EXTENSIONS:
                javascript_files.append(Path(current_folder) / filename)

    return javascript_files