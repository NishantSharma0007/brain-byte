import os
from pathlib import Path


SKIP_FOLDERS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
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
            if filename.endswith(".py"):
                python_files.append(Path(current_folder) / filename)

    return python_files