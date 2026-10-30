import ast
from pathlib import Path


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    return ""


class CallCollector(ast.NodeVisitor):
    def __init__(self):
        self.calls = []

    def visit_Call(self, node):
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Nested functions is version mein alag graph nodes nahi hain.
        return

    def visit_AsyncFunctionDef(self, node):
        return

    def visit_ClassDef(self, node):
        return


def build_call_graph(project_folder, python_files):
    root = Path(project_folder).resolve()
    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    for file_path in python_files:
        file_path = Path(file_path)

        try:
            relative_path = file_path.resolve().relative_to(root).as_posix()
            source = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            tree = ast.parse(source, filename=relative_path)
        except (OSError, SyntaxError, ValueError):
            continue

        file_node_id = f"file:{relative_path}"

        if file_node_id not in seen_nodes:
            nodes.append({
                "id": file_node_id,
                "type": "FILE",
            })
            seen_nodes.add(file_node_id)

        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        for function_name, function_node in functions.items():
            function_id = f"{relative_path}::{function_name}"

            if function_id not in seen_nodes:
                nodes.append({
                    "id": function_id,
                    "type": "FUNCTION",
                    "file": relative_path,
                    "line": function_node.lineno,
                })
                seen_nodes.add(function_id)

            define_edge = (
                file_node_id,
                function_id,
                "DEFINES",
            )

            if define_edge not in seen_edges:
                edges.append({
                    "from": file_node_id,
                    "to": function_id,
                    "type": "DEFINES",
                })
                seen_edges.add(define_edge)

        for function_name, function_node in functions.items():
            caller_id = f"{relative_path}::{function_name}"
            collector = CallCollector()

            for statement in function_node.body:
                collector.visit(statement)

            for call in collector.calls:
                # Sirf usi file mein defined top-level function calls include karo.
                if not isinstance(call.func, ast.Name):
                    continue

                target_name = get_call_name(call.func)

                if target_name not in functions:
                    continue

                target_id = f"{relative_path}::{target_name}"
                edge_key = (
                    caller_id,
                    target_id,
                    "CALLS",
                    call.lineno,
                )

                if edge_key in seen_edges:
                    continue

                edges.append({
                    "from": caller_id,
                    "to": target_id,
                    "type": "CALLS",
                    "line": call.lineno,
                })
                seen_edges.add(edge_key)

    return {
        "scope": (
            "Same-file calls between top-level Python functions. "
            "Imported, dynamic, nested, and class method calls are not included yet."
        ),
        "nodes": nodes,
        "edges": edges,
    }