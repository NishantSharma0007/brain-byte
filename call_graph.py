import ast
from pathlib import Path

import tree_sitter_javascript
from tree_sitter import Language, Parser

from inventory import find_javascript_files
from javascript_analysis import (
    parse_named_module_exports,
    parse_named_module_imports,
)


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())
JAVASCRIPT_PARSER = Parser(JAVASCRIPT_LANGUAGE)

NESTED_JAVASCRIPT_FUNCTION_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
}


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


def add_file_node(relative_path, language, nodes, seen_nodes):
    file_node_id = f"file:{relative_path}"

    if file_node_id not in seen_nodes:
        nodes.append({
            "id": file_node_id,
            "type": "FILE",
            "language": language,
        })
        seen_nodes.add(file_node_id)

    return file_node_id


def add_function_node(
    relative_path,
    function_name,
    line_number,
    language,
    nodes,
    edges,
    seen_nodes,
    seen_edges,
):
    file_node_id = f"file:{relative_path}"
    function_id = f"{relative_path}::{function_name}"

    if file_node_id not in seen_nodes:
        nodes.append({
            "id": file_node_id,
            "type": "FILE",
            "language": language,
        })
        seen_nodes.add(file_node_id)

    if function_id not in seen_nodes:
        nodes.append({
            "id": function_id,
            "type": "FUNCTION",
            "file": relative_path,
            "line": line_number,
            "language": language,
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

    return function_id


def add_call_edge(
    caller_id,
    target_id,
    line_number,
    edges,
    seen_edges,
):
    edge_key = (
        caller_id,
        target_id,
        "CALLS",
        line_number,
    )

    if edge_key in seen_edges:
        return

    edges.append({
        "from": caller_id,
        "to": target_id,
        "type": "CALLS",
        "line": line_number,
    })
    seen_edges.add(edge_key)


def add_python_graph(
    project_root,
    python_files,
    nodes,
    edges,
    seen_nodes,
    seen_edges,
):
    for file_path in python_files:
        file_path = Path(file_path)

        try:
            resolved_path = file_path.resolve()
            relative_path = resolved_path.relative_to(
                project_root
            ).as_posix()

            source = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            tree = ast.parse(source, filename=relative_path)
        except (OSError, SyntaxError, ValueError, RecursionError):
            continue

        add_file_node(
            relative_path,
            "python",
            nodes,
            seen_nodes,
        )

        functions = {
            node.name: node
            for node in tree.body
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            )
        }

        for function_name, function_node in functions.items():
            add_function_node(
                relative_path,
                function_name,
                function_node.lineno,
                "python",
                nodes,
                edges,
                seen_nodes,
                seen_edges,
            )

        for function_name, function_node in functions.items():
            caller_id = f"{relative_path}::{function_name}"
            collector = CallCollector()

            for statement in function_node.body:
                collector.visit(statement)

            for call in collector.calls:
                # Sirf isi file ke top-level functions include karo.
                if not isinstance(call.func, ast.Name):
                    continue

                target_name = get_call_name(call.func)

                if target_name not in functions:
                    continue

                target_id = f"{relative_path}::{target_name}"

                add_call_edge(
                    caller_id,
                    target_id,
                    call.lineno,
                    edges,
                    seen_edges,
                )


def node_text(node, source_bytes):
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


def top_level_javascript_statements(root_node):
    """
    Top-level statements deta hai.
    export statement ke andar wali declaration bhi include hoti hai.
    """
    for statement in root_node.named_children:
        if statement.type == "export_statement":
            for exported_statement in statement.named_children:
                yield exported_statement
        else:
            yield statement


def find_top_level_javascript_functions(root_node, source_bytes):
    """
    Top-level function declarations aur
    const/let/var name = () => {} functions dhoondhta hai.
    """
    functions = {}

    for statement in top_level_javascript_statements(root_node):
        if statement.type == "function_declaration":
            name_node = statement.child_by_field_name("name")
            body_node = statement.child_by_field_name("body")

            if name_node is None or body_node is None:
                continue

            function_name = node_text(name_node, source_bytes)

            functions[function_name] = {
                "node": statement,
                "body": body_node,
                "line": statement.start_point.row + 1,
            }
            continue

        if statement.type not in {
            "lexical_declaration",
            "variable_declaration",
        }:
            continue

        for declaration in statement.named_children:
            if declaration.type != "variable_declarator":
                continue

            name_node = declaration.child_by_field_name("name")
            value_node = declaration.child_by_field_name("value")

            if name_node is None or value_node is None:
                continue

            if value_node.type not in {
                "arrow_function",
                "function_expression",
            }:
                continue

            function_name = node_text(name_node, source_bytes)
            body_node = value_node.child_by_field_name("body")

            if body_node is None:
                continue

            functions[function_name] = {
                "node": value_node,
                "body": body_node,
                "line": declaration.start_point.row + 1,
            }

    return functions


def javascript_calls_in_function(body_node):
    """
    Function body ke calls deta hai.
    Nested functions ke andar jaakar calls caller ko assign nahi karta.
    """
    stack = list(reversed(body_node.named_children))

    while stack:
        node = stack.pop()

        if node.type in NESTED_JAVASCRIPT_FUNCTION_TYPES:
            continue

        if node.type == "call_expression":
            yield node

        stack.extend(reversed(node.named_children))


def add_javascript_graph(
    project_root,
    javascript_files,
    nodes,
    edges,
    seen_nodes,
    seen_edges,
):
    file_records = {}

    for file_path in javascript_files:
        file_path = Path(file_path)

        try:
            resolved_path = file_path.resolve()
            relative_path = resolved_path.relative_to(
                project_root
            ).as_posix()
            source_bytes = file_path.read_bytes()
            tree = JAVASCRIPT_PARSER.parse(source_bytes)
        except (OSError, ValueError, RecursionError):
            continue

        add_file_node(
            relative_path,
            "javascript",
            nodes,
            seen_nodes,
        )

        functions = find_top_level_javascript_functions(
            tree.root_node,
            source_bytes,
        )
        file_records[str(resolved_path)] = {
            "relative_path": relative_path,
            "source_bytes": source_bytes,
            "tree": tree,
            "functions": functions,
            "imports": parse_named_module_imports(
                source_bytes.decode("utf-8", errors="replace"),
                resolved_path,
                javascript_files,
            ),
            "exports": parse_named_module_exports(
                source_bytes.decode("utf-8", errors="replace")
            ),
        }

        for function_name, function_info in functions.items():
            add_function_node(
                relative_path,
                function_name,
                function_info["line"],
                "javascript",
                nodes,
                edges,
                seen_nodes,
                seen_edges,
            )

        for function_name, function_info in functions.items():
            caller_id = f"{relative_path}::{function_name}"

            for call in javascript_calls_in_function(
                function_info["body"]
            ):
                function_node = call.child_by_field_name("function")

                if function_node is None:
                    continue

                # Is version mein direct same-file function names hi match hote hain.
                if function_node.type != "identifier":
                    continue

                target_name = node_text(
                    function_node,
                    source_bytes,
                )

                if target_name not in functions:
                    continue

                target_id = f"{relative_path}::{target_name}"
                line_number = call.start_point.row + 1

                add_call_edge(
                    caller_id,
                    target_id,
                    line_number,
                    edges,
                    seen_edges,
                )

    # Imported relative named calls ko second pass mein connect karo, ab jab
    # project ke saare function aur export nodes ban chuke hain.
    for caller_file_key, caller_record in file_records.items():
        for function_name, function_info in caller_record["functions"].items():
            caller_id = (
                f"{caller_record['relative_path']}::{function_name}"
            )

            for call in javascript_calls_in_function(function_info["body"]):
                called_function = call.child_by_field_name("function")
                if called_function is None or called_function.type != "identifier":
                    continue

                local_name = node_text(
                    called_function,
                    caller_record["source_bytes"],
                )
                binding = caller_record["imports"].get(local_name)
                if binding is None:
                    continue

                target_file_key, exported_name = binding
                target_record = file_records.get(target_file_key)
                if target_record is None:
                    continue

                target_function_name = target_record["exports"].get(
                    exported_name
                )
                if (
                    target_function_name is None
                    or target_function_name not in target_record["functions"]
                ):
                    continue

                target_id = (
                    f"{target_record['relative_path']}::"
                    f"{target_function_name}"
                )
                add_call_edge(
                    caller_id,
                    target_id,
                    call.start_point.row + 1,
                    edges,
                    seen_edges,
                )


def build_call_graph(
    project_folder,
    python_files,
    javascript_files=None,
):
    project_root = Path(project_folder).resolve()

    if javascript_files is None:
        javascript_files = find_javascript_files(project_root)

    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    add_python_graph(
        project_root,
        python_files,
        nodes,
        edges,
        seen_nodes,
        seen_edges,
    )

    add_javascript_graph(
        project_root,
        javascript_files,
        nodes,
        edges,
        seen_nodes,
        seen_edges,
    )

    return {
        "scope": (
            "Same-file top-level Python and JavaScript calls, plus resolved "
            "named relative JavaScript imports. Python imported, dynamic, "
            "nested, and class-method calls are not included."
        ),
        "nodes": nodes,
        "edges": edges,
    }
