import re
from pathlib import Path

import tree_sitter_javascript as tree_sitter_javascript
from tree_sitter import Language, Parser

from models import Finding


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())
JAVASCRIPT_PARSER = Parser(JAVASCRIPT_LANGUAGE)

EXEC_FUNCTIONS = {"exec", "execSync"}
EVAL_FUNCTIONS = {"eval"}


def walk_nodes(root_node):
    """Syntax tree ke saare named nodes par chalta hai."""
    stack = [root_node]

    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def node_text(node, source_bytes):
    """Syntax node ka source text deta hai."""
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


def collect_child_process_imports(source_text):
    """
    child_process se import hue exec functions aur namespace aliases dhoondhta hai.

    Examples:
      const { exec } = require("child_process");
      const cp = require("node:child_process");
      import { exec as run } from "child_process";
      import * as cp from "node:child_process";
    """
    exec_names = set()
    namespace_names = {"child_process"}

    namespace_patterns = [
        re.compile(
            r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"""
            r"""require\s*\(\s*["'](?:node:)?child_process["']\s*\)"""
        ),
        re.compile(
            r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+"""
            r"""from\s+["'](?:node:)?child_process["']"""
        ),
    ]

    for pattern in namespace_patterns:
        for match in pattern.finditer(source_text):
            namespace_names.add(match.group(1))

    destructured_patterns = [
        re.compile(
            r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*"""
            r"""require\s*\(\s*["'](?:node:)?child_process["']\s*\)"""
        ),
        re.compile(
            r"""import\s*\{([^}]+)\}\s*from\s*"""
            r"""["'](?:node:)?child_process["']"""
        ),
    ]

    for pattern in destructured_patterns:
        for match in pattern.finditer(source_text):
            for item in match.group(1).split(","):
                parts = re.split(r"\s+as\s+|:", item.strip())
                if not parts:
                    continue

                imported_name = parts[0].strip()
                local_name = parts[-1].strip()

                if imported_name in EXEC_FUNCTIONS:
                    exec_names.add(local_name)

    return exec_names, namespace_names


def is_child_process_exec(function_node, source_bytes, exec_names, namespace_names):
    """Checks whether a call is a known child_process exec/execSync call."""
    function_name = node_text(function_node, source_bytes).strip()

    if function_node.type == "identifier":
        return function_name in exec_names

    if function_node.type != "member_expression":
        return False

    property_node = function_node.child_by_field_name("property")
    object_node = function_node.child_by_field_name("object")

    if property_node is None or object_node is None:
        return False

    property_name = node_text(property_node, source_bytes).strip()
    object_name = node_text(object_node, source_bytes).strip()

    return (
        property_name in EXEC_FUNCTIONS
        and (
            object_name in namespace_names
            or "child_process" in object_name
        )
    )


def is_dynamic_command(argument_node, source_bytes):
    """
    String literal command ko skip karta hai.
    Variable, template interpolation, concatenation, ya call expression
    ko dynamic samajh kar review ke liye report karta hai.
    """
    if argument_node.type == "string":
        return False

    if argument_node.type == "template_string":
        argument_bytes = source_bytes[
            argument_node.start_byte:argument_node.end_byte
        ]
        return b"${" in argument_bytes

    return True


def analyze_javascript_file(file_path):
    """JavaScript/JSX file me selected risky patterns dhoondhta hai."""
    source_path = Path(file_path)
    source_bytes = source_path.read_bytes()
    source_text = source_bytes.decode("utf-8", errors="replace")

    tree = JAVASCRIPT_PARSER.parse(source_bytes)
    root_node = tree.root_node

    imported_exec_names, namespace_names = collect_child_process_imports(
        source_text
    )

    findings = []

    for node in walk_nodes(root_node):
        if node.type != "call_expression":
            continue

        function_node = node.child_by_field_name("function")
        arguments_node = node.child_by_field_name("arguments")

        if function_node is None:
            continue

        function_name = node_text(function_node, source_bytes).strip()
        line_number = node.start_point.row + 1
        call_snippet = node_text(node, source_bytes).strip().replace("\n", " ")

        if (
            function_node.type == "identifier"
            and function_name in EVAL_FUNCTIONS
        ):
            findings.append(
                Finding(
                    rule_id="JS-EVAL-001",
                    title="Risky JavaScript eval() call",
                    file=str(source_path),
                    line=line_number,
                    message=(
                        "eval() dynamically evaluates JavaScript. "
                        "Review whether its input can be influenced by a user."
                    ),
                    evidence=[
                        f"Tree-sitter call expression: {call_snippet[:200]}"
                    ],
                )
            )
            continue

        if not is_child_process_exec(
            function_node,
            source_bytes,
            imported_exec_names,
            namespace_names,
        ):
            continue

        if arguments_node is None or not arguments_node.named_children:
            continue

        command_argument = arguments_node.named_children[0]

        if not is_dynamic_command(command_argument, source_bytes):
            continue

        argument_snippet = node_text(command_argument, source_bytes).strip()

        findings.append(
            Finding(
                rule_id="JS-CMD-001",
                title="Potential command injection in child_process",
                file=str(source_path),
                line=line_number,
                message=(
                    "child_process.exec() or execSync() runs a shell command. "
                    "Its command argument is dynamic; review whether untrusted "
                    "data can reach it. This rule does not prove taint."
                ),
                evidence=[
                    f"Command argument: {argument_snippet[:200]}",
                    f"Tree-sitter call expression: {call_snippet[:200]}",
                ],
            )
        )

    return findings