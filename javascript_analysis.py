import re
from pathlib import Path

import tree_sitter_javascript
from tree_sitter import Language, Parser

from models import Finding


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())
JAVASCRIPT_PARSER = Parser(JAVASCRIPT_LANGUAGE)

EXEC_FUNCTIONS = {"exec", "execSync"}
EVAL_FUNCTIONS = {"eval"}

FUNCTION_NODE_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
}

SOURCE_PATTERNS = (
    (
        re.compile(
            r"\b(?:req|request)\s*\.\s*"
            r"(?:query|body|params|cookies)\b"
        ),
        "Web request data source",
    ),
    (
        re.compile(r"\bprocess\s*\.\s*argv\b"),
        "Command-line argument source",
    ),
    (
        re.compile(r"\b(?:window\s*\.\s*)?location\s*\.\s*(?:search|hash)\b"),
        "Browser URL input source",
    ),
    (
        re.compile(r"\bevent\s*\.\s*data\b"),
        "Event data source",
    ),
)


def walk_nodes(root_node):
    """Syntax tree ke named nodes par chalta hai."""
    stack = [root_node]

    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def node_text(node, source_bytes):
    """Tree-sitter node ka source text deta hai."""
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


def unique_strings(values):
    """Evidence ko duplicate entries ke bina return karta hai."""
    return list(dict.fromkeys(values))


def source_evidence(node, source_bytes):
    """Node me known user-input source ho to uska evidence deta hai."""
    text = node_text(node, source_bytes)
    line_number = node.start_point.row + 1
    evidence = []

    for pattern, description in SOURCE_PATTERNS:
        if pattern.search(text):
            evidence.append(f"{description} at line {line_number}.")

    return unique_strings(evidence)


def identifier_names(node, source_bytes):
    """Expression ke identifier names collect karta hai."""
    names = set()

    for child in walk_nodes(node):
        if child.type == "identifier":
            names.add(node_text(child, source_bytes))

    return names


def assignment_parts(node):
    """Supported assignment node se target aur value nikalta hai."""
    if node.type == "variable_declarator":
        target = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
    elif node.type == "assignment_expression":
        target = node.child_by_field_name("left")
        value = node.child_by_field_name("right")
    else:
        return None, None

    if target is None or value is None:
        return None, None

    if target.type != "identifier":
        return None, None

    return target, value


def nodes_in_scope(scope_root):
    """
    Ek scope ke nodes deta hai.
    Nested function bodies ko us scope se alag rakhta hai.
    """
    stack = [scope_root]

    while stack:
        node = stack.pop()

        if node is not scope_root and node.type in FUNCTION_NODE_TYPES:
            continue

        yield node
        stack.extend(reversed(node.named_children))


def collect_tainted_variables(scope_nodes, source_bytes):
    """
    Scope ke andar source values se assignments tak taint propagate karta hai.
    """
    assignments = []

    for node in scope_nodes:
        target, value = assignment_parts(node)

        if target is not None and value is not None:
            assignments.append((node, target, value))

    assignments.sort(key=lambda item: item[0].start_byte)

    taint_evidence = {}
    max_iterations = len(assignments) + 1

    for _ in range(max_iterations):
        changed = False

        for assignment_node, target_node, value_node in assignments:
            target_name = node_text(target_node, source_bytes)
            evidence = []

            evidence.extend(source_evidence(value_node, source_bytes))

            for name in identifier_names(value_node, source_bytes):
                evidence.extend(taint_evidence.get(name, []))

            if not evidence:
                continue

            assignment_line = assignment_node.start_point.row + 1
            evidence.append(
                f"Assigned to '{target_name}' at line {assignment_line}."
            )
            evidence = unique_strings(evidence)

            old_evidence = taint_evidence.get(target_name, [])
            combined_evidence = unique_strings(old_evidence + evidence)

            if combined_evidence != old_evidence:
                taint_evidence[target_name] = combined_evidence
                changed = True

        if not changed:
            break

    return taint_evidence


def expression_taint_evidence(node, source_bytes, taint_evidence):
    """Expression me direct source ya tainted variable check karta hai."""
    evidence = []
    evidence.extend(source_evidence(node, source_bytes))

    for name in identifier_names(node, source_bytes):
        evidence.extend(taint_evidence.get(name, []))

    return unique_strings(evidence)


def collect_child_process_imports(source_text):
    """
    child_process se imported exec/execSync names aur namespace aliases dhoondhta hai.
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


def is_child_process_exec(
    function_node,
    source_bytes,
    exec_names,
    namespace_names,
):
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
    """Static string commands ko skip karke dynamic expressions identify karta hai."""
    if argument_node.type == "string":
        return False

    if argument_node.type == "template_string":
        argument_bytes = source_bytes[
            argument_node.start_byte:argument_node.end_byte
        ]
        return b"${" in argument_bytes

    return True


def analyze_javascript_file(file_path):
    """JavaScript/JSX file me selected risky patterns aur local taint flows dhoondhta hai."""
    source_path = Path(file_path)
    source_bytes = source_path.read_bytes()
    source_text = source_bytes.decode("utf-8", errors="replace")

    tree = JAVASCRIPT_PARSER.parse(source_bytes)
    root_node = tree.root_node

    imported_exec_names, namespace_names = collect_child_process_imports(
        source_text
    )

    findings = []
    reported_eval_calls = set()

    # eval() rule har scope me detect hota hai.
    for node in walk_nodes(root_node):
        if node.type != "call_expression":
            continue

        function_node = node.child_by_field_name("function")

        if function_node is None or function_node.type != "identifier":
            continue

        function_name = node_text(function_node, source_bytes).strip()

        if function_name not in EVAL_FUNCTIONS:
            continue

        line_number = node.start_point.row + 1

        if line_number in reported_eval_calls:
            continue

        reported_eval_calls.add(line_number)
        call_snippet = node_text(node, source_bytes).strip().replace("\n", " ")

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

    # Module scope aur har function ka local scope alag analyze karo.
    scope_roots = [root_node]

    for node in walk_nodes(root_node):
        if node.type not in FUNCTION_NODE_TYPES:
            continue

        body_node = node.child_by_field_name("body")

        if body_node is not None:
            scope_roots.append(body_node)

    seen_scope_roots = set()

    for scope_root in scope_roots:
        scope_key = (
            scope_root.start_byte,
            scope_root.end_byte,
            scope_root.type,
        )

        if scope_key in seen_scope_roots:
            continue

        seen_scope_roots.add(scope_key)

        scope_nodes = list(nodes_in_scope(scope_root))
        taint_evidence = collect_tainted_variables(
            scope_nodes,
            source_bytes,
        )

        for node in scope_nodes:
            if node.type != "call_expression":
                continue

            function_node = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")

            if function_node is None or arguments_node is None:
                continue

            if not is_child_process_exec(
                function_node,
                source_bytes,
                imported_exec_names,
                namespace_names,
            ):
                continue

            arguments = arguments_node.named_children

            if not arguments:
                continue

            command_argument = arguments[0]

            if not is_dynamic_command(command_argument, source_bytes):
                continue

            line_number = node.start_point.row + 1
            call_snippet = node_text(node, source_bytes).strip()
            call_snippet = call_snippet.replace("\n", " ")[:200]

            flow_evidence = expression_taint_evidence(
                command_argument,
                source_bytes,
                taint_evidence,
            )

            if flow_evidence:
                title = (
                    "Potential command injection: input reaches child_process"
                )
                message = (
                    "A recognized request, browser URL, or command-line input "
                    "can reach a dynamic child_process shell command in the "
                    "same function scope. Review and validate this flow."
                )
                evidence = flow_evidence + [
                    f"child_process shell sink at line {line_number}.",
                    f"Tree-sitter call expression: {call_snippet}",
                ]
            else:
                title = "Potential command injection in child_process"
                message = (
                    "child_process.exec() or execSync() runs a shell command. "
                    "Its command argument is dynamic; review whether untrusted "
                    "data can reach it. This rule does not prove taint."
                )
                evidence = [
                    f"Dynamic command argument at line {line_number}.",
                    f"Tree-sitter call expression: {call_snippet}",
                ]

            findings.append(
                Finding(
                    rule_id="JS-CMD-001",
                    title=title,
                    file=str(source_path),
                    line=line_number,
                    message=message,
                    evidence=unique_strings(evidence),
                )
            )

    return findings