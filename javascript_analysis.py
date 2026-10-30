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


def collect_tainted_variables(scope_nodes, source_bytes, initial_taint=None):
    """
    Scope ke andar source values se assignments tak taint propagate karta hai.
    """
    assignments = []

    for node in scope_nodes:
        target, value = assignment_parts(node)

        if target is not None and value is not None:
            assignments.append((node, target, value))

    assignments.sort(key=lambda item: item[0].start_byte)

    taint_evidence = {
        name: unique_strings(evidence)
        for name, evidence in (initial_taint or {}).items()
    }
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


def parameter_name(parameter_node, source_bytes):
    """Simple identifier/default/rest function parameters ko read karta hai."""
    if parameter_node.type == "identifier":
        return node_text(parameter_node, source_bytes)

    if parameter_node.type == "assignment_pattern":
        left_node = parameter_node.child_by_field_name("left")
        if left_node is not None and left_node.type == "identifier":
            return node_text(left_node, source_bytes)

    if parameter_node.type == "rest_pattern":
        for child in parameter_node.named_children:
            if child.type == "identifier":
                return node_text(child, source_bytes)

    return None


def javascript_function_info(function_node, source_bytes):
    """Function ka naam, parameters aur body nikalta hai."""
    body_node = function_node.child_by_field_name("body")
    if body_node is None:
        return None

    name_node = function_node.child_by_field_name("name")

    if name_node is None:
        parent_node = function_node.parent
        if (
            parent_node is not None
            and parent_node.type == "variable_declarator"
        ):
            name_node = parent_node.child_by_field_name("name")

    function_name = (
        node_text(name_node, source_bytes)
        if name_node is not None and name_node.type == "identifier"
        else None
    )

    parameters_node = (
        function_node.child_by_field_name("parameters")
        or function_node.child_by_field_name("parameter")
    )
    parameter_names = []

    if parameters_node is not None:
        if parameters_node.type == "identifier":
            parameter_names.append(
                node_text(parameters_node, source_bytes)
            )
        else:
            for parameter_node in parameters_node.named_children:
                name = parameter_name(parameter_node, source_bytes)
                if name:
                    parameter_names.append(name)

    return {
        "name": function_name,
        "parameters": parameter_names,
        "body": body_node,
        "node": function_node,
        "key": f"{function_name or '<anonymous>'}@{function_node.start_byte}",
        "nodes": list(nodes_in_scope(body_node)),
    }


def collect_javascript_functions(root_node, source_bytes):
    """File ke supported function declarations aur function expressions collect karta hai."""
    functions = []

    for node in walk_nodes(root_node):
        if node.type not in FUNCTION_NODE_TYPES:
            continue

        info = javascript_function_info(node, source_bytes)
        if info is not None:
            functions.append(info)

    return functions


def propagate_function_parameter_taint(
    functions,
    source_bytes=None,
    module_imports=None,
    module_exports=None,
    initial_parameter_taint=None,
):
    """
    Same-file calls aur resolved named module imports mein tainted arguments
    ko callee parameters tak propagate karta hai.
    """
    functions_by_file_name = {}

    for function in functions:
        if function["name"]:
            functions_by_file_name.setdefault(
                (function.get("file_key"), function["name"]),
                [],
            ).append(function)

    parameter_taint = {
        function["key"]: {
            parameter: []
            for parameter in function["parameters"]
        }
        for function in functions
    }
    for function_key, seeded_parameters in (initial_parameter_taint or {}).items():
        if function_key not in parameter_taint:
            continue
        for parameter, evidence in seeded_parameters.items():
            if parameter not in parameter_taint[function_key]:
                continue
            parameter_taint[function_key][parameter] = unique_strings(
                parameter_taint[function_key][parameter] + evidence
            )

    max_iterations = sum(
        len(function["parameters"])
        for function in functions
    ) + 1

    for _ in range(max_iterations):
        changed = False

        for caller in functions:
            caller_source = caller.get("source_bytes", source_bytes)
            if caller_source is None:
                continue

            caller_taint = collect_tainted_variables(
                caller["nodes"],
                caller_source,
                parameter_taint[caller["key"]],
            )

            for call_node in caller["nodes"]:
                if call_node.type != "call_expression":
                    continue

                called_function_node = call_node.child_by_field_name(
                    "function"
                )
                arguments_node = call_node.child_by_field_name(
                    "arguments"
                )

                if (
                    called_function_node is None
                    or called_function_node.type != "identifier"
                    or arguments_node is None
                ):
                    continue

                target_name = node_text(
                    called_function_node,
                    caller_source,
                )
                caller_file_key = caller.get("file_key")
                callees = functions_by_file_name.get(
                    (caller_file_key, target_name),
                    [],
                )

                # Cross-file propagation only follows an imported, exported
                # named function. This avoids matching unrelated functions
                # that happen to share a name.
                if not callees:
                    imported_binding = (module_imports or {}).get(
                        caller_file_key,
                        {},
                    ).get(target_name)

                    if imported_binding:
                        target_file_key, exported_name = imported_binding
                        local_name = (module_exports or {}).get(
                            target_file_key,
                            {},
                        ).get(exported_name)

                        if local_name:
                            callees = functions_by_file_name.get(
                                (target_file_key, local_name),
                                [],
                            )

                if not callees:
                    continue

                arguments = arguments_node.named_children
                call_line = call_node.start_point.row + 1

                for callee in callees:
                    for index, argument in enumerate(arguments):
                        if index >= len(callee["parameters"]):
                            continue

                        parameter = callee["parameters"][index]
                        evidence = expression_taint_evidence(
                            argument,
                            caller_source,
                            caller_taint,
                        )

                        if not evidence:
                            continue

                        caller_file_key = caller.get("file_key")
                        callee_file_key = callee.get("file_key")
                        if (
                            caller_file_key
                            and callee_file_key
                            and caller_file_key != callee_file_key
                        ):
                            caller_file_name = Path(caller_file_key).name
                            callee_file_name = Path(callee_file_key).name
                            evidence.extend([
                                (
                                    f"Cross-file call from {caller_file_name} "
                                    f"line {call_line} passes tainted data to "
                                    f"parameter '{parameter}' of "
                                    f"{target_name}() in {callee_file_name}."
                                ),
                                (
                                    f"Function parameter '{parameter}' is "
                                    f"tainted inside {callee_file_name}."
                                ),
                            ])
                        else:
                            evidence.extend([
                                (
                                    f"Tainted value passed to parameter "
                                    f"'{parameter}' of {target_name}() "
                                    f"at line {call_line}."
                                ),
                                (
                                    f"Function parameter '{parameter}' is "
                                    f"tainted inside {target_name}()."
                                ),
                            ])
                        evidence = unique_strings(evidence)

                        old_evidence = parameter_taint[
                            callee["key"]
                        ].get(parameter, [])
                        combined = unique_strings(
                            old_evidence + evidence
                        )

                        if combined != old_evidence:
                            parameter_taint[callee["key"]][
                                parameter
                            ] = combined
                            changed = True

        if not changed:
            break

    return parameter_taint


def resolve_relative_module(importer_path, module_specifier, available_files):
    """Project ke supported JS file paths mein relative module resolve karta hai."""
    if not module_specifier.startswith("."):
        return None

    base_path = Path(importer_path).parent / module_specifier
    candidates = [base_path]

    if not base_path.suffix:
        for extension in (".js", ".jsx", ".mjs", ".cjs"):
            candidates.append(Path(f"{base_path}{extension}"))
        for extension in (".js", ".jsx", ".mjs", ".cjs"):
            candidates.append(base_path / f"index{extension}")

    available_by_key = {
        str(Path(path).resolve()): Path(path).resolve()
        for path in available_files
    }

    for candidate in candidates:
        key = str(candidate.resolve())
        if key in available_by_key:
            return key

    return None


def parse_named_module_imports(source_text, source_path, available_files):
    """CommonJS/ESM named relative imports ko local names se map karta hai."""
    imports = {}
    patterns = (
        re.compile(
            r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*(['\"])(\.{1,2}/[^'\"]+)\2\s*\)"""
        ),
        re.compile(
            r"""import\s*\{([^}]+)\}\s*from\s*(['\"])(\.{1,2}/[^'\"]+)\2"""
        ),
    )

    for pattern in patterns:
        for match in pattern.finditer(source_text):
            bindings_text = match.group(1)
            module_specifier = match.group(3)
            target_file_key = resolve_relative_module(
                source_path,
                module_specifier,
                available_files,
            )
            if target_file_key is None:
                continue

            for item in bindings_text.split(","):
                item = item.strip()
                if not item:
                    continue

                if ":" in item:
                    imported_name, local_name = item.split(":", 1)
                elif re.search(r"\s+as\s+", item):
                    imported_name, local_name = re.split(
                        r"\s+as\s+",
                        item,
                        maxsplit=1,
                    )
                else:
                    imported_name = local_name = item

                imported_name = imported_name.strip()
                local_name = local_name.strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", imported_name) and re.fullmatch(
                    r"[A-Za-z_$][\w$]*",
                    local_name,
                ):
                    imports[local_name] = (target_file_key, imported_name)

    return imports


def parse_named_module_exports(source_text):
    """Supported CommonJS/ESM export syntaxes ko function-name map mein badalta hai."""
    exports = {}

    def add_object_bindings(bindings_text):
        for item in bindings_text.split(","):
            item = item.strip()
            if not item:
                continue
            if ":" in item:
                exported_name, local_name = item.split(":", 1)
            else:
                exported_name = local_name = item
            exported_name = exported_name.strip()
            local_name = local_name.strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", exported_name) and re.fullmatch(
                r"[A-Za-z_$][\w$]*",
                local_name,
            ):
                exports[exported_name] = local_name

    def add_esm_bindings(bindings_text):
        for item in bindings_text.split(","):
            item = item.strip()
            if not item:
                continue
            alias_match = re.fullmatch(
                r"([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)",
                item,
            )
            if alias_match:
                local_name, exported_name = alias_match.groups()
            else:
                local_name = exported_name = item
            if re.fullmatch(r"[A-Za-z_$][\w$]*", local_name):
                exports[exported_name] = local_name

    for match in re.finditer(
        r"\bmodule\.exports\s*=\s*\{([^}]*)\}",
        source_text,
    ):
        add_object_bindings(match.group(1))

    assignment_patterns = (
        r"\bexports\.([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)",
        r"\bmodule\.exports\.([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)",
    )
    for pattern in assignment_patterns:
        for match in re.finditer(pattern, source_text):
            exports[match.group(1)] = match.group(2)

    declaration_pattern = re.compile(
        r"\bexport\s+(?:(?:async\s+)?function|(?:const|let|var|class))\s+"
        r"([A-Za-z_$][\w$]*)"
    )
    for match in declaration_pattern.finditer(source_text):
        exports[match.group(1)] = match.group(1)

    for match in re.finditer(
        r"\bexport\s*\{([^}]*)\}",
        source_text,
    ):
        add_esm_bindings(match.group(1))

    return exports


def collect_project_function_parameter_taint(file_paths):
    """Project ke relative imports follow karke cross-file taint seeds banata hai."""
    records = {}
    all_files = [Path(path).resolve() for path in file_paths]

    for file_path in all_files:
        try:
            source_bytes = file_path.read_bytes()
            source_text = source_bytes.decode("utf-8", errors="replace")
            tree = JAVASCRIPT_PARSER.parse(source_bytes)
        except OSError:
            continue

        file_key = str(file_path)
        records[file_key] = {
            "path": file_path,
            "source_bytes": source_bytes,
            "source_text": source_text,
            "root": tree.root_node,
            "imports": parse_named_module_imports(
                source_text,
                file_path,
                all_files,
            ),
            "exports": parse_named_module_exports(source_text),
            "functions": [],
        }

    all_functions = []
    module_imports = {}
    module_exports = {}

    for file_key, record in records.items():
        module_imports[file_key] = record["imports"]
        module_exports[file_key] = record["exports"]

        for function in collect_javascript_functions(
            record["root"],
            record["source_bytes"],
        ):
            function["local_key"] = function["key"]
            function["key"] = f"{file_key}::{function['key']}"
            function["file_key"] = file_key
            function["source_bytes"] = record["source_bytes"]
            record["functions"].append(function)
            all_functions.append(function)

    project_parameter_taint = propagate_function_parameter_taint(
        all_functions,
        module_imports=module_imports,
        module_exports=module_exports,
    )

    per_file_parameter_taint = {}
    for file_key, record in records.items():
        per_file_parameter_taint[file_key] = {
            function["local_key"]: project_parameter_taint[function["key"]]
            for function in record["functions"]
        }

    return per_file_parameter_taint


def analyze_javascript_files(file_paths):
    """Project ke JS files scan karke supported relative imports mein taint trace karta hai."""
    paths = [Path(path).resolve() for path in file_paths]
    shared_parameter_taint = collect_project_function_parameter_taint(paths)
    findings = []

    for file_path in paths:
        findings.extend(
            analyze_javascript_file(
                file_path,
                shared_parameter_taint.get(str(file_path), {}),
            )
        )

    return findings


def collect_function_initial_taint(
    function,
    functions_by_start,
    parameter_taint,
    source_bytes,
    cache,
):
    """Function parameters aur enclosing lexical scope se taint leta hai."""
    function_key = function["key"]
    if function_key in cache:
        return cache[function_key]

    initial_taint = {
        name: list(evidence)
        for name, evidence in parameter_taint[function_key].items()
        if evidence
    }

    parent_node = function["node"].parent
    enclosing_function = None

    while parent_node is not None:
        if parent_node.type in FUNCTION_NODE_TYPES:
            enclosing_function = functions_by_start.get(
                parent_node.start_byte
            )
            if enclosing_function is not None:
                break
        parent_node = parent_node.parent

    if enclosing_function is not None:
        parent_initial_taint = collect_function_initial_taint(
            enclosing_function,
            functions_by_start,
            parameter_taint,
            source_bytes,
            cache,
        )
        parent_taint = collect_tainted_variables(
            enclosing_function["nodes"],
            source_bytes,
            parent_initial_taint,
        )

        local_bindings = set(function["parameters"])
        for node in function["nodes"]:
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    local_bindings.add(
                        node_text(name_node, source_bytes)
                    )
            elif node.type in {"function_declaration", "class_declaration"}:
                name_node = node.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    local_bindings.add(
                        node_text(name_node, source_bytes)
                    )

        for name, evidence in parent_taint.items():
            # Inner parameters/declarations shadow outer closure variables.
            if (
                name in local_bindings
                and not parameter_taint[function_key].get(name)
            ):
                continue
            initial_taint[name] = unique_strings(
                initial_taint.get(name, []) + evidence
            )

    cache[function_key] = initial_taint
    return initial_taint

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


def analyze_javascript_file(file_path, shared_parameter_taint=None):
    """JS/JSX risky patterns aur supported function/module taint flows dhoondhta hai."""
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
        call_snippet = re.sub(r"\s+", " ", node_text(node, source_bytes)).strip()

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

    # Function parameters par same-file call flows propagate karo.
    function_infos = collect_javascript_functions(
        root_node,
        source_bytes,
    )
    function_parameter_taint = propagate_function_parameter_taint(
        function_infos,
        source_bytes,
        initial_parameter_taint=shared_parameter_taint,
    )
    functions_by_start = {
        function["node"].start_byte: function
        for function in function_infos
    }
    initial_taint_cache = {}

    scope_entries = [(root_node, {})]
    scope_entries.extend(
        (
            function["body"],
            collect_function_initial_taint(
                function,
                functions_by_start,
                function_parameter_taint,
                source_bytes,
                initial_taint_cache,
            ),
        )
        for function in function_infos
    )
    seen_scope_roots = set()

    for scope_root, initial_taint in scope_entries:
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
            initial_taint,
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
            call_snippet = re.sub(r"\s+", " ", call_snippet).strip()[:200]

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
                    "can reach a dynamic child_process shell command through "
                    "supported direct calls, nested closures, or a relative "
                    "named module import. Review and validate this flow."
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
