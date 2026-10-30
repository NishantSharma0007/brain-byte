import ast
from pathlib import Path

from models import Finding


REQUEST_SOURCE_PARTS = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
)

SUBPROCESS_FUNCTIONS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    return ""


def unique_items(items):
    result = []

    for item in items:
        if item not in result:
            result.append(item)

    return result


def get_function_parameters(function_node):
    args = function_node.args
    positional = args.posonlyargs + args.args
    return [argument.arg for argument in positional]


class FunctionFlow:
    def __init__(
        self,
        file_path,
        function_name,
        function_node,
        functions,
        known_tainted_parameters,
    ):
        self.file_path = str(file_path)
        self.function_name = function_name
        self.function_node = function_node
        self.functions = functions

        self.environment = {}
        self.discovered_parameters = {}
        self.findings = {}
        self.seen_calls = set()

        # Caller se tainted aaye parameters ko function ke andar seed karo.
        for parameter, evidence in known_tainted_parameters.items():
            self.environment[parameter] = unique_items(
                evidence + [
                    f"Function parameter '{parameter}' is tainted "
                    f"inside {function_name}()."
                ]
            )

    def source_trace(self, node):
        if isinstance(node, ast.Call):
            call_name = get_call_name(node.func)

            if call_name in {"input", "builtins.input"}:
                return [f"User input source at line {node.lineno}."]

            if any(part in call_name for part in REQUEST_SOURCE_PARTS):
                return [f"Web request data source at line {node.lineno}."]

        dotted_name = get_call_name(node)

        if any(part in dotted_name for part in REQUEST_SOURCE_PARTS):
            line = getattr(node, "lineno", 1)
            return [f"Web request data source at line {line}."]

        return []

    def expression_trace(self, node):
        if node is None:
            return []

        if isinstance(node, ast.Name):
            return list(self.environment.get(node.id, []))

        direct_source = self.source_trace(node)

        if direct_source:
            return direct_source

        if isinstance(node, ast.Call):
            call_name = get_call_name(node.func)

            # Local function call ka return-flow abhi track nahi hota.
            # Uske arguments alag se callee parameters tak trace hote hain.
            if call_name in self.functions:
                return []

        traces = []

        for child in ast.iter_child_nodes(node):
            traces.extend(self.expression_trace(child))

        return unique_items(traces)

    @staticmethod
    def is_dynamic_expression(node):
        if node is None:
            return False

        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return True

        if (
            isinstance(node, ast.Call)
            and get_call_name(node.func).endswith(".format")
        ):
            return True

        return any(
            FunctionFlow.is_dynamic_expression(child)
            for child in ast.iter_child_nodes(node)
        )

    @staticmethod
    def iter_calls(node):
        stack = [node]

        while stack:
            current = stack.pop()

            if isinstance(
                current,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                    ast.ClassDef,
                ),
            ):
                continue

            if isinstance(current, ast.Call):
                yield current

            stack.extend(reversed(list(ast.iter_child_nodes(current))))

    def add_finding(
        self,
        rule_id,
        title,
        line,
        message,
        evidence,
    ):
        key = (rule_id, line)

        if key in self.findings:
            existing = self.findings[key]
            existing.evidence = unique_items(existing.evidence + evidence)
            return

        self.findings[key] = Finding(
            rule_id=rule_id,
            title=title,
            file=self.file_path,
            line=line,
            message=message,
            evidence=unique_items(evidence),
        )

    def pass_taint_to_local_functions(self, call):
        call_name = get_call_name(call.func)

        if call_name not in self.functions:
            return

        callee_node = self.functions[call_name]
        parameters = get_function_parameters(callee_node)

        def mark_parameter(parameter, argument):
            trace = self.expression_trace(argument)

            if not trace:
                return

            pass_evidence = (
                f"Tainted value passed to parameter '{parameter}' "
                f"of {call_name}() at line {call.lineno}."
            )
            new_trace = unique_items(trace + [pass_evidence])

            callee_taints = self.discovered_parameters.setdefault(
                call_name,
                {},
            )

            old_trace = callee_taints.get(parameter, [])
            combined_trace = unique_items(old_trace + new_trace)

            if combined_trace != old_trace:
                callee_taints[parameter] = combined_trace

        for index, argument in enumerate(call.args):
            if index < len(parameters):
                mark_parameter(parameters[index], argument)

        for keyword in call.keywords:
            if keyword.arg in parameters:
                mark_parameter(keyword.arg, keyword.value)

    def scan_calls(self, node):
        for call in self.iter_calls(node):
            call_name = get_call_name(call.func)

            # Tainted arguments can flow into another local function.
            self.pass_taint_to_local_functions(call)

            if call_name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                argument = call.args[0] if call.args else None
                trace = self.expression_trace(argument)

                self.add_finding(
                    rule_id="PY-EVAL-001",
                    title=f"Risky {call_name.split('.')[-1]}() call",
                    line=call.lineno,
                    message="eval()/exec() dynamically evaluates code.",
                    evidence=trace + [
                        f"Dynamic evaluation sink at line {call.lineno}."
                    ],
                )

            elif call_name in SUBPROCESS_FUNCTIONS:
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in call.keywords
                )

                argument = call.args[0] if call.args else None
                trace = self.expression_trace(argument)

                if shell_true and (
                    trace or self.is_dynamic_expression(argument)
                ):
                    evidence = list(trace)

                    if not evidence:
                        evidence.append(
                            f"Dynamic command expression at line {call.lineno}."
                        )

                    evidence.append(
                        f"subprocess shell=True sink at line {call.lineno}."
                    )

                    self.add_finding(
                        rule_id="PY-CMD-001",
                        title="Potential command injection in shell execution",
                        line=call.lineno,
                        message=(
                            "A dynamic or tainted command may reach "
                            "subprocess with shell=True."
                        ),
                        evidence=evidence,
                    )

            elif call_name.endswith((".execute", ".executemany")):
                query = call.args[0] if call.args else None
                trace = self.expression_trace(query)

                if trace or self.is_dynamic_expression(query):
                    evidence = list(trace)

                    if not evidence:
                        evidence.append(
                            f"Dynamic SQL expression at line {call.lineno}."
                        )

                    evidence.append(
                        f"Database query sink at line {call.lineno}."
                    )

                    self.add_finding(
                        rule_id="PY-SQL-001",
                        title="Potential SQL injection in dynamic query",
                        line=call.lineno,
                        message=(
                            "The SQL query is tainted or dynamically built. "
                            "Use parameterized queries."
                        ),
                        evidence=evidence,
                    )

    def assign_taint(self, target, trace, line):
        if not trace:
            return

        if isinstance(target, ast.Name):
            self.environment[target.id] = unique_items(
                trace + [f"Assigned to '{target.id}' at line {line}."]
            )

        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.assign_taint(child, trace, line)

    def merge_environments(self, first, second):
        merged = {}

        for name in set(first) | set(second):
            merged[name] = unique_items(
                first.get(name, []) + second.get(name, [])
            )

        return merged

    def scan_statements(self, statements):
        for statement in statements:
            if isinstance(statement, ast.Assign):
                self.scan_calls(statement.value)
                trace = self.expression_trace(statement.value)

                for target in statement.targets:
                    self.assign_taint(target, trace, statement.lineno)

            elif isinstance(statement, ast.AnnAssign):
                self.scan_calls(statement.value)
                trace = self.expression_trace(statement.value)
                self.assign_taint(
                    statement.target,
                    trace,
                    statement.lineno,
                )

            elif isinstance(statement, ast.If):
                self.scan_calls(statement.test)

                before = {
                    name: list(trace)
                    for name, trace in self.environment.items()
                }

                self.environment = {
                    name: list(trace)
                    for name, trace in before.items()
                }
                self.scan_statements(statement.body)
                body_environment = self.environment

                self.environment = {
                    name: list(trace)
                    for name, trace in before.items()
                }
                self.scan_statements(statement.orelse)
                else_environment = self.environment

                self.environment = self.merge_environments(
                    body_environment,
                    else_environment,
                )

            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self.scan_calls(statement.iter)

                before = {
                    name: list(trace)
                    for name, trace in self.environment.items()
                }

                self.scan_statements(statement.body)

                self.environment = self.merge_environments(
                    before,
                    self.environment,
                )
                self.scan_statements(statement.orelse)

            elif isinstance(statement, ast.While):
                self.scan_calls(statement.test)

                before = {
                    name: list(trace)
                    for name, trace in self.environment.items()
                }

                self.scan_statements(statement.body)

                self.environment = self.merge_environments(
                    before,
                    self.environment,
                )
                self.scan_statements(statement.orelse)

            else:
                self.scan_calls(statement)

    def run(self):
        self.scan_statements(self.function_node.body)

        return (
            self.discovered_parameters,
            list(self.findings.values()),
        )


def analyze_file(file_path):
    file_path = Path(file_path)

    try:
        source = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        return []

    # Is version mein same file ke top-level functions analyze hote hain.
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    if not functions:
        return []

    tainted_parameters = {
        function_name: {}
        for function_name in functions
    }

    # Caller se callee tak tainted parameters propagate karo.
    # Repeat karne se multi-function chains bhi mil sakti hain.
    max_iterations = len(functions) * len(functions) + 1

    for _ in range(max_iterations):
        changed = False

        for function_name, function_node in functions.items():
            flow = FunctionFlow(
                file_path=file_path,
                function_name=function_name,
                function_node=function_node,
                functions=functions,
                known_tainted_parameters=tainted_parameters[function_name],
            )

            discovered, _ = flow.run()

            for callee_name, parameter_map in discovered.items():
                for parameter, evidence in parameter_map.items():
                    current = tainted_parameters[callee_name].get(
                        parameter,
                        [],
                    )
                    combined = unique_items(current + evidence)

                    if combined != current:
                        tainted_parameters[callee_name][parameter] = combined
                        changed = True

        if not changed:
            break

    # Final pass: stabilized taint information ke saath findings banao.
    findings = []

    for function_name, function_node in functions.items():
        flow = FunctionFlow(
            file_path=file_path,
            function_name=function_name,
            function_node=function_node,
            functions=functions,
            known_tainted_parameters=tainted_parameters[function_name],
        )

        _, function_findings = flow.run()
        findings.extend(function_findings)

    return findings