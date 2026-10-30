import re
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SCANNER = PROJECT_ROOT / "scanner.py"

VULNERABLE_CASES = [
    {
        "name": "JavaScript vulnerable",
        "path": "benchmarks/js_vulnerable",
        "expected_rule": "JS-CMD-001",
    },
    {
        "name": "Python vulnerable",
        "path": "benchmarks/py_vulnerable",
        "expected_rule": "PY-CMD-001",
    },
    {
        "name": "JavaScript cross-file vulnerable",
        "path": "benchmarks/js_cross_file",
        "expected_rule": "JS-CMD-001",
        "expected_evidence": [
            "Web request data source at line 4.",
            "Cross-file call from route.js",
            "child_process shell sink at line 4.",
        ],
    },
]

SAFE_CASES = [
    {
        "name": "JavaScript safe",
        "path": "benchmarks/js_safe",
    },
    {
        "name": "Python safe",
        "path": "benchmarks/py_safe",
    },
]

DEPENDENCY_VULNERABLE_CASES = [
    {
        "name": "Vulnerable PyPI dependency",
        "path": "benchmarks/dep_py_vulnerable",
        "package": "requests",
        "version": "2.31.0",
        "expected_advisory_id": "GHSA-9hjg-9r4m-mvj7",
    },
]

DEPENDENCY_SAFE_CASES = [
    {
        "name": "Updated PyPI dependency",
        "path": "benchmarks/dep_py_safe",
        "package": "requests",
        "version": "2.33.0",
    },
]

RULE_PATTERN = re.compile(
    r"^\[((?:PY|JS)-[A-Z0-9_-]+)\]",
    re.MULTILINE,
)
OSV_PACKAGE_PATTERN = re.compile(
    r"^\[OSV\][^\r\n]*?\s+([A-Za-z0-9_.-]+)==([^\s]+)",
    re.MULTILINE,
)


def scan_example(example_path):
    """Scanner chala kar code rules aur console output return karta hai."""
    project_path = PROJECT_ROOT / example_path

    if not project_path.is_dir():
        raise FileNotFoundError(
            f"Benchmark folder nahi mila: {project_path}"
        )

    with tempfile.TemporaryDirectory(
        prefix="security_auditor_benchmark_"
    ) as temporary_directory:
        temporary_path = Path(temporary_directory)

        command = [
            sys.executable,
            str(SCANNER),
            str(project_path),
            str(temporary_path / "audit_report.json"),
            "--markdown-report",
            str(temporary_path / "audit_report.md"),
            "--sarif-report",
            str(temporary_path / "audit_report.sarif"),
        ]

        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Scanner fail hua: {example_path}\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

        return set(RULE_PATTERN.findall(result.stdout)), result.stdout


def parse_osv_package_versions(scan_output):
    """Console report se OSV-hit package/version pairs nikalta hai."""
    return {
        (package.lower(), version)
        for package, version in OSV_PACKAGE_PATTERN.findall(scan_output)
    }


def percentage(numerator, denominator):
    """Percentage calculate karta hai; zero denominator par 0 deta hai."""
    if denominator == 0:
        return 0.0

    return numerator / denominator * 100


def main():
    if not SCANNER.is_file():
        raise FileNotFoundError(
            f"scanner.py nahi mila: {SCANNER}"
        )

    true_positives = 0
    false_negatives = 0
    false_positives = 0
    true_negatives = 0

    print("Security auditor benchmark shuru...\n")

    for example in VULNERABLE_CASES:
        found_rules, scan_output = scan_example(example["path"])
        expected_rule = example["expected_rule"]
        expected_evidence = example.get("expected_evidence", [])
        evidence_missing = [
            item
            for item in expected_evidence
            if item not in scan_output
        ]

        if expected_rule in found_rules and not evidence_missing:
            true_positives += 1
            result_label = "TP - expected vulnerability detect hui"
        else:
            false_negatives += 1
            result_label = (
                "FN - expected vulnerability ya required evidence missing"
            )

        print(f'{example["name"]}: {result_label}')
        print(f"  Expected: {expected_rule}")
        print(
            "  Found: "
            + (", ".join(sorted(found_rules)) if found_rules else "koi code finding nahi")
        )
        if evidence_missing:
            print(
                "  Missing evidence: "
                + "; ".join(evidence_missing)
            )

    for example in SAFE_CASES:
        found_rules, _ = scan_example(example["path"])

        if found_rules:
            false_positives += 1
            result_label = "FP - safe example par finding aayi"
        else:
            true_negatives += 1
            result_label = "TN - safe example par finding nahi aayi"

        print(f'\n{example["name"]}: {result_label}')
        print(
            "  Found: "
            + (", ".join(sorted(found_rules)) if found_rules else "koi code finding nahi")
        )

    total = (
        true_positives
        + false_positives
        + true_negatives
        + false_negatives
    )

    accuracy = percentage(
        true_positives + true_negatives,
        total,
    )
    precision = percentage(
        true_positives,
        true_positives + false_positives,
    )
    recall = percentage(
        true_positives,
        true_positives + false_negatives,
    )
    false_positive_rate = percentage(
        false_positives,
        false_positives + true_negatives,
    )

    print("\nBenchmark summary:")
    print(f"  TP (vulnerable correctly detected): {true_positives}")
    print(f"  TN (safe correctly passed):         {true_negatives}")
    print(f"  FP (safe flagged):                  {false_positives}")
    print(f"  FN (vulnerable missed):             {false_negatives}")
    print(f"  Accuracy:                           {accuracy:.1f}%")
    print(f"  Precision:                          {precision:.1f}%")
    print(f"  Recall:                             {recall:.1f}%")
    print(f"  False-positive rate:                {false_positive_rate:.1f}%")
    print(f"\nTotal labeled examples: {total}")

    print(
        "\nNote: yeh chhote demo examples ka result hai; "
        "ise general-purpose scanner accuracy na samjhein."
    )

    dependency_tp = 0
    dependency_fn = 0
    dependency_fp = 0
    dependency_tn = 0

    print("\nDependency advisory benchmark shuru...")

    for example in DEPENDENCY_VULNERABLE_CASES:
        _, scan_output = scan_example(example["path"])
        package_version = (
            example["package"].lower(),
            example["version"],
        )
        observed_versions = parse_osv_package_versions(scan_output)
        expected_id_found = (
            example["expected_advisory_id"] in scan_output
        )

        if package_version in observed_versions and expected_id_found:
            dependency_tp += 1
            result_label = "TP - expected OSV advisory detect hui"
        else:
            dependency_fn += 1
            result_label = "FN - expected OSV advisory detect nahi hui"

        print(f'\n{example["name"]}: {result_label}')
        print(
            f'  Expected: {example["package"]}=={example["version"]} '
            f'and {example["expected_advisory_id"]}'
        )
        print(
            "  OSV package/version match: "
            f"{package_version in observed_versions}"
        )

    for example in DEPENDENCY_SAFE_CASES:
        _, scan_output = scan_example(example["path"])
        package_version = (
            example["package"].lower(),
            example["version"],
        )
        observed_versions = parse_osv_package_versions(scan_output)

        if package_version in observed_versions:
            dependency_fp += 1
            result_label = "FP - updated package par advisory aayi"
        else:
            dependency_tn += 1
            result_label = "TN - updated package par advisory nahi aayi"

        print(f'\n{example["name"]}: {result_label}')
        print(
            f'  Checked: {example["package"]}=={example["version"]}'
        )

    dependency_total = (
        dependency_tp
        + dependency_fn
        + dependency_fp
        + dependency_tn
    )
    dependency_accuracy = percentage(
        dependency_tp + dependency_tn,
        dependency_total,
    )
    dependency_precision = percentage(
        dependency_tp,
        dependency_tp + dependency_fp,
    )
    dependency_recall = percentage(
        dependency_tp,
        dependency_tp + dependency_fn,
    )
    dependency_false_positive_rate = percentage(
        dependency_fp,
        dependency_fp + dependency_tn,
    )

    print("\nDependency benchmark summary:")
    print(f"  TP (vulnerable package detected): {dependency_tp}")
    print(f"  TN (updated package passed):      {dependency_tn}")
    print(f"  FP (updated package flagged):     {dependency_fp}")
    print(f"  FN (vulnerable package missed):   {dependency_fn}")
    print(f"  Accuracy:                         {dependency_accuracy:.1f}%")
    print(f"  Precision:                        {dependency_precision:.1f}%")
    print(f"  Recall:                           {dependency_recall:.1f}%")
    print(
        "  False-positive rate:              "
        f"{dependency_false_positive_rate:.1f}%"
    )
    print(f"  Total dependency examples:        {dependency_total}")
    print(
        "  Note: dependency results rely on live OSV data and network access."
    )


if __name__ == "__main__":
    main()
