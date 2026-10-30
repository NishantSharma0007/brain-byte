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

RULE_PATTERN = re.compile(
    r"^\[((?:PY|JS)-[A-Z0-9_-]+)\]",
    re.MULTILINE,
)


def scan_example(example_path):
    """Scanner chala kar code rule IDs aur console evidence return karta hai."""
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


if __name__ == "__main__":
    main()
