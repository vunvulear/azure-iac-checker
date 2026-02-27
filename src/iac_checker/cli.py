"""CLI entry point for the Azure IaC Compliance Checker (Terraform, ARM, Bicep)."""

import argparse
import logging
import sys
from pathlib import Path

from iac_checker import __version__
from iac_checker.config.loader import ConfigLoader
from iac_checker.parser.scanner import IacScanner
from iac_checker.parser.terraform.hcl_parser import HclParser
from iac_checker.parser.arm.arm_parser import ArmParser
from iac_checker.parser.bicep.bicep_parser import BicepParser
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.engine import RulesEngine
from iac_checker.reporters.markdown_reporter import MarkdownReporter
from iac_checker.models.enums import Severity

logger = logging.getLogger("iac_checker")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iac-checker",
        description="Validate Terraform, ARM template, and Bicep code against Azure WAF & CAF best practices.",
    )
    parser.add_argument(
        "--path", "-p",
        type=str,
        required=True,
        help="Path to the IaC folder to scan (Terraform, ARM, Bicep).",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=".iac-checker.yaml",
        help="Path to the configuration YAML file.",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="compliance-report.md",
        help="Output path for the Markdown report.",
    )
    parser.add_argument(
        "--severity-threshold", "-s",
        type=str,
        choices=["Critical", "High", "Medium", "Low"],
        default=None,
        help="Minimum severity to trigger a non-zero exit code (overrides config).",
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        nargs="+",
        choices=["terraform", "arm", "bicep"],
        default=["terraform", "arm", "bicep"],
        help="IaC formats to scan (default: all). Example: --format terraform arm",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    # Configure logging
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    try:
        return _run(args)
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        return 130
    except Exception as exc:
        logger.error("Unexpected error: %s", exc, exc_info=log_level == logging.DEBUG)
        return 2


def _run(args: argparse.Namespace) -> int:
    """Core pipeline: scan → parse → evaluate → report."""

    # 1. Validate path
    scan_path = Path(args.path)
    if not scan_path.exists():
        logger.error("Path does not exist: %s", scan_path)
        return 2
    if not scan_path.is_dir():
        logger.error("Path is not a directory: %s", scan_path)
        return 2

    # 2. Load configuration
    config = ConfigLoader.load(args.config)

    # Override severity threshold from CLI if provided
    if args.severity_threshold:
        config.severity_threshold = Severity(args.severity_threshold)

    # 3. Scan for IaC files (Terraform, ARM, Bicep)
    formats = set(getattr(args, "format", ["terraform", "arm", "bicep"]))
    scanner = IacScanner(
        root_path=scan_path,
        exclude_paths=config.exclude_paths,
        formats=formats,
    )
    files_by_format = scanner.discover()
    total_files = sum(len(v) for v in files_by_format.values())

    if total_files == 0:
        logger.warning("No IaC files found in %s (formats: %s)", args.path, ", ".join(formats))
        return 0

    for fmt, files in files_by_format.items():
        if files:
            logger.info("Found %d %s files in %s", len(files), fmt, args.path)

    # 4. Parse files with format-appropriate parsers
    parsers = {
        "terraform": HclParser,
        "arm": ArmParser,
        "bicep": BicepParser,
    }
    parsed_files = []
    for fmt, files in files_by_format.items():
        if files and fmt in parsers:
            parser = parsers[fmt]()
            parsed_files.extend(parser.parse_files(files))

    if not parsed_files:
        logger.error("All files failed to parse. Check for syntax errors.")
        return 2

    # 5. Build resource index
    index = ResourceIndex()
    index.build(parsed_files)

    logger.info(
        "Indexed %d resources, %d data sources, %d modules (from %d files)",
        len(index.resources), len(index.data_sources), len(index.modules), len(parsed_files),
    )

    # 6. Run rules engine
    engine = RulesEngine(config=config)
    findings = engine.evaluate(index)

    failed_count = len([f for f in findings if not f.passed and not f.suppressed])
    logger.info(
        "Evaluated %d rules, found %d issues",
        engine.rules_count, failed_count,
    )

    # 7. Generate Markdown report
    reporter = MarkdownReporter(
        scan_path=args.path,
        files_scanned=total_files,
        config=config,
    )
    report_content = reporter.generate(findings)

    # 8. Write report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_content, encoding="utf-8")
    logger.info("Report written to %s", output_path)

    # 9. Determine exit code
    failed_findings = [f for f in findings if not f.passed and not f.suppressed]
    threshold = config.severity_threshold

    has_violations = any(
        f.severity.rank <= threshold.rank for f in failed_findings
    )

    if has_violations:
        critical_count = len([f for f in failed_findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in failed_findings if f.severity == Severity.HIGH])
        logger.info(
            "FAIL: %d Critical, %d High violations found (threshold: %s)",
            critical_count, high_count, threshold.value,
        )
        return 1

    logger.info("PASS: No violations above severity threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
