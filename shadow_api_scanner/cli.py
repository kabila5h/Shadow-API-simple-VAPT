"""
Shadow API Scanner — CLI Entry Point

Parses command-line arguments and orchestrates the four-phase scan pipeline.
"""

from __future__ import annotations

import asyncio
import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import ScanResult
from shadow_api_scanner.phase1.static_analyzer import StaticAnalyzer
from shadow_api_scanner.phase2.shadow_detector import ShadowDetector
from shadow_api_scanner.phase3.security_tester import SecurityTester
from shadow_api_scanner.phase4.risk_scorer import RiskScorer
from shadow_api_scanner.phase4.report_generator import ReportGenerator
from shadow_api_scanner.utils.helpers import setup_logging

console = Console()

BANNER = r"""
[bold magenta]
 ____  _               _                  _    ____ ___
/ ___|| |__   __ _  __| | _____      __  / \  |  _ \_ _|
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / / _ \ | |_) | |
 ___) | | | | (_| | (_| | (_) \ V  V / / ___ \|  __/| |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/ /_/   \_\_|  |___|
    [cyan]Scanner v1.0.0 — Shadow API Detection & Security Testing[/cyan]
[/bold magenta]"""


async def run_scan(config: ScanConfig):
    """Execute the full four-phase scan pipeline."""
    logger = setup_logging(config.verbose)

    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold] {config.target_url}\n"
        f"[bold]Output:[/bold] {config.output_dir}\n"
        f"[bold]Headless:[/bold] {config.browser_headless}\n"
        f"[bold]Fuzzing:[/bold] {config.enable_fuzzing}",
        title="⚙️  Scan Configuration",
        border_style="blue",
    ))

    result = ScanResult(target_url=config.target_url)

    try:
        # ── Phase 1: Static JS Analysis ──
        analyzer = StaticAnalyzer(config)
        static_endpoints = await analyzer.run(result)

        # ── Phase 2: Dynamic Monitoring + Shadow Detection ──
        detector = ShadowDetector(config)
        all_endpoints = await detector.run(static_endpoints, result)

        # ── Phase 3: Security Testing ──
        # Test shadow endpoints, or all if no spec was found
        test_targets = result.shadow_endpoints if result.shadow_endpoints else all_endpoints
        if test_targets:
            tester = SecurityTester(config)
            await tester.run(test_targets, result)
        else:
            logger.info("No endpoints to test — skipping Phase 3.")

        # ── Phase 4: Risk Scoring & Reporting ──
        scorer = RiskScorer()
        scorer.score(result)

        reporter = ReportGenerator(config)
        report_files = reporter.generate(result)

        # ── Final Summary ──
        _print_summary(result, report_files)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user.[/yellow]")
        result.errors.append("Scan interrupted by user")
        result.finalize()
    except Exception as e:
        console.print(f"\n[red]❌ Fatal error: {e}[/red]")
        logger.exception("Fatal scan error")
        result.errors.append(str(e))
        result.finalize()


def _print_summary(result: ScanResult, report_files: dict[str, str]):
    """Print a rich summary table to the console."""
    console.print()

    # Summary table
    table = Table(title="📊 Scan Summary", show_header=True, border_style="bright_blue")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    risk_color = {
        "Critical": "bold red", "High": "bold yellow",
        "Medium": "yellow", "Low": "green", "Info": "blue",
    }.get(result.overall_risk_level.value, "white")

    table.add_row("Target URL", result.target_url)
    table.add_row("JS Files Analyzed", str(result.js_files_analyzed))
    table.add_row("Total Endpoints", str(len(result.all_endpoints)))
    table.add_row("Shadow APIs", f"[red]{len(result.shadow_endpoints)}[/red]")
    table.add_row("Vulnerabilities", f"[yellow]{len(result.vulnerabilities)}[/yellow]")
    table.add_row("Overall Risk", f"[{risk_color}]{result.overall_risk_level.value} ({result.overall_risk_score:.1f}/10)[/{risk_color}]")
    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[yellow]{result.high_count}[/yellow]")
    table.add_row("Medium", str(result.medium_count))
    table.add_row("Low", str(result.low_count))

    for fmt, path in report_files.items():
        table.add_row(f"Report ({fmt.upper()})", path)

    console.print(table)
    console.print()


@click.command()
@click.argument("target_url")
@click.option("--output", "-o", default="reports", help="Output directory for reports")
@click.option("--openapi-spec", default=None, help="Path or URL to OpenAPI spec file")
@click.option("--auth-token", default=None, help="Authorization token (e.g., 'Bearer xxx')")
@click.option("--auth-header", default="Authorization", help="Auth header name")
@click.option("--no-browser", is_flag=True, help="Skip Phase 2 dynamic monitoring")
@click.option("--no-fuzz", is_flag=True, help="Skip fuzzing in Phase 3")
@click.option("--headed", is_flag=True, help="Show browser window (not headless)")
@click.option("--timeout", default=60, help="Browser timeout in seconds")
@click.option("--concurrency", default=10, help="Max concurrent test requests")
@click.option("--format", "formats", default="json,html", help="Report formats (json,html)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(
    target_url, output, openapi_spec, auth_token, auth_header,
    no_browser, no_fuzz, headed, timeout, concurrency, formats, verbose,
):
    """
    Shadow API Scanner — Detect and test shadow APIs in Single-Page Applications.

    TARGET_URL: The SPA URL to scan (e.g., https://example.com)
    """
    # Validate URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Build config
    spec_url = None
    spec_file = None
    if openapi_spec:
        if openapi_spec.startswith(("http://", "https://")):
            spec_url = openapi_spec
        else:
            spec_file = openapi_spec

    config = ScanConfig(
        target_url=target_url,
        output_dir=output,
        openapi_spec_url=spec_url,
        openapi_spec_file=spec_file,
        browser_headless=not headed,
        browser_timeout=timeout,
        max_concurrent_tests=concurrency,
        enable_fuzzing=not no_fuzz,
        report_formats=[f.strip() for f in formats.split(",")],
        verbose=verbose,
        auth_token=auth_token,
        auth_header=auth_header,
    )

    # If --no-browser, skip Phase 2 by setting timeout to 0
    if no_browser:
        config.browser_timeout = 0
        config.wait_after_load = 0

    asyncio.run(run_scan(config))


if __name__ == "__main__":
    main()
