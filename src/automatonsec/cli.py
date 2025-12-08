# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from automatonsec import SecurityEngine, AnalysisConfig
from automatonsec.core.models import Severity

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="AutomatonSec")
def main():
    """AutomatonSec - Advanced Smart Contract Security Analysis Engine"""
    pass


@main.command()
@click.argument("contract_path", type=click.Path(exists=True))
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config file")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--format", "-f", type=click.Choice(["json", "text"]), default="text", help="Output format")
@click.option("--full", is_flag=True, help="Run full analysis suite")
@click.option("--generate-exploits", is_flag=True, help="Generate exploit PoCs")
def analyze(contract_path, config, output, format, full, generate_exploits):
    """Analyze a smart contract for vulnerabilities"""
    try:
        console.print(Panel.fit(
            "[bold cyan]AutomatonSec v1.0.0[/bold cyan]\n"
            "Advanced Smart Contract Security Analysis",
            border_style="cyan"
        ))

        analysis_config = AnalysisConfig()
        if config:
            from automatonsec.config.config_loader import load_config
            analysis_config = load_config(config)

        if full:
            analysis_config.symbolic_execution_enabled = True
            analysis_config.data_flow_enabled = True
            analysis_config.fuzzing_enabled = True

        if generate_exploits:
            analysis_config.include_exploits = True

        console.print(f"\n[bold]Analyzing:[/bold] {contract_path}")
        console.print(f"[dim]Starting security analysis...\n[/dim]")

        engine = SecurityEngine(analysis_config)
        result = engine.analyze_file(contract_path)

        if format == "json":
            output_data = result.to_dict()
            if output:
                Path(output).write_text(json.dumps(output_data, indent=2))
                console.print(f"\n[green]Results saved to {output}[/green]")
            else:
                print(json.dumps(output_data, indent=2))
        else:
            _display_text_results(result)

            if output:
                with open(output, "w") as f:
                    f.write(json.dumps(result.to_dict(), indent=2))
                console.print(f"\n[green]Results also saved to {output}[/green]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def _display_text_results(result):
    critical = result.get_critical()
    high = result.get_high()

    stats_table = Table(title="Analysis Statistics", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="magenta")

    stats_table.add_row("Contract", result.contract_name)
    stats_table.add_row("Analysis Time", f"{result.analysis_time:.2f}s")
    stats_table.add_row("Total Functions", str(result.total_functions))
    stats_table.add_row("Paths Analyzed", str(result.analyzed_paths))
    stats_table.add_row("Coverage", f"{result.coverage:.1f}%")
    stats_table.add_row("Total Vulnerabilities", str(len(result.vulnerabilities)))
    stats_table.add_row("Critical", f"[red]{len(critical)}[/red]")
    stats_table.add_row("High", f"[orange1]{len(high)}[/orange1]")

    console.print("\n")
    console.print(stats_table)

    if result.vulnerabilities:
        vuln_table = Table(title="\nVulnerabilities Found", box=box.DOUBLE_EDGE)
        vuln_table.add_column("#", style="dim", width=4)
        vuln_table.add_column("Severity", width=10)
        vuln_table.add_column("Type", width=20)
        vuln_table.add_column("Location", width=30)
        vuln_table.add_column("Confidence", width=10)

        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_colors = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }
            color = severity_colors.get(vuln.severity, "white")

            vuln_table.add_row(
                str(i),
                f"[{color}]{vuln.severity.value}[/{color}]",
                vuln.type.value,
                str(vuln.location),
                f"{vuln.confidence:.0%}",
            )

        console.print("\n")
        console.print(vuln_table)

        console.print("\n[bold]Detailed Findings:[/bold]\n")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_colors = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }
            color = severity_colors.get(vuln.severity, "white")

            console.print(Panel(
                f"[bold]{vuln.name}[/bold]\n\n"
                f"[dim]Description:[/dim] {vuln.description}\n\n"
                f"[dim]Impact:[/dim] {vuln.impact}\n\n"
                f"[dim]Recommendation:[/dim] {vuln.recommendation}",
                title=f"[{color}]#{i} - {vuln.severity.value}[/{color}]",
                border_style=color,
            ))
    else:
        console.print("\n[bold green]No vulnerabilities found![/bold green]")


@main.command()
@click.argument("bytecode")
def bytecode(bytecode):
    """Analyze raw bytecode"""
    console.print("[cyan]Analyzing bytecode...[/cyan]\n")
    engine = SecurityEngine()
    result = engine.analyze_bytecode(bytecode)
    _display_text_results(result)


if __name__ == "__main__":
    main()