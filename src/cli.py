# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import click
import json
import sys
from pathlib import Path

from src.core.engine import AutomatonSecEngine
from src.scanner.repository_scanner import RepositoryScanner


@click.group()
@click.version_option(version="1.0.0", prog_name="AutomatonSec")
def main():
    """AutomatonSec - Advanced Smart Contract Security Analysis Engine"""
    pass


@main.command()
@click.argument("contract_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--full", is_flag=True, help="Run full analysis suite")
def analyze(contract_path, output, full):
    """Analyze a smart contract for vulnerabilities"""
    try:
        config = {
            "max_symbolic_depth": 128 if full else 64,
            "fuzzing_iterations": 10000 if full else 5000,
        }

        print(f"Analyzing: {contract_path}")
        engine = AutomatonSecEngine(config)
        
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        report = engine.analyze_contract(source_code=source_code)
        
        result = {"vulnerabilities": [v.to_dict() for v in engine.vulnerabilities]}
        
        if output:
            Path(output).write_text(json.dumps(result, indent=2))
            print(f"Results saved to {output}")
        else:
            print(json.dumps(result, indent=2))

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


@main.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="report.json")
@click.option("--workers", "-w", type=int, default=4)
def scan(directory, output, workers):
    """Scan bug bounty repository for vulnerabilities"""
    try:
        print(f"Scanning: {directory}")
        scanner = RepositoryScanner({"max_workers": workers})
        results = scanner.scan_directory(Path(directory))
        
        print(f"Found {results['summary']['critical']} critical vulnerabilities")
        scanner.export_report(Path(output))
        print(f"Report saved to {output}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
