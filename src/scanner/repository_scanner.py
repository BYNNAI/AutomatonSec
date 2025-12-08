# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime

from src.core.engine import AutomatonSecEngine
from src.core.models import AnalysisResult, Vulnerability
from src.scanner.test_filter import TestFileFilter

logger = logging.getLogger(__name__)


class RepositoryScanner:
    """
    Scans bug bounty repositories for vulnerabilities across multiple contracts.
    Excludes test files and provides comprehensive cross-contract analysis.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.engine = AutomatonSecEngine(self.config)
        self.test_filter = TestFileFilter()
        self.results: List[AnalysisResult] = []
        
    def _default_config(self) -> Dict:
        return {
            "max_workers": 4,
            "max_symbolic_depth": 128,
            "fuzzing_iterations": 10000,
            "enable_cross_contract": True,
            "enable_ml_detection": True,
            "exclude_tests": True,
            "file_extensions": [".sol"],
            "max_file_size_mb": 5,
        }
    
    def scan_directory(self, directory: Path) -> Dict:
        """
        Recursively scan a directory for Solidity contracts and analyze them.
        
        Args:
            directory: Path to bug bounty repository
            
        Returns:
            Dict containing all analysis results and statistics
        """
        logger.info(f"Starting repository scan: {directory}")
        start_time = datetime.now()
        
        solidity_files = self._discover_contracts(directory)
        logger.info(f"Discovered {len(solidity_files)} Solidity files")
        
        if self.config.get("exclude_tests", True):
            production_files = self.test_filter.filter_files(solidity_files)
            logger.info(f"After test exclusion: {len(production_files)} production files")
        else:
            production_files = solidity_files
        
        self.results = self._analyze_contracts_parallel(production_files)
        
        end_time = datetime.now()
        analysis_time = (end_time - start_time).total_seconds()
        
        return self._generate_report(production_files, analysis_time)
    
    def _discover_contracts(self, directory: Path) -> List[Path]:
        """
        Recursively discover all Solidity contract files.
        """
        contracts = []
        extensions = self.config.get("file_extensions", [".sol"])
        max_size = self.config.get("max_file_size_mb", 5) * 1024 * 1024
        
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if file_path.is_file():
                    if file_path.stat().st_size <= max_size:
                        contracts.append(file_path)
                    else:
                        logger.warning(f"Skipping large file: {file_path}")
        
        return contracts
    
    def _analyze_contracts_parallel(self, files: List[Path]) -> List[AnalysisResult]:
        """
        Analyze contracts in parallel for performance.
        """
        results = []
        max_workers = self.config.get("max_workers", 4)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._analyze_file, f): f for f in files}
            
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        logger.info(f"Analyzed {file_path.name}: {len(result.vulnerabilities)} issues")
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
        
        return results
    
    def _analyze_file(self, file_path: Path) -> Optional[AnalysisResult]:
        """
        Analyze a single Solidity file.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            report = self.engine.analyze_contract(source_code=source_code)
            
            return AnalysisResult(
                contract_name=file_path.name,
                contract_address=None,
                vulnerabilities=self.engine.vulnerabilities,
                analysis_time=0.0,
                timestamp=datetime.now(),
                engine_version="1.0.0",
                total_functions=0,
                analyzed_paths=0,
                coverage=0.0,
                metadata={"file_path": str(file_path)}
            )
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")
            return None
    
    def _generate_report(self, files: List[Path], analysis_time: float) -> Dict:
        """
        Generate comprehensive vulnerability report.
        """
        all_vulnerabilities = []
        for result in self.results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        critical = [v for v in all_vulnerabilities if v.severity.value == "CRITICAL"]
        high = [v for v in all_vulnerabilities if v.severity.value == "HIGH"]
        medium = [v for v in all_vulnerabilities if v.severity.value == "MEDIUM"]
        low = [v for v in all_vulnerabilities if v.severity.value == "LOW"]
        
        return {
            "summary": {
                "total_files": len(files),
                "total_vulnerabilities": len(all_vulnerabilities),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "analysis_time_seconds": analysis_time,
            },
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities],
            "critical_issues": [v.to_dict() for v in critical],
            "files_analyzed": [str(f) for f in files],
            "timestamp": datetime.now().isoformat(),
        }
    
    def export_report(self, output_path: Path, format: str = "json") -> None:
        """
        Export analysis report to file.
        """
        report = self._generate_report([], 0.0)
        
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        logger.info(f"Report exported to {output_path}")
