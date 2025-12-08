# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from loguru import logger

from automatonsec.core.models import (
    AnalysisResult,
    Vulnerability,
    ContractInfo,
)
from automatonsec.core.contract_parser import ContractParser
from automatonsec.core.bytecode_analyzer import BytecodeAnalyzer
from automatonsec.config.config_loader import AnalysisConfig
from automatonsec.detectors.reentrancy_detector import ReentrancyDetector
from automatonsec.detectors.access_control_detector import AccessControlDetector
from automatonsec.detectors.flashloan_detector import FlashloanDetector
from automatonsec.detectors.oracle_detector import OracleDetector
from automatonsec.detectors.exploit_chain_detector import ExploitChainDetector
from automatonsec.symbolic.executor import SymbolicExecutor
from automatonsec.dataflow.taint_analyzer import TaintAnalyzer
from automatonsec.fuzzing.profit_fuzzer import ProfitFuzzer


class SecurityEngine:
    VERSION = "1.0.0"

    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self.parser = ContractParser()
        self.bytecode_analyzer = BytecodeAnalyzer()

        self.detectors = [
            ReentrancyDetector(self.config),
            AccessControlDetector(self.config),
            FlashloanDetector(self.config),
            OracleDetector(self.config),
            ExploitChainDetector(self.config),
        ]

        if self.config.symbolic_execution_enabled:
            self.symbolic_executor = SymbolicExecutor(self.config)

        if self.config.data_flow_enabled:
            self.taint_analyzer = TaintAnalyzer(self.config)

        if self.config.fuzzing_enabled:
            self.profit_fuzzer = ProfitFuzzer(self.config)

        logger.info(f"AutomatonSec Engine v{self.VERSION} initialized")

    def analyze_file(self, file_path: str) -> AnalysisResult:
        logger.info(f"Starting analysis of {file_path}")
        start_time = time.time()

        parsed = self.parser.parse_file(file_path)
        source_code = Path(file_path).read_text(encoding="utf-8")

        vulnerabilities = []
        total_functions = 0
        analyzed_paths = 0

        for contract in parsed["contracts"]:
            contract_name = contract["name"]
            total_functions += len(contract["functions"])

            logger.info(f"Analyzing contract: {contract_name}")

            if self.config.parallel_detectors:
                contract_vulns = self._parallel_detect(contract, source_code, file_path)
            else:
                contract_vulns = self._sequential_detect(contract, source_code, file_path)

            vulnerabilities.extend(contract_vulns)

            if self.config.symbolic_execution_enabled:
                sym_result = self.symbolic_executor.execute(contract, source_code)
                vulnerabilities.extend(sym_result.vulnerabilities)
                analyzed_paths += sym_result.paths_explored

            if self.config.data_flow_enabled:
                taint_vulns = self.taint_analyzer.analyze(contract, source_code)
                vulnerabilities.extend(taint_vulns)

            if self.config.fuzzing_enabled:
                fuzz_vulns = self.profit_fuzzer.fuzz(contract, source_code)
                vulnerabilities.extend(fuzz_vulns)

        vulnerabilities = self._deduplicate_vulns(vulnerabilities)
        vulnerabilities = self._filter_by_confidence(vulnerabilities)

        analysis_time = time.time() - start_time
        coverage = (analyzed_paths / max(total_functions * 10, 1)) * 100

        result = AnalysisResult(
            contract_name=parsed["contracts"][0]["name"] if parsed["contracts"] else "Unknown",
            contract_address=None,
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            timestamp=datetime.now(),
            engine_version=self.VERSION,
            total_functions=total_functions,
            analyzed_paths=analyzed_paths,
            coverage=min(coverage, 100.0),
        )

        logger.info(
            f"Analysis complete: {len(vulnerabilities)} vulnerabilities found in {analysis_time:.2f}s"
        )

        return result

    def _parallel_detect(self, contract: Dict, source_code: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            futures = {
                executor.submit(detector.detect, contract, source_code, file_path): detector
                for detector in self.detectors
            }

            for future in as_completed(futures):
                try:
                    vulns = future.result()
                    vulnerabilities.extend(vulns)
                except Exception as e:
                    detector = futures[future]
                    logger.error(f"Detector {detector.__class__.__name__} failed: {e}")

        return vulnerabilities

    def _sequential_detect(self, contract: Dict, source_code: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        for detector in self.detectors:
            try:
                vulns = detector.detect(contract, source_code, file_path)
                vulnerabilities.extend(vulns)
            except Exception as e:
                logger.error(f"Detector {detector.__class__.__name__} failed: {e}")
        return vulnerabilities

    def _deduplicate_vulns(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        seen = set()
        unique = []

        for vuln in vulnerabilities:
            key = (vuln.type, vuln.location.line_start, vuln.location.function)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)

        return unique

    def _filter_by_confidence(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        threshold = self.config.confidence_threshold
        return [v for v in vulnerabilities if v.confidence >= threshold]

    def analyze_bytecode(self, bytecode: str) -> AnalysisResult:
        start_time = time.time()
        logger.info("Analyzing bytecode directly")

        self.bytecode_analyzer.disassemble(bytecode)
        vulnerabilities = []

        reentrancy = self.bytecode_analyzer.detect_reentrancy_pattern()
        for pattern in reentrancy:
            from automatonsec.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation
            vuln = Vulnerability(
                type=VulnerabilityType.REENTRANCY,
                severity=Severity.CRITICAL,
                name="Potential Reentrancy Pattern Detected",
                description=f"External call at {pattern['call_address']:04x} followed by state change at {pattern['sstore_address']:04x}",
                location=SourceLocation("<bytecode>", pattern['call_address'], pattern['call_address']),
                confidence=0.75,
                impact="An attacker could re-enter the contract and manipulate state",
                recommendation="Implement checks-effects-interactions pattern or use ReentrancyGuard",
            )
            vulnerabilities.append(vuln)

        analysis_time = time.time() - start_time

        return AnalysisResult(
            contract_name="<bytecode>",
            contract_address=None,
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            timestamp=datetime.now(),
            engine_version=self.VERSION,
            total_functions=len(self.bytecode_analyzer.extract_function_selectors()),
            analyzed_paths=len(self.bytecode_analyzer.instructions),
            coverage=100.0,
        )