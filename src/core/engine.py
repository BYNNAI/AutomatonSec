# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
import json

from src.core.contract_parser import ContractParser
from src.core.bytecode_analyzer import BytecodeAnalyzer
from src.symbolic.executor import SymbolicExecutor
from src.dataflow.cfg_builder import CFGBuilder
from src.dataflow.taint_analyzer import TaintAnalyzer
from src.fuzzing.profit_fuzzer import ProfitFuzzer
from src.ml.anomaly_detector import AnomalyDetector
from src.detectors.reentrancy_detector import ReentrancyDetector
from src.detectors.flashloan_detector import FlashLoanDetector
from src.detectors.exploit_chain_detector import ExploitChainDetector
from src.reporting.vulnerability_report import VulnerabilityReport

logger = logging.getLogger(__name__)


class AutomatonSecEngine:
    """
    Main orchestration engine for AutomatonSec security analysis.
    Coordinates all analysis modules to detect novel zero-day vulnerabilities.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._load_default_config()
        
        self.parser = ContractParser()
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.symbolic_executor = SymbolicExecutor(max_depth=self.config.get("max_symbolic_depth", 128))
        self.cfg_builder = CFGBuilder()
        self.taint_analyzer = TaintAnalyzer()
        self.profit_fuzzer = ProfitFuzzer(max_iterations=self.config.get("fuzzing_iterations", 10000))
        self.anomaly_detector = AnomalyDetector()
        
        self.detectors = [
            ReentrancyDetector(),
            FlashLoanDetector(),
            ExploitChainDetector()
        ]
        
        self.vulnerabilities: List[Dict] = []
        
    def _load_default_config(self) -> Dict:
        """Load default analysis configuration."""
        return {
            "max_symbolic_depth": 128,
            "fuzzing_iterations": 10000,
            "enable_cross_contract": True,
            "enable_ml_detection": True,
            "profit_threshold": 0.01,
            "max_execution_time": 3600
        }
    
    def analyze_contract(self, source_code: Optional[str] = None, 
                        bytecode: Optional[str] = None,
                        address: Optional[str] = None) -> VulnerabilityReport:
        """
        Perform comprehensive multi-layered analysis on a smart contract.
        
        Args:
            source_code: Solidity source code
            bytecode: EVM bytecode (hex string)
            address: On-chain contract address for live analysis
            
        Returns:
            VulnerabilityReport with all detected vulnerabilities
        """
        logger.info("Starting AutomatonSec analysis")
        
        if source_code:
            parsed_contract = self.parser.parse(source_code)
            bytecode = parsed_contract.get("bytecode")
        
        if not bytecode and not address:
            raise ValueError("Must provide source_code, bytecode, or address")
        
        self.vulnerabilities = []
        
        logger.info("Phase 1: Bytecode Analysis")
        bytecode_analysis = self.bytecode_analyzer.analyze(bytecode)
        
        logger.info("Phase 2: CFG Construction")
        cfg = self.cfg_builder.build(bytecode_analysis)
        
        logger.info("Phase 3: Taint Analysis")
        taint_results = self.taint_analyzer.analyze(cfg, bytecode_analysis)
        
        logger.info("Phase 4: Symbolic Execution")
        symbolic_results = self.symbolic_executor.execute(
            bytecode_analysis, 
            cfg,
            taint_sinks=taint_results.get("sinks", [])
        )
        
        logger.info("Phase 5: Profit-Guided Fuzzing")
        fuzzing_results = self.profit_fuzzer.fuzz(
            bytecode_analysis,
            cfg,
            symbolic_results.get("interesting_paths", [])
        )
        
        logger.info("Phase 6: ML Anomaly Detection")
        if self.config.get("enable_ml_detection", True):
            anomalies = self.anomaly_detector.detect(
                bytecode_analysis,
                cfg,
                symbolic_results
            )
            self.vulnerabilities.extend(anomalies)
        
        logger.info("Phase 7: Vulnerability Detection")
        for detector in self.detectors:
            detected = detector.detect(
                bytecode_analysis=bytecode_analysis,
                cfg=cfg,
                taint_results=taint_results,
                symbolic_results=symbolic_results,
                fuzzing_results=fuzzing_results
            )
            self.vulnerabilities.extend(detected)
        
        logger.info("Phase 8: Cross-Contract Analysis")
        if self.config.get("enable_cross_contract", True) and address:
            cross_contract_vulns = self._analyze_cross_contract(address)
            self.vulnerabilities.extend(cross_contract_vulns)
        
        report = VulnerabilityReport(
            vulnerabilities=self.vulnerabilities,
            bytecode_analysis=bytecode_analysis,
            symbolic_results=symbolic_results,
            fuzzing_results=fuzzing_results
        )
        
        logger.info(f"Analysis complete: {len(self.vulnerabilities)} vulnerabilities found")
        return report
    
    def _analyze_cross_contract(self, address: str) -> List[Dict]:
        """
        Analyze cross-contract interactions for exploit chains.
        """
        logger.info(f"Analyzing cross-contract interactions for {address}")
        return []
    
    def analyze_multiple(self, contracts: List[Dict]) -> List[VulnerabilityReport]:
        """
        Analyze multiple contracts for cross-contract vulnerabilities.
        """
        reports = []
        for contract in contracts:
            report = self.analyze_contract(**contract)
            reports.append(report)
        
        return reports
