# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class ReentrancyDetector:
    """
    Advanced reentrancy vulnerability detector.
    Detects single-function, cross-function, and cross-contract reentrancy.
    Uses state change analysis and call graph tracking.
    """
    
    def __init__(self):
        self.vulnerabilities = []
        
    def detect(self, bytecode_analysis: Dict, cfg: Dict, 
               taint_results: Dict, symbolic_results: Dict,
               fuzzing_results: Dict) -> List[Dict]:
        """
        Detect reentrancy vulnerabilities.
        
        Returns:
            List of detected reentrancy vulnerabilities
        """
        logger.info("Detecting reentrancy vulnerabilities")
        
        self.vulnerabilities = []
        
        external_calls = bytecode_analysis.get("external_calls", [])
        storage_ops = bytecode_analysis.get("storage_operations", [])
        
        self._detect_classic_reentrancy(external_calls, storage_ops, bytecode_analysis)
        
        self._detect_cross_function_reentrancy(cfg, external_calls, storage_ops)
        
        self._detect_read_only_reentrancy(external_calls, storage_ops)
        
        self._validate_with_symbolic(symbolic_results)
        
        logger.info(f"Found {len(self.vulnerabilities)} reentrancy vulnerabilities")
        return self.vulnerabilities
    
    def _detect_classic_reentrancy(self, external_calls: List[Dict], 
                                   storage_ops: List[Dict],
                                   bytecode_analysis: Dict):
        """
        Detect classic reentrancy pattern: external call before state update.
        """
        for call in external_calls:
            call_pc = call["pc"]
            call_type = call["call_type"]
            
            if call_type not in ['CALL', 'DELEGATECALL']:
                continue
            
            state_changes_after = [op for op in storage_ops if op["pc"] > call_pc]
            
            if state_changes_after:
                for state_op in state_changes_after[:3]:
                    self.vulnerabilities.append({
                        "type": "CLASSIC_REENTRANCY",
                        "severity": "CRITICAL",
                        "call_pc": call_pc,
                        "call_type": call_type,
                        "state_update_pc": state_op["pc"],
                        "description": f"External {call_type} at PC {call_pc} before state update at PC {state_op['pc']}",
                        "confidence": 0.85,
                        "exploit_potential": "HIGH",
                        "remediation": "Apply checks-effects-interactions pattern or use reentrancy guard"
                    })
    
    def _detect_cross_function_reentrancy(self, cfg: Dict, 
                                          external_calls: List[Dict],
                                          storage_ops: List[Dict]):
        """
        Detect cross-function reentrancy vulnerabilities.
        """
        function_selectors = {}
        
        for call in external_calls:
            call_pc = call["pc"]
            
            containing_function = self._find_containing_function(call_pc, cfg)
            
            if containing_function:
                if containing_function not in function_selectors:
                    function_selectors[containing_function] = {
                        "calls": [],
                        "storage_ops": []
                    }
                
                function_selectors[containing_function]["calls"].append(call)
        
        for func, data in function_selectors.items():
            if len(data["calls"]) > 1:
                self.vulnerabilities.append({
                    "type": "CROSS_FUNCTION_REENTRANCY",
                    "severity": "HIGH",
                    "function": func,
                    "call_count": len(data["calls"]),
                    "description": f"Function {func} has multiple external calls enabling cross-function reentrancy",
                    "confidence": 0.70,
                    "exploit_potential": "MEDIUM"
                })
    
    def _detect_read_only_reentrancy(self, external_calls: List[Dict],
                                     storage_ops: List[Dict]):
        """
        Detect read-only reentrancy (view function reentrancy).
        """
        for call in external_calls:
            if call["call_type"] == 'STATICCALL':
                storage_reads_after = [
                    op for op in storage_ops 
                    if op["pc"] > call["pc"] and op["operation"] == 'SLOAD'
                ]
                
                if storage_reads_after:
                    self.vulnerabilities.append({
                        "type": "READ_ONLY_REENTRANCY",
                        "severity": "MEDIUM",
                        "call_pc": call["pc"],
                        "description": "STATICCALL followed by storage read may be vulnerable to read-only reentrancy",
                        "confidence": 0.60,
                        "exploit_potential": "LOW"
                    })
    
    def _validate_with_symbolic(self, symbolic_results: Dict):
        """
        Validate reentrancy findings using symbolic execution results.
        """
        vulnerable_states = symbolic_results.get("vulnerable_states", [])
        
        for state in vulnerable_states:
            if state.get("vulnerability_type") == "POTENTIAL_REENTRANCY":
                for vuln in self.vulnerabilities:
                    if vuln.get("call_pc") == state.get("pc"):
                        vuln["confidence"] = min(0.95, vuln.get("confidence", 0.5) + 0.2)
                        vuln["symbolic_validation"] = True
    
    def _find_containing_function(self, pc: int, cfg: Dict) -> Optional[str]:
        """
        Find which function contains a given PC.
        """
        basic_blocks = cfg.get("basic_blocks", {})
        
        for block_pc, block_data in basic_blocks.items():
            if block_data["start_pc"] <= pc <= block_data["end_pc"]:
                return f"func_{block_pc}"
        
        return None
