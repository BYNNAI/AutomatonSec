# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class AccessControlDetector:
    """
    Detects access control vulnerabilities including missing checks,
    weak authorization, and privilege escalation.
    """
    
    def __init__(self):
        self.vulnerabilities = []
    
    def detect(self, bytecode_analysis: Dict, cfg: Dict,
               taint_results: Dict, symbolic_results: Dict,
               fuzzing_results: Dict) -> List[Dict]:
        """
        Detect access control vulnerabilities.
        """
        logger.info("Detecting access control vulnerabilities")
        
        self.vulnerabilities = []
        
        self._detect_missing_access_checks(bytecode_analysis, taint_results)
        self._detect_weak_authorization(symbolic_results)
        
        return self.vulnerabilities
    
    def _detect_missing_access_checks(self, bytecode_analysis: Dict,
                                      taint_results: Dict):
        """
        Detect critical operations without access control.
        """
        external_calls = bytecode_analysis.get("external_calls", [])
        taint_flows = taint_results.get("taint_flows", [])
        
        for call in external_calls:
            if call["call_type"] in ['DELEGATECALL', 'SELFDESTRUCT']:
                has_caller_check = any(
                    flow.get("source_pc", -1) < call["pc"]
                    for flow in taint_flows
                    if 'CALLER' in str(flow)
                )
                
                if not has_caller_check:
                    self.vulnerabilities.append({
                        "type": "MISSING_ACCESS_CONTROL",
                        "severity": "CRITICAL",
                        "pc": call["pc"],
                        "operation": call["call_type"],
                        "confidence": 0.80
                    })
    
    def _detect_weak_authorization(self, symbolic_results: Dict):
        """
        Detect weak authorization patterns.
        """
        vulnerable_states = symbolic_results.get("vulnerable_states", [])
        
        for state in vulnerable_states:
            if len(state.get("constraints", [])) < 2:
                self.vulnerabilities.append({
                    "type": "WEAK_AUTHORIZATION",
                    "severity": "HIGH",
                    "pc": state.get("pc"),
                    "confidence": 0.65
                })
