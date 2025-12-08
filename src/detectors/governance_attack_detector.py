# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class GovernanceAttackDetector:
    """
    Detects governance manipulation vulnerabilities.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        voting_functions = self._find_voting_functions(bytecode_analysis)
        
        for func in voting_functions:
            if self._vulnerable_to_flash_loan(func):
                vuln = Vulnerability(
                    type=VulnerabilityType.GOVERNANCE_ATTACK,
                    severity=Severity.CRITICAL,
                    name="Flash Loan Governance Attack",
                    description=f"Voting vulnerable to flash loan manipulation",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=func.get('line', 0),
                        line_end=func.get('line', 0),
                        function=func.get('name', 'unknown')
                    ),
                    confidence=0.88,
                    impact="Attacker can manipulate governance with temporary voting power",
                    recommendation="Use snapshot-based voting or time-weighted voting",
                    technical_details=func
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_voting_functions(self, bytecode_analysis: Dict) -> List[Dict]:
        functions = []
        for func in bytecode_analysis.get('functions', []):
            if any(kw in func.get('name', '').lower() for kw in ['vote', 'propose']):
                functions.append(func)
        return functions

    def _vulnerable_to_flash_loan(self, func: Dict) -> bool:
        return func.get('uses_current_balance', True) and not func.get('uses_snapshot', False)
