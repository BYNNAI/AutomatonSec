# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class SandwichAttackDetector:
    """
    Detects MEV sandwich attack vulnerabilities.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        swap_functions = self._find_swap_functions(bytecode_analysis)
        
        for swap in swap_functions:
            if self._lacks_slippage_protection(swap):
                vuln = Vulnerability(
                    type=VulnerabilityType.SANDWICH_ATTACK,
                    severity=Severity.MEDIUM,
                    name="MEV Sandwich Attack Vector",
                    description=f"Swap lacks adequate slippage protection",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=swap.get('line', 0),
                        line_end=swap.get('line', 0),
                        function=swap.get('name', 'unknown')
                    ),
                    confidence=0.80,
                    impact="Users can be sandwich attacked by MEV bots",
                    recommendation="Implement strict slippage limits and deadline checks",
                    technical_details=swap
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_swap_functions(self, bytecode_analysis: Dict) -> List[Dict]:
        functions = []
        for func in bytecode_analysis.get('functions', []):
            if any(kw in func.get('name', '').lower() for kw in ['swap', 'trade']):
                functions.append(func)
        return functions

    def _lacks_slippage_protection(self, swap: Dict) -> bool:
        params = swap.get('parameters', [])
        has_min = any('min' in str(p).lower() for p in params)
        has_deadline = any('deadline' in str(p).lower() for p in params)
        return not (has_min and has_deadline)
