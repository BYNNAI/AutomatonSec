# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class DonationAttackDetector:
    """
    Detects donation-based attacks via direct transfers.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        balance_deps = self._find_balance_dependencies(symbolic_results)
        
        for dep in balance_deps:
            if not self._has_protection(dep):
                vuln = Vulnerability(
                    type=VulnerabilityType.DONATION_ATTACK,
                    severity=Severity.HIGH,
                    name="Donation Attack Vulnerability",
                    description=f"Function depends on untracked balance",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=dep.get('line', 0),
                        line_end=dep.get('line', 0),
                        function=dep.get('function', 'unknown')
                    ),
                    confidence=0.82,
                    impact="Attacker can manipulate behavior via direct transfers",
                    recommendation="Track deposits explicitly",
                    technical_details=dep
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_balance_dependencies(self, symbolic_results: Dict) -> List[Dict]:
        deps = []
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if 'balance' in op.get('expression', '').lower():
                    deps.append(op)
        return deps

    def _has_protection(self, dep: Dict) -> bool:
        expr = dep.get('expression', '').lower()
        return 'tracked' in expr or 'recorded' in expr
