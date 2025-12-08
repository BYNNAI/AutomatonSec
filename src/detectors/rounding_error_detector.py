# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class RoundingErrorDetector:
    """
    Detects precision loss and rounding errors in financial calculations.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        division_operations = self._find_divisions(symbolic_results)
        
        for op in division_operations:
            if self._has_rounding_risk(op):
                vuln = Vulnerability(
                    type=VulnerabilityType.ROUNDING_ERROR,
                    severity=Severity.MEDIUM,
                    name="Precision Loss / Rounding Error",
                    description=f"Division operation may cause precision loss",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=op.get('line', 0),
                        line_end=op.get('line', 0),
                        function=op.get('function', 'unknown')
                    ),
                    confidence=0.75,
                    impact="Users may lose funds due to rounding errors",
                    recommendation="Multiply before divide or use higher precision",
                    technical_details=op
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_divisions(self, symbolic_results: Dict) -> List[Dict]:
        divisions = []
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('operator') == 'div':
                    divisions.append(op)
        return divisions

    def _has_rounding_risk(self, op: Dict) -> bool:
        expr = op.get('expression', '').lower()
        return any(kw in expr for kw in ['amount', 'shares', 'fee'])
