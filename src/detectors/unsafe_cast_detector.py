# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class UnsafeCastDetector:
    """
    Detects unsafe type casting that can lead to overflow.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        cast_operations = self._find_casts(symbolic_results)
        
        for cast in cast_operations:
            if self._is_unsafe(cast):
                vuln = Vulnerability(
                    type=VulnerabilityType.UNSAFE_CAST,
                    severity=Severity.HIGH,
                    name="Unsafe Type Cast",
                    description=f"Unsafe downcast detected",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=cast.get('line', 0),
                        line_end=cast.get('line', 0),
                        function=cast.get('function', 'unknown')
                    ),
                    confidence=0.92,
                    impact="Type casting can cause silent overflow",
                    recommendation="Use SafeCast library or add bounds checking",
                    technical_details=cast
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_casts(self, symbolic_results: Dict) -> List[Dict]:
        casts = []
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'cast':
                    casts.append(op)
        return casts

    def _is_unsafe(self, cast: Dict) -> bool:
        return not cast.get('bounds_checked', False)
