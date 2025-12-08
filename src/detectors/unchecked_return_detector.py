# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class UncheckedReturnDetector:
    """
    Detects unchecked return values from external calls.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        external_calls = self._find_external_calls(cfg)
        
        for call in external_calls:
            if self._is_unchecked(call):
                vuln = Vulnerability(
                    type=VulnerabilityType.UNCHECKED_RETURN,
                    severity=Severity.HIGH,
                    name="Unchecked Return Value",
                    description=f"Return value not checked",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=call.get('line', 0),
                        line_end=call.get('line', 0),
                        function=call.get('caller', 'unknown')
                    ),
                    confidence=0.90,
                    impact="Silent failures can lead to fund loss",
                    recommendation="Check return value with require() or use SafeERC20",
                    technical_details=call
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_external_calls(self, cfg: Dict) -> List[Dict]:
        calls = []
        for node in cfg.get('nodes', []):
            if node.get('type') == 'external_call':
                calls.append(node)
        return calls

    def _is_unchecked(self, call: Dict) -> bool:
        return not call.get('return_checked', False)
