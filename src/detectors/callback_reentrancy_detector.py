# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class CallbackReentrancyDetector:
    """
    Detects reentrancy through ERC721/ERC1155 callbacks.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        callback_patterns = self._find_callback_patterns(cfg)
        
        for pattern in callback_patterns:
            if self._has_reentrancy_risk(pattern):
                vuln = Vulnerability(
                    type=VulnerabilityType.CALLBACK_REENTRANCY,
                    severity=Severity.HIGH,
                    name="Callback Reentrancy",
                    description=f"NFT transfer callback can reenter",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=pattern.get('line', 0),
                        line_end=pattern.get('line', 0),
                        function=pattern.get('function', 'unknown')
                    ),
                    confidence=0.87,
                    impact="Callback reentrancy can manipulate state",
                    recommendation="Use checks-effects-interactions or reentrancy guard",
                    technical_details=pattern
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_callback_patterns(self, cfg: Dict) -> List[Dict]:
        patterns = []
        callbacks = ['safetransferfrom', 'safemint']
        
        for node in cfg.get('nodes', []):
            func = node.get('function', '').lower()
            if any(cb in func for cb in callbacks):
                patterns.append(node)
        
        return patterns

    def _has_reentrancy_risk(self, pattern: Dict) -> bool:
        has_state = pattern.get('state_changes', False)
        lacks_guard = not pattern.get('has_reentrancy_guard', False)
        return has_state and lacks_guard
