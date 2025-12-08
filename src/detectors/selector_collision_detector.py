# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set
import hashlib

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class SelectorCollisionDetector:
    """
    Detects function selector collisions where different function signatures
    produce the same 4-byte selector. Can be exploited in proxy patterns.
    """

    def __init__(self):
        self.selectors: Dict[str, List[str]] = {}

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Detect function selector collisions.
        """
        vulnerabilities = []
        
        self._compute_selectors(bytecode_analysis)
        collisions = self._find_collisions()
        
        for collision in collisions:
            vuln = Vulnerability(
                type=VulnerabilityType.SELECTOR_COLLISION,
                severity=Severity.HIGH,
                name="Function Selector Collision",
                description=f"Functions {collision['functions']} have the same selector {collision['selector']}",
                location=SourceLocation(
                    file="contract.sol",
                    line_start=0,
                    line_end=0
                ),
                confidence=1.0,
                impact="Selector collision can lead to wrong function execution in proxy contracts",
                recommendation="Use unique function signatures or implement selector validation",
                technical_details=collision
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _compute_selectors(self, bytecode_analysis: Dict) -> None:
        """Compute function selectors for all functions."""
        functions = bytecode_analysis.get('functions', [])
        
        for func in functions:
            signature = func.get('signature', '')
            if signature:
                selector = self._calculate_selector(signature)
                if selector not in self.selectors:
                    self.selectors[selector] = []
                self.selectors[selector].append(signature)

    def _calculate_selector(self, signature: str) -> str:
        """Calculate 4-byte function selector."""
        hash_bytes = hashlib.sha3_256(signature.encode()).digest()
        return hash_bytes[:4].hex()

    def _find_collisions(self) -> List[Dict]:
        """Find selector collisions."""
        collisions = []
        
        for selector, functions in self.selectors.items():
            if len(functions) > 1:
                collisions.append({
                    'selector': selector,
                    'functions': functions,
                    'count': len(functions)
                })
        
        return collisions
