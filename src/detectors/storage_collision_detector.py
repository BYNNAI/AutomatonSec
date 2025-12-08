# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Tuple

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class StorageCollisionDetector:
    """
    Detects storage slot collisions in proxy patterns where implementation
    and proxy storage layouts conflict. Critical for upgradeable contracts.
    """

    def __init__(self):
        self.storage_layout: Dict[str, int] = {}
        self.proxy_slots: Set[int] = set()
        self.implementation_slots: Set[int] = set()

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Detect storage collision vulnerabilities.
        """
        vulnerabilities = []
        
        self._analyze_storage_layout(bytecode_analysis)
        collisions = self._find_collisions()
        
        for collision in collisions:
            vuln = Vulnerability(
                type=VulnerabilityType.STORAGE_COLLISION,
                severity=Severity.CRITICAL,
                name="Storage Slot Collision",
                description=f"Storage slot {collision['slot']} collides between proxy and implementation",
                location=SourceLocation(
                    file="contract.sol",
                    line_start=0,
                    line_end=0
                ),
                confidence=0.95,
                impact="Storage collision can corrupt contract state and lead to fund loss or contract takeover",
                recommendation="Use EIP-1967 standard storage slots or namespaced storage patterns",
                technical_details=collision
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _analyze_storage_layout(self, bytecode_analysis: Dict) -> None:
        """Analyze storage slot assignments."""
        for var in bytecode_analysis.get('state_variables', []):
            slot = var.get('storage_slot', 0)
            var_name = var.get('name', '')
            self.storage_layout[var_name] = slot
            
            if self._is_proxy_slot(var_name):
                self.proxy_slots.add(slot)
            else:
                self.implementation_slots.add(slot)

    def _is_proxy_slot(self, var_name: str) -> bool:
        """Check if variable is a proxy-specific slot."""
        proxy_patterns = ['implementation', 'admin', '_owner', 'initializable']
        return any(pattern in var_name.lower() for pattern in proxy_patterns)

    def _find_collisions(self) -> List[Dict]:
        """Find colliding storage slots."""
        collisions = []
        collision_slots = self.proxy_slots.intersection(self.implementation_slots)
        
        for slot in collision_slots:
            proxy_vars = [k for k, v in self.storage_layout.items() if v == slot and self._is_proxy_slot(k)]
            impl_vars = [k for k, v in self.storage_layout.items() if v == slot and not self._is_proxy_slot(k)]
            
            collisions.append({
                'slot': slot,
                'proxy_variables': proxy_vars,
                'implementation_variables': impl_vars,
                'risk': 'HIGH'
            })
        
        return collisions
