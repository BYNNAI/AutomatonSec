# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Optional
from collections import defaultdict
import re

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class StorageCollisionAnalyzer:
    """
    Production-grade storage collision detector.
    Real-world: Audius ($6M), Wormhole ($10M bounty)
    Target accuracy: 90-95%
    """

    EIP1967_SLOTS = {
        'implementation': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
        'admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
        'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
    }

    def __init__(self):
        self.proxy_storage: Dict[str, Dict] = {}
        self.impl_storage: Dict[str, Dict] = {}
        self.collisions: List[Dict] = []

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        is_proxy = self._detect_proxy_pattern(bytecode_analysis)
        
        if is_proxy:
            self._map_proxy_storage(symbolic_results)
            self._map_implementation_storage(bytecode_analysis)
            
            collisions = self._detect_slot_collisions()
            for collision in collisions:
                vuln = self._create_vulnerability(collision)
                vulnerabilities.append(vuln)
            
            eip_violations = self._validate_eip1967()
            for violation in eip_violations:
                vuln = self._create_eip1967_vuln(violation)
                vulnerabilities.append(vuln)
        
        inheritance_issues = self._check_inheritance(bytecode_analysis)
        vulnerabilities.extend(inheritance_issues)
        
        return vulnerabilities

    def _detect_proxy_pattern(self, bytecode_analysis: Dict) -> bool:
        functions = bytecode_analysis.get('functions', [])
        has_delegatecall = any(
            'delegatecall' in func.get('name', '').lower() or
            'upgradeto' in func.get('name', '').lower()
            for func in functions
        )
        opcodes = bytecode_analysis.get('opcodes', [])
        has_delegatecall_op = any(op.get('opcode') == 'DELEGATECALL' for op in opcodes)
        return has_delegatecall or has_delegatecall_op

    def _map_proxy_storage(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            if path.get('function', '').lower() not in ['constructor', 'initialize']:
                continue
            for op in path.get('operations', []):
                if op.get('type') == 'sstore':
                    slot = op.get('slot')
                    var = op.get('variable', 'unknown')
                    self.proxy_storage[var] = {'slot': slot, 'location': op.get('location', {})}

    def _map_implementation_storage(self, bytecode_analysis: Dict) -> None:
        state_vars = bytecode_analysis.get('state_variables', [])
        current_slot = 0
        for var in state_vars:
            self.impl_storage[var.get('name')] = {
                'slot': current_slot,
                'type': var.get('type')
            }
            current_slot += 1

    def _detect_slot_collisions(self) -> List[Dict]:
        collisions = []
        for pvar, pinfo in self.proxy_storage.items():
            for ivar, iinfo in self.impl_storage.items():
                if pinfo['slot'] == iinfo['slot']:
                    collisions.append({
                        'proxy_var': pvar, 'impl_var': ivar,
                        'slot': pinfo['slot'], 'location': pinfo['location']
                    })
        return collisions

    def _validate_eip1967(self) -> List[Dict]:
        violations = []
        for var, info in self.proxy_storage.items():
            if 'implementation' in var.lower():
                if info['slot'] != self.EIP1967_SLOTS['implementation']:
                    violations.append({'var': var, 'slot': info['slot'], 'expected': self.EIP1967_SLOTS['implementation']})
        return violations

    def _check_inheritance(self, bytecode_analysis: Dict) -> List[Vulnerability]:
        vulns = []
        inheritance = bytecode_analysis.get('inheritance', [])
        if len(inheritance) > 1:
            source = bytecode_analysis.get('source_code', '')
            if not re.search(r'uint256\[\d+\]\s+private\s+__gap', source):
                vulns.append(Vulnerability(
                    type=VulnerabilityType.STORAGE_COLLISION,
                    severity=Severity.MEDIUM,
                    name="Missing Storage Gap",
                    description="Upgradeable contract lacks storage gap",
                    location=SourceLocation(file="contract.sol", line_start=0, line_end=0),
                    confidence=0.85,
                    impact="Future upgrades may cause storage collisions",
                    recommendation="Add: uint256[50] private __gap;"
                ))
        return vulns

    def _create_vulnerability(self, collision: Dict) -> Vulnerability:
        poc = f"""// Storage Collision Attack (Audius-style $6M)
// Slot {collision['slot']}: {collision['proxy_var']} (proxy) vs {collision['impl_var']} (implementation)
implementation.set_{collision['impl_var']}(attackerAddress);
// Overwrites proxy.{collision['proxy_var']} = attackerAddress
// Attacker now controls proxy!
"""
        return Vulnerability(
            type=VulnerabilityType.STORAGE_COLLISION,
            severity=Severity.CRITICAL,
            name="Proxy Storage Collision",
            description=f"Slot {collision['slot']} collision: proxy '{collision['proxy_var']}' vs impl '{collision['impl_var']}'",
            location=SourceLocation(
                file="contract.sol",
                line_start=collision.get('location', {}).get('line', 0),
                line_end=collision.get('location', {}).get('line', 0)
            ),
            confidence=0.95,
            impact="CRITICAL: Implementation overwrites proxy state. $6M Audius hack pattern.",
            recommendation="Use EIP-1967 slots: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            exploit=Exploit(
                description="Storage collision proxy takeover",
                attack_vector=f"Write to {collision['impl_var']} overwrites {collision['proxy_var']}",
                profit_estimate=6000000.0,
                proof_of_concept=poc
            )
        )

    def _create_eip1967_vuln(self, violation: Dict) -> Vulnerability:
        return Vulnerability(
            type=VulnerabilityType.STORAGE_COLLISION,
            severity=Severity.HIGH,
            name="EIP-1967 Non-Compliance",
            description=f"Variable '{violation['var']}' uses non-standard slot {violation['slot']}",
            location=SourceLocation(file="contract.sol", line_start=0, line_end=0),
            confidence=0.90,
            impact="Vulnerable to storage collisions",
            recommendation=f"Use EIP-1967 slot: {violation['expected']}"
        )
