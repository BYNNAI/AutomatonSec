# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class ReadOnlyReentrancyDetector:
    """
    Detects read-only reentrancy vulnerabilities where view/pure functions
    can be called during external calls to read stale state values.
    Common in protocols using Curve/Balancer LP tokens or similar mechanisms.
    """

    def __init__(self):
        self.view_functions: Set[str] = set()
        self.external_calls: List[Dict] = []
        self.state_reads: Dict[str, List[str]] = {}

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Detect read-only reentrancy patterns.
        """
        vulnerabilities = []
        
        self._identify_view_functions(bytecode_analysis)
        self._track_external_calls(cfg)
        self._analyze_state_reads(symbolic_results)
        
        vulnerable_patterns = self._find_vulnerable_patterns()
        
        for pattern in vulnerable_patterns:
            vuln = Vulnerability(
                type=VulnerabilityType.READ_ONLY_REENTRANCY,
                severity=Severity.HIGH,
                name="Read-Only Reentrancy",
                description=f"View function {pattern['function']} reads state that can be manipulated during external call",
                location=SourceLocation(
                    file="contract.sol",
                    line_start=pattern.get('line', 0),
                    line_end=pattern.get('line', 0),
                    function=pattern['function']
                ),
                confidence=0.85,
                impact="Attackers can exploit stale state reads to manipulate oracle prices, LP token values, or accounting",
                recommendation="Use reentrancy guards on view functions or ensure state consistency before external calls",
                technical_details=pattern
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_view_functions(self, bytecode_analysis: Dict) -> None:
        """Identify view/pure functions in the contract."""
        functions = bytecode_analysis.get('functions', [])
        for func in functions:
            if func.get('stateMutability') in ['view', 'pure']:
                self.view_functions.add(func['name'])

    def _track_external_calls(self, cfg: Dict) -> None:
        """Track all external calls in the control flow."""
        for node in cfg.get('nodes', []):
            if node.get('type') == 'external_call':
                self.external_calls.append({
                    'function': node.get('function'),
                    'target': node.get('target'),
                    'node_id': node.get('id')
                })

    def _analyze_state_reads(self, symbolic_results: Dict) -> None:
        """Analyze which state variables are read by view functions."""
        for path in symbolic_results.get('paths', []):
            for operation in path.get('operations', []):
                if operation.get('type') == 'sload':
                    func = operation.get('function')
                    var = operation.get('variable')
                    if func not in self.state_reads:
                        self.state_reads[func] = []
                    self.state_reads[func].append(var)

    def _find_vulnerable_patterns(self) -> List[Dict]:
        """Identify vulnerable read-only reentrancy patterns."""
        vulnerable = []
        
        for ext_call in self.external_calls:
            for view_func in self.view_functions:
                if view_func in self.state_reads:
                    vulnerable.append({
                        'function': view_func,
                        'external_call': ext_call,
                        'state_variables': self.state_reads[view_func],
                        'pattern': 'read_only_reentrancy'
                    })
        
        return vulnerable
