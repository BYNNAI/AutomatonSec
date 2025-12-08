# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class JITLiquidityDetector:
    """
    Detects Just-In-Time liquidity attacks.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        liquidity_ops = self._find_liquidity_operations(bytecode_analysis)
        
        for op in liquidity_ops:
            if self._vulnerable_to_jit(op):
                vuln = Vulnerability(
                    type=VulnerabilityType.JIT_LIQUIDITY,
                    severity=Severity.MEDIUM,
                    name="JIT Liquidity Attack Vector",
                    description=f"Liquidity operation vulnerable to JIT attacks",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=op.get('line', 0),
                        line_end=op.get('line', 0),
                        function=op.get('name', 'unknown')
                    ),
                    confidence=0.70,
                    impact="MEV bots can front-run with JIT liquidity",
                    recommendation="Implement liquidity lock periods",
                    technical_details=op
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_liquidity_operations(self, bytecode_analysis: Dict) -> List[Dict]:
        operations = []
        for func in bytecode_analysis.get('functions', []):
            if any(kw in func.get('name', '').lower() for kw in ['addliquidity', 'mint']):
                operations.append(func)
        return operations

    def _vulnerable_to_jit(self, op: Dict) -> bool:
        lacks_lock = not op.get('has_lock_period', False)
        instant_withdrawal = op.get('allows_instant_withdrawal', True)
        return lacks_lock and instant_withdrawal
