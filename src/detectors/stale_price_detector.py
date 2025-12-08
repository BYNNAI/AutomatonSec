# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation

logger = logging.getLogger(__name__)


class StalePriceDetector:
    """
    Detects usage of stale oracle prices.
    """

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        oracle_calls = self._find_oracle_calls(symbolic_results)
        
        for call in oracle_calls:
            if not self._validates_freshness(call):
                vuln = Vulnerability(
                    type=VulnerabilityType.STALE_PRICE,
                    severity=Severity.HIGH,
                    name="Stale Oracle Price",
                    description=f"Oracle price used without timestamp validation",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=call.get('line', 0),
                        line_end=call.get('line', 0),
                        function=call.get('function', 'unknown')
                    ),
                    confidence=0.85,
                    impact="Stale prices can be exploited for arbitrage",
                    recommendation="Validate oracle timestamp and implement heartbeat checks",
                    technical_details=call
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_oracle_calls(self, symbolic_results: Dict) -> List[Dict]:
        calls = []
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if 'oracle' in op.get('target', '').lower() or 'price' in op.get('function', '').lower():
                    calls.append(op)
        return calls

    def _validates_freshness(self, call: Dict) -> bool:
        return call.get('checks_timestamp', False) or call.get('validates_update', False)
