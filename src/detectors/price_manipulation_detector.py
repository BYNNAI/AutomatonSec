# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class PriceManipulationDetector:
    """
    Detects price manipulation vulnerabilities in AMMs and DEXs where
    attackers can manipulate spot prices through flash loans or large swaps.
    """

    def __init__(self):
        self.price_queries: List[Dict] = []
        self.swap_functions: Set[str] = set()
        self.oracle_calls: List[Dict] = []

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Detect price manipulation vulnerabilities.
        """
        vulnerabilities = []
        
        self._identify_price_queries(bytecode_analysis)
        self._track_oracle_usage(symbolic_results)
        
        vulnerable_patterns = self._find_manipulation_vectors()
        
        for pattern in vulnerable_patterns:
            exploit = self._generate_exploit(pattern)
            
            vuln = Vulnerability(
                type=VulnerabilityType.PRICE_MANIPULATION,
                severity=Severity.CRITICAL,
                name="Price Oracle Manipulation",
                description=f"Price query in {pattern['function']} can be manipulated via spot price",
                location=SourceLocation(
                    file="contract.sol",
                    line_start=pattern.get('line', 0),
                    line_end=pattern.get('line', 0),
                    function=pattern['function']
                ),
                confidence=0.88,
                impact="Attacker can manipulate price oracle to drain funds or gain unfair advantage",
                recommendation="Use TWAP oracle, Chainlink price feeds, or implement manipulation resistance",
                exploit=exploit,
                technical_details=pattern
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_price_queries(self, bytecode_analysis: Dict) -> None:
        """Identify price query operations."""
        functions = bytecode_analysis.get('functions', [])
        for func in functions:
            if self._is_price_function(func['name']):
                self.price_queries.append({
                    'function': func['name'],
                    'signature': func.get('signature', '')
                })

    def _is_price_function(self, name: str) -> bool:
        """Check if function is related to price queries."""
        price_keywords = ['price', 'getamount', 'quote', 'rate', 'exchange']
        return any(keyword in name.lower() for keyword in price_keywords)

    def _track_oracle_usage(self, symbolic_results: Dict) -> None:
        """Track oracle usage in execution paths."""
        for path in symbolic_results.get('paths', []):
            for operation in path.get('operations', []):
                if operation.get('type') == 'external_call':
                    target = operation.get('target', '')
                    if 'pair' in target.lower() or 'pool' in target.lower():
                        self.oracle_calls.append({
                            'function': operation.get('function'),
                            'target': target,
                            'path_id': path.get('id')
                        })

    def _find_manipulation_vectors(self) -> List[Dict]:
        """Find price manipulation attack vectors."""
        vulnerable = []
        
        for query in self.price_queries:
            for oracle in self.oracle_calls:
                if self._is_manipulable(oracle):
                    vulnerable.append({
                        'function': query['function'],
                        'oracle': oracle['target'],
                        'attack_type': 'spot_price_manipulation'
                    })
        
        return vulnerable

    def _is_manipulable(self, oracle: Dict) -> bool:
        """Check if oracle is manipulable."""
        target = oracle.get('target', '').lower()
        safe_patterns = ['chainlink', 'twap', 'median']
        return not any(pattern in target for pattern in safe_patterns)

    def _generate_exploit(self, pattern: Dict) -> Exploit:
        """Generate price manipulation exploit."""
        return Exploit(
            description="Flash loan price manipulation attack",
            attack_vector="Use flash loan to manipulate spot price and exploit vulnerable price query",
            profit_estimate=500000.0,
            transaction_sequence=[
                {"step": 1, "action": "Take flash loan"},
                {"step": 2, "action": "Perform large swap to manipulate price"},
                {"step": 3, "action": "Call vulnerable function with manipulated price"},
                {"step": 4, "action": "Reverse swap and repay flash loan"}
            ],
            proof_of_concept="""// 1. Flash loan
flashLoan(amount);
// 2. Manipulate price
pair.swap(largeAmount);
// 3. Exploit
vulnerableContract.vulnerableFunction();
// 4. Reverse and profit"""
        )
