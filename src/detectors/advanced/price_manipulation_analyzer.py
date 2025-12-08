# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional
from collections import defaultdict

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class PriceManipulationAnalyzer:
    """
    Production-grade price manipulation detector.
    Target accuracy: 70-80%
    
    Real-world impact: $2.47B stolen in H1 2025
    """

    def __init__(self):
        self.spot_price_queries: List[Dict] = []
        self.flash_loan_calls: List[Dict] = []
        self.dex_interactions: List[Dict] = []
        
        self.spot_price_methods = [
            'getamountout', 'getreserves', 'balanceof', 
            'getprice', 'currentprice'
        ]
        
        self.safe_methods = ['latestrounddata', 'consult', 'observe', 'gettwap']
        self.dex_protocols = ['uniswap', 'sushiswap', 'balancer', 'curve']

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_price_queries(symbolic_results)
        self._identify_flash_loans(symbolic_results)
        self._identify_dex_interactions(symbolic_results)
        
        # Spot price vulnerabilities
        for query in self.spot_price_queries:
            if self._is_vulnerable_spot_price(query):
                vuln = self._create_spot_price_vuln(query)
                vulnerabilities.append(vuln)
        
        # Flash loan manipulation
        if self.flash_loan_calls and self.spot_price_queries:
            vuln = self._create_flash_loan_vuln()
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_price_queries(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') != 'external_call':
                    continue
                
                method = op.get('method', '').lower()
                target = op.get('target', '').lower()
                
                is_spot = any(m in method for m in self.spot_price_methods)
                is_safe = any(m in method for m in self.safe_methods)
                
                if is_spot and not is_safe:
                    self.spot_price_queries.append({
                        'method': method,
                        'target': target,
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'dex': self._identify_dex(target)
                    })

    def _identify_flash_loans(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                method = op.get('method', '').lower()
                if 'flash' in method or 'borrow' in method:
                    self.flash_loan_calls.append(op)

    def _identify_dex_interactions(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                method = op.get('method', '').lower()
                target = op.get('target', '').lower()
                
                if 'swap' in method or any(dex in target for dex in self.dex_protocols):
                    self.dex_interactions.append(op)

    def _identify_dex(self, target: str) -> str:
        for dex in self.dex_protocols:
            if dex in target:
                return dex
        return 'unknown'

    def _is_vulnerable_spot_price(self, query: Dict) -> bool:
        # High risk: balance or reserve queries
        method = query['method']
        return 'reserve' in method or 'balance' in method or 'getamount' in method

    def _create_spot_price_vuln(self, query: Dict) -> Vulnerability:
        dex = query['dex'].title()
        
        poc = f"""// Spot Price Manipulation: {dex}
// Real-world: $2.47B losses in H1 2025

// 1. Flash loan large amount
flashLoan(1000000 ether);

// 2. Manipulate {dex} pool
{dex}.swap(largeAmount, 0, this, "");

// 3. Query manipulated price
uint price = victim.{query['method']}(); // Inflated!

// 4. Exploit (liquidate, borrow, etc)
victim.exploit(price);

// 5. Restore and profit
"""
        
        return Vulnerability(
            type=VulnerabilityType.PRICE_MANIPULATION,
            severity=Severity.CRITICAL,
            name=f"{dex} Spot Price Manipulation",
            description=f"Uses {query['method']} which is manipulatable via flash loans",
            location=SourceLocation(
                file="contract.sol",
                line_start=query.get('location', {}).get('line', 0),
                line_end=query.get('location', {}).get('line', 0),
                function=query['function']
            ),
            confidence=0.85,
            impact=f"Price manipulation. Pattern caused $2.47B losses. {dex} reserves manipulatable.",
            recommendation="Use TWAP oracle (Uniswap V3 observe()) or Chainlink instead of spot prices",
            exploit=Exploit(
                description=f"{dex} price manipulation",
                attack_vector="Flash loan → manipulate reserves → exploit",
                profit_estimate=500000.0,
                proof_of_concept=poc
            ),
            technical_details=query
        )

    def _create_flash_loan_vuln(self) -> Vulnerability:
        poc = """// Flash Loan + Price Manipulation
// Borrow → Manipulate DEX → Query Price → Exploit

function attack() {
    flashLoan(amount);
    // During loan: manipulate prices
    dex.swap(...); // Skew reserves
    uint price = getPrice(); // Query manipulated
    exploit(price); // Profit
    repay();
}
"""
        
        return Vulnerability(
            type=VulnerabilityType.PRICE_MANIPULATION,
            severity=Severity.CRITICAL,
            name="Flash Loan Price Manipulation Pattern",
            description=f"Flash loans with {len(self.spot_price_queries)} spot price queries",
            location=SourceLocation(file="contract.sol", line_start=0, line_end=0, function="multiple"),
            confidence=0.88,
            impact="Complete price manipulation via flash loans",
            recommendation="Use TWAP oracles, not spot prices",
            exploit=Exploit(
                description="Flash loan manipulation",
                attack_vector="Flash loan enables price manipulation",
                profit_estimate=1000000.0,
                proof_of_concept=poc
            )
        )
