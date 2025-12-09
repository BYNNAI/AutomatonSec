# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List
from collections import defaultdict

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class PriceManipulationAnalyzer:
    """
    Production-grade price manipulation detector.
    Real-world: $2.47B stolen in H1 2025, 80% of DeFi exploits
    Target accuracy: 70-80%
    """

    def __init__(self):
        self.price_queries: List[Dict] = []
        self.flash_loans: List[Dict] = []
        self.dex_interactions: List[Dict] = []
        
        self.spot_price_methods = [
            'getamountout', 'getamountin', 'getreserves', 'quote',
            'getprice', 'getspotprice', 'balanceof', 'reserve0', 'reserve1'
        ]
        self.safe_methods = ['latestrounddata', 'consult', 'observe', 'gettwap']
        self.dex_protocols = ['uniswap', 'sushiswap', 'balancer', 'curve', 'pancakeswap']

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_price_queries(symbolic_results)
        self._identify_flash_loans(symbolic_results)
        self._identify_dex_interactions(symbolic_results)
        
        vulnerabilities.extend(self._analyze_spot_price_usage())
        vulnerabilities.extend(self._analyze_flash_loan_attacks(symbolic_results))
        vulnerabilities.extend(self._check_twap_usage())
        
        return vulnerabilities

    def _identify_price_queries(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') != 'external_call':
                    continue
                method = op.get('method', '').lower()
                target = op.get('target', '').lower()
                
                if any(pm in method for pm in self.spot_price_methods):
                    self.price_queries.append({
                        'method': method, 'target': target,
                        'function': op.get('function'), 'location': op.get('location', {}),
                        'is_spot': not any(safe in method for safe in self.safe_methods),
                        'dex_type': next((dex for dex in self.dex_protocols if dex in target), 'unknown')
                    })

    def _identify_flash_loans(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'external_call':
                    method = op.get('method', '').lower()
                    if any(x in method for x in ['flashloan', 'flash', 'borrow']):
                        self.flash_loans.append({
                            'method': method, 'function': op.get('function'),
                            'location': op.get('location', {})
                        })

    def _identify_dex_interactions(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') != 'external_call':
                    continue
                method = op.get('method', '').lower()
                if any(x in method for x in ['swap', 'addliquidity', 'removeliquidity']):
                    self.dex_interactions.append({
                        'method': method, 'function': op.get('function')
                    })

    def _analyze_spot_price_usage(self) -> List[Vulnerability]:
        vulns = []
        for query in self.price_queries:
            if not query['is_spot']:
                continue
            
            confidence = 0.40 if 'reserve' in query['method'] else 0.25
            confidence += 0.20 if query['dex_type'] != 'unknown' else 0
            
            if confidence >= 0.45:
                poc = f"""// Spot Price Manipulation ({query['dex_type'].title()})
flashLender.flashLoan(amount);
{query['dex_type']}Pair.swap(amount, 0, address(this), "");
uint256 manipulated = victim.{query['method']}();
victim.exploit(manipulated);
{query['dex_type']}Pair.swap(0, amount, address(this), "");
"""
                vulns.append(Vulnerability(
                    type=VulnerabilityType.PRICE_MANIPULATION,
                    severity=Severity.CRITICAL,
                    name=f"{query['dex_type'].title()} Spot Price Manipulation",
                    description=f"Function {query['function']} uses spot price {query['method']}",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=query.get('location', {}).get('line', 0),
                        line_end=query.get('location', {}).get('line', 0),
                        function=query['function']
                    ),
                    confidence=confidence,
                    impact=f"Flash loan manipulation. $2.47B pattern (H1 2025). {query['dex_type']} reserves manipulable.",
                    recommendation="Use TWAP: Uniswap V3 observe(), Chainlink feeds, or 30+ min observation window.",
                    exploit=Exploit(
                        description=f"{query['dex_type']} price manipulation",
                        attack_vector="Flash loan → manipulate reserves → query price → exploit",
                        profit_estimate=500000.0,
                        proof_of_concept=poc
                    )
                ))
        return vulns

    def _analyze_flash_loan_attacks(self, symbolic_results: Dict) -> List[Vulnerability]:
        vulns = []
        for flash in self.flash_loans:
            func = flash['function']
            price_queries_in_func = [q for q in self.price_queries if q['function'] == func]
            dex_interactions_in_func = [d for d in self.dex_interactions if d['function'] == func]
            
            if price_queries_in_func and dex_interactions_in_func:
                vulns.append(Vulnerability(
                    type=VulnerabilityType.PRICE_MANIPULATION,
                    severity=Severity.CRITICAL,
                    name="Flash Loan Price Manipulation Pattern",
                    description=f"Function {func} combines flash loan + {len(dex_interactions_in_func)} DEX ops + {len(price_queries_in_func)} price queries",
                    location=SourceLocation(
                        file="contract.sol",
                        line_start=flash.get('location', {}).get('line', 0),
                        line_end=flash.get('location', {}).get('line', 0),
                        function=func
                    ),
                    confidence=0.92,
                    impact="Complete price manipulation capability during flash loan.",
                    recommendation="Use TWAP oracles, not spot prices during flash execution."
                ))
        return vulns

    def _check_twap_usage(self) -> List[Vulnerability]:
        vulns = []
        spot_count = sum(1 for q in self.price_queries if q['is_spot'])
        twap_count = sum(1 for q in self.price_queries if not q['is_spot'])
        
        if spot_count > 0 and twap_count == 0:
            vulns.append(Vulnerability(
                type=VulnerabilityType.PRICE_MANIPULATION,
                severity=Severity.CRITICAL,
                name="No TWAP Oracle Usage",
                description=f"Contract uses {spot_count} spot price queries, zero TWAP",
                location=SourceLocation(file="contract.sol", line_start=0, line_end=0),
                confidence=0.88,
                impact="All price queries vulnerable to flash loan manipulation.",
                recommendation="Replace spot with TWAP: Uniswap V3 observe() or Chainlink."
            ))
        return vulns
