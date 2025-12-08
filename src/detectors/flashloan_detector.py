# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)


class FlashLoanDetector:
    """
    Detects flash loan attack vectors and MEV exploitation opportunities.
    Analyzes price manipulation, oracle attacks, and arbitrage vulnerabilities.
    """
    
    DEFI_PATTERNS = {
        'UNISWAP_SWAP': ['0x022c0d9f', '0x18cbafe5'],
        'BALANCER_SWAP': ['0x52bbbe29'],
        'AAVE_FLASHLOAN': ['0xab9c4b5d', '0xd9627aa4'],
        'COMPOUND_BORROW': ['0xc5ebeaec'],
        'PRICE_ORACLE': ['0x50d25bcd', '0x1a686502']
    }
    
    def __init__(self):
        self.vulnerabilities = []
        
    def detect(self, bytecode_analysis: Dict, cfg: Dict,
               taint_results: Dict, symbolic_results: Dict,
               fuzzing_results: Dict) -> List[Dict]:
        """
        Detect flash loan and DeFi-specific vulnerabilities.
        """
        logger.info("Detecting flash loan vulnerabilities")
        
        self.vulnerabilities = []
        
        function_selectors = bytecode_analysis.get("function_selectors", {})
        external_calls = bytecode_analysis.get("external_calls", [])
        
        self._detect_flashloan_pattern(function_selectors, external_calls)
        
        self._detect_price_manipulation(external_calls, symbolic_results)
        
        self._detect_oracle_dependency(function_selectors, taint_results)
        
        self._detect_mev_opportunities(external_calls, fuzzing_results)
        
        logger.info(f"Found {len(self.vulnerabilities)} flash loan vulnerabilities")
        return self.vulnerabilities
    
    def _detect_flashloan_pattern(self, function_selectors: Dict,
                                  external_calls: List[Dict]):
        """
        Detect potential flash loan attack patterns.
        """
        has_flashloan_interface = any(
            selector in self.DEFI_PATTERNS['AAVE_FLASHLOAN']
            for selector in function_selectors.keys()
        )
        
        has_swap_operations = any(
            selector in self.DEFI_PATTERNS['UNISWAP_SWAP'] or
            selector in self.DEFI_PATTERNS['BALANCER_SWAP']
            for selector in function_selectors.keys()
        )
        
        if has_flashloan_interface and has_swap_operations:
            self.vulnerabilities.append({
                "type": "FLASHLOAN_ATTACK_VECTOR",
                "severity": "CRITICAL",
                "description": "Contract implements flash loan callback with DEX swap operations",
                "patterns_detected": ["flashloan_callback", "dex_swap"],
                "confidence": 0.75,
                "exploit_potential": "VERY_HIGH",
                "attack_scenario": "Attacker can manipulate prices using flash loans and profit from swaps"
            })
        
        if len(external_calls) >= 3:
            call_sequence = [call["call_type"] for call in external_calls]
            if call_sequence.count('CALL') >= 2:
                self.vulnerabilities.append({
                    "type": "COMPLEX_FLASHLOAN_CHAIN",
                    "severity": "HIGH",
                    "description": f"Multiple external calls ({len(external_calls)}) suggest complex flash loan exploitation",
                    "call_count": len(external_calls),
                    "confidence": 0.65,
                    "exploit_potential": "HIGH"
                })
    
    def _detect_price_manipulation(self, external_calls: List[Dict],
                                   symbolic_results: Dict):
        """
        Detect price manipulation vulnerabilities.
        """
        explored_paths = symbolic_results.get("explored_paths", [])
        
        for path in explored_paths:
            final_state = path.get("final_state", {})
            external_call_count = final_state.get("external_calls", 0)
            
            if external_call_count >= 2:
                storage_writes = final_state.get("storage_writes", 0)
                
                if storage_writes > 0:
                    self.vulnerabilities.append({
                        "type": "PRICE_MANIPULATION",
                        "severity": "HIGH",
                        "description": "State updates between multiple external calls enable price manipulation",
                        "path_id": path.get("path_id"),
                        "external_calls": external_call_count,
                        "confidence": 0.70,
                        "exploit_potential": "HIGH"
                    })
    
    def _detect_oracle_dependency(self, function_selectors: Dict,
                                  taint_results: Dict):
        """
        Detect vulnerable oracle dependencies.
        """
        has_oracle_call = any(
            selector in self.DEFI_PATTERNS['PRICE_ORACLE']
            for selector in function_selectors.keys()
        )
        
        if has_oracle_call:
            taint_flows = taint_results.get("taint_flows", [])
            
            critical_flows = [
                flow for flow in taint_flows
                if flow.get("severity") in ["CRITICAL", "HIGH"]
            ]
            
            if critical_flows:
                self.vulnerabilities.append({
                    "type": "ORACLE_MANIPULATION",
                    "severity": "CRITICAL",
                    "description": "Oracle price data flows to critical operations without validation",
                    "taint_flow_count": len(critical_flows),
                    "confidence": 0.80,
                    "exploit_potential": "VERY_HIGH",
                    "remediation": "Implement TWAP or multi-oracle price validation"
                })
    
    def _detect_mev_opportunities(self, external_calls: List[Dict],
                                  fuzzing_results: Dict):
        """
        Detect MEV (Maximal Extractable Value) opportunities.
        """
        if len(external_calls) >= 2:
            profit_paths = fuzzing_results.get("profit_paths", [])
            
            if profit_paths:
                max_profit = max([p.get("profit_estimate", 0) for p in profit_paths], default=0)
                
                if max_profit > 0:
                    self.vulnerabilities.append({
                        "type": "MEV_OPPORTUNITY",
                        "severity": "MEDIUM",
                        "description": "Contract enables MEV extraction through transaction ordering",
                        "max_profit_estimate": max_profit,
                        "profitable_path_count": len(profit_paths),
                        "confidence": 0.60,
                        "exploit_potential": "MEDIUM"
                    })
