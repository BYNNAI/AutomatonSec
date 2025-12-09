# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class UncheckedReturnAnalyzer:
    """
    Production-grade unchecked return value detector.
    Real-world: Multiple protocols, silent ERC20 failures
    Target accuracy: 80-90%
    """

    def __init__(self):
        self.external_calls: List[Dict] = []
        self.unchecked_calls: List[Dict] = []
        
        # Critical functions that must be checked
        self.critical_functions = [
            'transfer', 'transferfrom', 'approve',
            'send', 'call', 'delegatecall',
            'mint', 'burn', 'withdraw', 'deposit'
        ]
        
        # ERC20 tokens known for non-reverting failures
        self.known_noncompliant = ['usdt', 'bnb', 'omg', 'zrx']

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_external_calls(symbolic_results)
        self._identify_unchecked_returns(symbolic_results, cfg)
        
        for unchecked in self.unchecked_calls:
            vuln = self._create_vulnerability(unchecked)
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_external_calls(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') in ['external_call', 'call', 'delegatecall']:
                    method = op.get('method', '').lower()
                    
                    self.external_calls.append({
                        'method': method,
                        'target': op.get('target', ''),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'returns': op.get('returns', False),
                        'return_checked': op.get('return_checked', False),
                        'is_critical': any(crit in method for crit in self.critical_functions)
                    })

    def _identify_unchecked_returns(self, symbolic_results: Dict, cfg: Dict) -> None:
        for call in self.external_calls:
            if not call['is_critical']:
                continue
            
            # Check if return value is validated
            is_checked = self._check_return_validation(call, symbolic_results, cfg)
            
            if not is_checked:
                self.unchecked_calls.append(call)

    def _check_return_validation(self, call: Dict, symbolic_results: Dict, cfg: Dict) -> bool:
        """
        Check if return value is properly validated.
        """
        func_name = call['function']
        
        # Look for checks after the call
        for path in symbolic_results.get('paths', []):
            if path.get('function') != func_name:
                continue
            
            found_call = False
            for i, op in enumerate(path.get('operations', [])):
                # Find the external call
                if op.get('method') == call['method']:
                    found_call = True
                    continue
                
                # After finding call, look for require/revert checking return
                if found_call and i < len(path['operations']) - 1:
                    next_ops = path['operations'][i:i+3]  # Check next 3 operations
                    
                    for next_op in next_ops:
                        op_type = next_op.get('type', '').lower()
                        condition = next_op.get('condition', '').lower()
                        
                        # Check for require/assert/revert on return value
                        if op_type in ['require', 'assert', 'revert']:
                            if any(x in condition for x in ['success', 'return', 'result']):
                                return True
                    
                    # If we've checked next few ops and found nothing, it's unchecked
                    break
        
        return False

    def _create_vulnerability(self, call: Dict) -> Vulnerability:
        method = call['method']
        target = call['target']
        
        # Determine severity based on function type
        if method in ['transfer', 'transferfrom']:
            severity = Severity.HIGH
            impact = "Silent ERC20 transfer failure. Funds appear sent but aren't. Accounting corruption."
            example = "USDT"
        elif method in ['approve']:
            severity = Severity.MEDIUM
            impact = "Silent approval failure. User thinks allowance set but isn't. Subsequent operations fail."
            example = "Some ERC20s"
        elif 'call' in method:
            severity = Severity.CRITICAL
            impact = "Silent low-level call failure. Ether/data not sent. Critical logic bypass."
            example = "address.call"
        else:
            severity = Severity.HIGH
            impact = f"Silent {method} failure. Operation may fail without contract awareness."
            example = method
        
        poc = f"""// Unchecked Return Value Attack

// Vulnerable code:
token.{method}(recipient, amount);  // Return value ignored!
// If transfer fails (e.g., USDT), code continues
balances[user] -= amount;  // Balance updated even though transfer failed
// Result: Accounting corruption, fund loss

// Attack scenario:
// 1. Attacker uses non-compliant token ({example})
// 2. {method}() fails silently (no revert)
// 3. Contract updates state assuming success
// 4. Attacker gains credit without actual transfer

// Fix:
bool success = token.{method}(recipient, amount);
require(success, "Transfer failed");

// Or use SafeERC20:
using SafeERC20 for IERC20;
token.safeTransfer(recipient, amount);  // Reverts on failure
"""
        
        return Vulnerability(
            type=VulnerabilityType.UNCHECKED_RETURN,
            severity=severity,
            name=f"Unchecked {method.title()} Return Value",
            description=f"Function {call['function']} calls {method} without checking return value",
            location=SourceLocation(
                file="contract.sol",
                line_start=call.get('location', {}).get('line', 0),
                line_end=call.get('location', {}).get('line', 0),
                function=call['function']
            ),
            confidence=0.85,
            impact=impact + f" Common with USDT, BNB, and other non-standard ERC20 tokens.",
            recommendation=f"Check return value: require({method}(...), 'Failed'); or use OpenZeppelin SafeERC20 library.",
            exploit=Exploit(
                description=f"Unchecked {method} exploitation",
                attack_vector=f"Use non-compliant token → {method} fails silently → accounting corruption",
                profit_estimate=100000.0,
                proof_of_concept=poc
            ),
            technical_details=call
        )
