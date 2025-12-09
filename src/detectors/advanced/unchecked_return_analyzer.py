# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class UncheckedReturnAnalyzer:
    """
    Production-grade unchecked return value detector.
    Target accuracy: 80-90%
    
    Detects silent failures in:
    - ERC20 transfers
    - External calls
    - Low-level calls
    """

    def __init__(self):
        self.unchecked_calls: List[Dict] = []
        
        # High-risk methods that MUST check return values
        self.critical_methods = [
            'transfer', 'transferfrom', 'approve',
            'call', 'delegatecall', 'staticcall',
            'send'
        ]
        
        # ERC20 tokens known to return false instead of reverting
        self.problematic_tokens = [
            'usdt', 'bnb', 'zrx', 'omg'
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Phase 1: Find all external calls
        external_calls = self._find_external_calls(symbolic_results)
        
        # Phase 2: Check which calls don't validate return values
        for call in external_calls:
            if self._is_unchecked(call, symbolic_results):
                vuln = self._create_vulnerability(call)
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_external_calls(self, symbolic_results: Dict) -> List[Dict]:
        calls = []
        
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') not in ['external_call', 'call']:
                    continue
                
                method = op.get('method', '').lower()
                
                # Check if this is a critical method
                if any(critical in method for critical in self.critical_methods):
                    calls.append({
                        'method': method,
                        'target': op.get('target', ''),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'returns_to': op.get('returns_to'),
                        'operation_id': op.get('id')
                    })
        
        return calls

    def _is_unchecked(self, call: Dict, symbolic_results: Dict) -> bool:
        """
        Determine if return value is checked.
        """
        operation_id = call.get('operation_id')
        returns_to = call.get('returns_to')
        func = call.get('function')
        
        # If no return value captured, it's unchecked
        if not returns_to:
            return True
        
        # Check if return value is used in a require/assert/if statement
        for path in symbolic_results.get('paths', []):
            if path.get('function') != func:
                continue
            
            found_call = False
            for op in path.get('operations', []):
                # Find our call
                if op.get('id') == operation_id:
                    found_call = True
                    continue
                
                # After the call, check if return value is validated
                if found_call:
                    op_type = op.get('type', '')
                    expr = op.get('expression', '').lower()
                    condition = op.get('condition', '').lower()
                    
                    # Check for require/assert/revert
                    if op_type in ['require', 'assert', 'revert']:
                        if returns_to in expr or returns_to in condition:
                            return False  # Return value IS checked
                    
                    # Check for if statement
                    if op_type == 'if':
                        if returns_to in condition:
                            return False  # Return value IS checked
        
        # Return value not validated
        return True

    def _create_vulnerability(self, call: Dict) -> Vulnerability:
        method = call['method']
        
        # Determine severity based on method
        if 'transfer' in method or 'approve' in method:
            severity = Severity.HIGH
            impact_desc = "Silent ERC20 transfer failure. Funds may be lost without reverting."
            profit_est = 100000.0
        elif 'call' in method or 'delegatecall' in method:
            severity = Severity.CRITICAL
            impact_desc = "Silent call failure. Critical operations may fail without detection."
            profit_est = 500000.0
        else:
            severity = Severity.MEDIUM
            impact_desc = "Unchecked return value may lead to unexpected behavior."
            profit_est = 50000.0
        
        poc = f"""// Unchecked Return Value: {method}
// Real-world: Multiple fund losses

// Vulnerable code:
token.{method}(recipient, amount);
// If transfer fails, contract continues as if it succeeded!

// Attack scenario for ERC20:
// 1. Attacker uses non-reverting token (USDT, ZRX)
// 2. Transfer fails (insufficient balance, frozen account)
// 3. Contract doesn't detect failure
// 4. Contract updates state as if transfer succeeded
// 5. Attacker exploits incorrect state

// Example exploit:
function withdraw() {{
    token.transfer(msg.sender, balance); // Unchecked!
    balance[msg.sender] = 0; // State updated even if transfer failed
    // Attacker got free balance reset without receiving tokens
}}

// Fix:
require(token.{method}(recipient, amount), "Transfer failed");
// OR use SafeERC20:
SafeERC20.safeTransfer(token, recipient, amount);
"""
        
        return Vulnerability(
            type=VulnerabilityType.UNCHECKED_RETURN,
            severity=severity,
            name=f"Unchecked {method.title()} Return Value",
            description=f"Function {call['function']} calls {method} without checking return value. "
                       f"Some ERC20 tokens (USDT, ZRX) return false on failure instead of reverting.",
            location=SourceLocation(
                file="contract.sol",
                line_start=call.get('location', {}).get('line', 0),
                line_end=call.get('location', {}).get('line', 0),
                function=call['function']
            ),
            confidence=0.88,
            impact=impact_desc + f" Affects {len(self.problematic_tokens)} common tokens that don't revert on failure.",
            recommendation=f"Add return value check: require({method}(...), \"Failed\"); "
                         f"OR use OpenZeppelin SafeERC20 library for token operations.",
            exploit=Exploit(
                description=f"Unchecked {method} exploitation",
                attack_vector="Failed operation doesn't revert, contract continues with incorrect state",
                profit_estimate=profit_est,
                transaction_sequence=[
                    {"step": 1, "action": f"Trigger {method} call that will fail"},
                    {"step": 2, "action": "Call fails but returns false (no revert)"},
                    {"step": 3, "action": "Contract updates state as if call succeeded"},
                    {"step": 4, "action": "Exploit incorrect contract state for profit"}
                ],
                proof_of_concept=poc
            ),
            technical_details=call
        )
