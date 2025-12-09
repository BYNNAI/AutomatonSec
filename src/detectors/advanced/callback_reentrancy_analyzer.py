# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class CallbackReentrancyAnalyzer:
    """
    Production-grade callback reentrancy detector.
    Real-world: ERC721/ERC1155 callback exploits
    Target accuracy: 70-80%
    """

    def __init__(self):
        self.callback_triggers: List[Dict] = []
        self.state_changes: List[Dict] = []
        self.vulnerable_flows: List[Dict] = []
        
        # Known callback functions
        self.callback_functions = [
            'onerc721received', 'onerc1155received', 'onerc1155batchreceived',
            'tokenfallback', 'tokensreceived', 'receive', 'fallback'
        ]
        
        # Functions that trigger callbacks
        self.callback_triggers_methods = [
            'safetransfer', 'safetransferfrom', 'safemint',
            'mint', 'transfer', 'send'
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_callback_triggers(symbolic_results)
        self._identify_state_changes(symbolic_results)
        self._analyze_callback_flows(cfg, symbolic_results)
        
        for flow in self.vulnerable_flows:
            vuln = self._create_vulnerability(flow)
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_callback_triggers(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') != 'external_call':
                    continue
                
                method = op.get('method', '').lower()
                
                if any(trigger in method for trigger in self.callback_triggers_methods):
                    self.callback_triggers.append({
                        'method': method,
                        'target': op.get('target', ''),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'is_safe_transfer': 'safe' in method
                    })

    def _identify_state_changes(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'sstore':
                    self.state_changes.append({
                        'variable': op.get('variable', 'unknown'),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'operation_index': op.get('index', 0)
                    })

    def _analyze_callback_flows(self, cfg: Dict, symbolic_results: Dict) -> None:
        """
        Analyze if state is updated before or after callback-triggering calls.
        """
        for trigger in self.callback_triggers:
            func_name = trigger['function']
            
            # Find state changes in same function
            func_state_changes = [
                sc for sc in self.state_changes 
                if sc['function'] == func_name
            ]
            
            if not func_state_changes:
                continue
            
            # Analyze order: state change vs callback trigger
            vulnerable = self._check_cei_pattern(trigger, func_state_changes, symbolic_results)
            
            if vulnerable:
                self.vulnerable_flows.append({
                    'trigger': trigger,
                    'state_changes': func_state_changes,
                    'pattern': vulnerable
                })

    def _check_cei_pattern(self, trigger: Dict, state_changes: List[Dict],
                          symbolic_results: Dict) -> str:
        """
        Check if Checks-Effects-Interactions pattern is violated.
        """
        func_name = trigger['function']
        
        # Find operation sequence
        for path in symbolic_results.get('paths', []):
            if path.get('function') != func_name:
                continue
            
            ops = path.get('operations', [])
            
            # Find indices
            callback_index = None
            state_change_indices = []
            
            for i, op in enumerate(ops):
                if op.get('method') == trigger['method']:
                    callback_index = i
                
                if op.get('type') == 'sstore':
                    state_change_indices.append(i)
            
            if callback_index is None:
                continue
            
            # Check if any state changes happen AFTER callback
            state_after_callback = any(idx > callback_index for idx in state_change_indices)
            
            if state_after_callback:
                return 'state_after_callback'  # Vulnerable!
        
        return None

    def _create_vulnerability(self, flow: Dict) -> Vulnerability:
        trigger = flow['trigger']
        method = trigger['method']
        
        # Determine token standard
        if '721' in method:
            standard = "ERC721"
            callback = "onERC721Received"
        elif '1155' in method:
            standard = "ERC1155"
            callback = "onERC1155Received"
        else:
            standard = "Token"
            callback = "callback function"
        
        poc = f"""// Callback Reentrancy Attack ({standard})

// Vulnerable contract:
function vulnerableFunction() public {{
    // Step 1: Call {method} - triggers callback to attacker
    nft.{method}(attacker, tokenId);
    
    // Step 2: State update AFTER callback (WRONG ORDER!)
    userBalances[msg.sender] -= amount;
    // But callback already executed with OLD state!
}}

// Attacker's malicious contract:
function {callback}(...) external returns (bytes4) {{
    // Called DURING {method}, before state update
    // State still shows old balance!
    
    // Reenter and exploit stale state
    victim.anotherFunction();  // Uses old userBalances value
    
    return this.{callback}.selector;
}}

// Attack flow:
// 1. Attacker calls vulnerableFunction()
// 2. Contract calls {method}() to attacker
// 3. {callback}() executes with OLD state
// 4. Attacker reenters, exploits stale state
// 5. Original function finally updates state (too late!)

// Fix - Checks-Effects-Interactions:
function safe() public {{
    // Update state BEFORE external call
    userBalances[msg.sender] -= amount;
    
    // Then do external call
    nft.{method}(attacker, tokenId);
}}
"""
        
        return Vulnerability(
            type=VulnerabilityType.CALLBACK_REENTRANCY,
            severity=Severity.HIGH,
            name=f"{standard} Callback Reentrancy",
            description=f"Function {trigger['function']} updates state AFTER calling {method}, "
                       f"allowing reentrancy through {callback} callback",
            location=SourceLocation(
                file="contract.sol",
                line_start=trigger.get('location', {}).get('line', 0),
                line_end=trigger.get('location', {}).get('line', 0),
                function=trigger['function']
            ),
            confidence=0.78,
            impact=f"Reentrancy during {standard} transfer callback. Attacker can manipulate state before updates complete. "
                   f"Common with safe{standard} functions that trigger {callback}.",
            recommendation="Apply Checks-Effects-Interactions pattern: "
                         "1) Update all state BEFORE external calls, "
                         "2) Add reentrancy guard (OpenZeppelin ReentrancyGuard), "
                         "3) Use pull-over-push payment pattern.",
            exploit=Exploit(
                description=f"{standard} callback reentrancy",
                attack_vector=f"Trigger {method} → reenter via {callback} → exploit stale state",
                profit_estimate=150000.0,
                proof_of_concept=poc
            ),
            technical_details=flow
        )
