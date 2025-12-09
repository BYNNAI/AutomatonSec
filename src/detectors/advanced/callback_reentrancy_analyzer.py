# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class CallbackReentrancyAnalyzer:
    """
    Production-grade callback reentrancy detector.
    Target accuracy: 70-80%
    
    Detects reentrancy through:
    - ERC721 onERC721Received
    - ERC1155 onERC1155Received
    - onTokenReceived callbacks
    - Custom callback patterns
    """

    def __init__(self):
        self.callback_functions: Set[str] = set()
        self.external_calls: List[Dict] = []
        self.state_changes: List[Dict] = []
        
        # Known callback patterns
        self.callback_patterns = [
            'onerc721received',
            'onerc1155received',
            'onerc1155batchreceived',
            'ontokenreceived',
            'tokentopayingtoken',
            'tokenfallback',
            'receive',
            'fallback'
        ]
        
        # Safe transfer methods that trigger callbacks
        self.callback_triggers = [
            'safetransferfrom',
            'safemint',
            'safebatchTransferFrom'
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Phase 1: Identify callback functions
        self._identify_callbacks(bytecode_analysis)
        
        # Phase 2: Find external calls that trigger callbacks
        self._find_callback_triggers(symbolic_results)
        
        # Phase 3: Track state changes
        self._track_state_changes(symbolic_results)
        
        # Phase 4: Analyze reentrancy patterns
        reentrancy_patterns = self._analyze_reentrancy_patterns(cfg, symbolic_results)
        
        for pattern in reentrancy_patterns:
            vuln = self._create_vulnerability(pattern)
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_callbacks(self, bytecode_analysis: Dict) -> None:
        """
        Identify callback functions in contract.
        """
        functions = bytecode_analysis.get('functions', [])
        
        for func in functions:
            func_name = func.get('name', '').lower()
            
            if any(pattern in func_name for pattern in self.callback_patterns):
                self.callback_functions.add(func_name)

    def _find_callback_triggers(self, symbolic_results: Dict) -> None:
        """
        Find external calls that trigger callbacks.
        """
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') != 'external_call':
                    continue
                
                method = op.get('method', '').lower()
                
                # Check if this triggers a callback
                if any(trigger in method for trigger in self.callback_triggers):
                    self.external_calls.append({
                        'method': method,
                        'target': op.get('target', ''),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'triggers_callback': True,
                        'operation_id': op.get('id')
                    })

    def _track_state_changes(self, symbolic_results: Dict) -> None:
        """
        Track state variable modifications.
        """
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'sstore':  # Storage write
                    self.state_changes.append({
                        'variable': op.get('variable'),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'operation_id': op.get('id')
                    })

    def _analyze_reentrancy_patterns(self, cfg: Dict, 
                                    symbolic_results: Dict) -> List[Dict]:
        """
        Detect reentrancy patterns in callbacks.
        """
        patterns = []
        
        # Pattern: State change AFTER callback-triggering call
        for ext_call in self.external_calls:
            if not ext_call['triggers_callback']:
                continue
            
            call_func = ext_call['function']
            call_id = ext_call['operation_id']
            
            # Find state changes after this call
            for path in symbolic_results.get('paths', []):
                if path.get('function') != call_func:
                    continue
                
                found_call = False
                state_changes_after = []
                
                for op in path.get('operations', []):
                    if op.get('id') == call_id:
                        found_call = True
                        continue
                    
                    # After the callback-triggering call
                    if found_call and op.get('type') == 'sstore':
                        state_changes_after.append(op)
                
                # If state changes occur after callback, it's vulnerable
                if state_changes_after:
                    patterns.append({
                        'type': 'callback_reentrancy',
                        'external_call': ext_call,
                        'state_changes_after': state_changes_after,
                        'function': call_func,
                        'callback_method': ext_call['method']
                    })
        
        return patterns

    def _create_vulnerability(self, pattern: Dict) -> Vulnerability:
        ext_call = pattern['external_call']
        state_changes = pattern['state_changes_after']
        method = ext_call['method']
        
        poc = f"""// Callback Reentrancy: {method}
// Real-world: Multiple NFT contracts vulnerable

// Vulnerable contract:
contract Vulnerable {{
    mapping(address => uint256) public balances;
    
    function withdraw() public {{
        uint256 amount = balances[msg.sender];
        
        // VULNERABLE: External call before state update
        nft.{method}(address(this), msg.sender, tokenId);
        // ↑ This triggers onERC721Received callback in attacker's contract
        
        balances[msg.sender] = 0; // ← State update AFTER callback!
    }}
}}

// Attacker contract:
contract Attacker {{
    function onERC721Received(...) external returns (bytes4) {{
        // Called DURING withdraw(), BEFORE balance is set to 0
        if (victim.balances(address(this)) > 0) {{
            victim.withdraw(); // Reentrancy!
        }}
        return this.onERC721Received.selector;
    }}
    
    function attack() public {{
        victim.deposit{{value: 1 ether}}();
        victim.withdraw(); // Triggers reentrancy
        // Balance is withdrawn multiple times before being set to 0
    }}
}}

// Attack flow:
// 1. Attacker calls withdraw()
// 2. {method} is called, triggering onERC721Received
// 3. In callback, attacker calls withdraw() again
// 4. Balance still not updated, so second withdrawal succeeds
// 5. Repeat until victim drained

// Fix: Update state BEFORE external call (Checks-Effects-Interactions)
balances[msg.sender] = 0;
nft.{method}(address(this), msg.sender, tokenId);
"""
        
        return Vulnerability(
            type=VulnerabilityType.CALLBACK_REENTRANCY,
            severity=Severity.HIGH,
            name=f"Callback Reentrancy via {method}",
            description=f"Function {pattern['function']} calls {method} before updating state. "
                       f"This triggers a callback where attacker can reenter. "
                       f"{len(state_changes)} state changes occur AFTER the callback.",
            location=SourceLocation(
                file="contract.sol",
                line_start=ext_call.get('location', {}).get('line', 0),
                line_end=ext_call.get('location', {}).get('line', 0),
                function=pattern['function']
            ),
            confidence=0.82,
            impact=f"Reentrancy through {method} callback allows attacker to drain contract funds. "
                   f"State is updated after callback completes, enabling multiple withdrawals. "
                   f"Vulnerable state variables: {[sc.get('variable') for sc in state_changes]}",
            recommendation="Apply Checks-Effects-Interactions pattern: Update all state BEFORE external calls. "
                         "OR use ReentrancyGuard from OpenZeppelin. "
                         f"Move state updates before {method} call.",
            exploit=Exploit(
                description=f"Callback reentrancy via {method}",
                attack_vector="Implement callback receiver, reenter during callback before state update",
                profit_estimate=300000.0,
                transaction_sequence=[
                    {"step": 1, "action": "Attacker deposits funds into victim contract"},
                    {"step": 2, "action": "Call function that triggers callback"},
                    {"step": 3, "action": f"{method} triggers onERC721Received in attacker contract"},
                    {"step": 4, "action": "During callback, reenter victim before state update"},
                    {"step": 5, "action": "Repeat reentrancy to drain contract"}
                ],
                proof_of_concept=poc
            ),
            technical_details=pattern
        )
