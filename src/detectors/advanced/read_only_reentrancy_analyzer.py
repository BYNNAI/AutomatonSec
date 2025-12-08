# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class ReadOnlyReentrancyAnalyzer:
    """
    Production-grade read-only reentrancy detector.
    
    Detects view/pure function manipulation during external calls:
    - Curve/Balancer LP token price queries during callbacks
    - State inconsistency in view functions during reentrancy
    - Oracle manipulation through callback execution
    
    Real-world example: Sturdy Finance ($800K loss, June 2023)
    Attack: Remove liquidity → receive callback → query inflated LP price
    """

    def __init__(self):
        self.view_functions: Dict[str, Dict] = {}
        self.external_calls: List[Dict] = []
        self.callback_functions: Set[str] = set()
        self.state_reads: Dict[str, List[str]] = defaultdict(list)
        self.lp_token_queries: List[Dict] = []
        
        # Known vulnerable patterns
        self.vulnerable_lp_protocols = [
            'balancer', 'curve', 'convex', 'aura'
        ]
        
        self.price_query_functions = [
            'balanceof', 'getrate', 'getprice', 'exchangerate',
            'totalassets', 'gettokensperlptoken', 'getspotprice'
        ]
        
        # Callback function patterns
        self.callback_patterns = [
            'receive', 'fallback', 'onerc721received', 'onerc1155received',
            'tokentopayingtoken', 'transfercallback'
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Deep analysis for read-only reentrancy vulnerabilities.
        """
        vulnerabilities = []
        
        # Phase 1: Identify all view/pure functions
        self._identify_view_functions(bytecode_analysis)
        
        # Phase 2: Map external calls and potential callbacks
        self._map_external_calls(cfg, symbolic_results)
        
        # Phase 3: Track state reads in view functions
        self._analyze_state_reads(symbolic_results)
        
        # Phase 4: Detect LP token price queries
        self._detect_lp_queries(bytecode_analysis, symbolic_results)
        
        # Phase 5: Find vulnerable callback flows
        vulnerable_patterns = self._find_vulnerable_patterns(cfg, symbolic_results)
        
        for pattern in vulnerable_patterns:
            vuln = self._create_vulnerability(pattern, bytecode_analysis)
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_view_functions(self, bytecode_analysis: Dict) -> None:
        """
        Identify and catalog all view/pure functions.
        """
        functions = bytecode_analysis.get('functions', [])
        
        for func in functions:
            mutability = func.get('stateMutability', '').lower()
            
            if mutability in ['view', 'pure']:
                func_name = func.get('name')
                self.view_functions[func_name] = {
                    'name': func_name,
                    'signature': func.get('signature'),
                    'mutability': mutability,
                    'visibility': func.get('visibility'),
                    'returns': func.get('returns', []),
                    'calls_external': False,
                    'reads_balance': False,
                    'queries_price': False
                }

    def _map_external_calls(self, cfg: Dict, symbolic_results: Dict) -> None:
        """
        Map all external calls and identify callback entry points.
        """
        # Analyze CFG for external calls
        for node in cfg.get('nodes', []):
            if node.get('type') == 'external_call':
                call_info = {
                    'caller_function': node.get('function'),
                    'target': node.get('target', '').lower(),
                    'method': node.get('method', '').lower(),
                    'node_id': node.get('id'),
                    'state_before': node.get('state_before', {}),
                    'potential_callback': self._is_potential_callback(node)
                }
                
                self.external_calls.append(call_info)
                
                # Identify callback functions
                if call_info['potential_callback']:
                    # Look for callback patterns after this call
                    callback_funcs = self._find_callbacks_after_call(node, cfg)
                    self.callback_functions.update(callback_funcs)

    def _is_potential_callback(self, node: Dict) -> bool:
        """
        Determine if external call can trigger callbacks.
        """
        method = node.get('method', '').lower()
        target = node.get('target', '').lower()
        
        # Known callback-triggering patterns
        callback_triggers = [
            'transfer',           # ETH transfers
            'safetransfer',      # Safe token transfers
            'exit',              # Balancer pool exit
            'remove_liquidity',  # Curve remove liquidity
            'withdraw',          # LP token withdrawal
            'mint',              # NFT minting
            'burn'               # Token burning
        ]
        
        return any(trigger in method for trigger in callback_triggers)

    def _find_callbacks_after_call(self, call_node: Dict, cfg: Dict) -> Set[str]:
        """
        Find functions that could be called back after external call.
        """
        callbacks = set()
        node_id = call_node.get('id')
        
        # Look for edges from this node
        for edge in cfg.get('edges', []):
            if edge.get('from') == node_id:
                target_node = self._get_node_by_id(cfg, edge.get('to'))
                if target_node:
                    func_name = target_node.get('function', '').lower()
                    
                    # Check if it's a callback pattern
                    if any(pattern in func_name for pattern in self.callback_patterns):
                        callbacks.add(func_name)
        
        return callbacks

    def _get_node_by_id(self, cfg: Dict, node_id: int) -> Optional[Dict]:
        """
        Get CFG node by ID.
        """
        for node in cfg.get('nodes', []):
            if node.get('id') == node_id:
                return node
        return None

    def _analyze_state_reads(self, symbolic_results: Dict) -> None:
        """
        Track which state variables are read by view functions.
        """
        for path in symbolic_results.get('paths', []):
            func_name = path.get('function')
            
            if func_name not in self.view_functions:
                continue
            
            for op in path.get('operations', []):
                if op.get('type') == 'sload':  # Storage load
                    var_name = op.get('variable', 'unknown')
                    self.state_reads[func_name].append(var_name)
                    
                    # Mark function characteristics
                    if 'balance' in var_name.lower():
                        self.view_functions[func_name]['reads_balance'] = True

    def _detect_lp_queries(self, bytecode_analysis: Dict, symbolic_results: Dict) -> None:
        """
        Detect LP token price/balance queries.
        """
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'external_call':
                    target = op.get('target', '').lower()
                    method = op.get('method', '').lower()
                    
                    # Check if querying LP token price
                    is_lp_protocol = any(proto in target for proto in self.vulnerable_lp_protocols)
                    is_price_query = any(query in method for query in self.price_query_functions)
                    
                    if is_lp_protocol and is_price_query:
                        self.lp_token_queries.append({
                            'function': op.get('function'),
                            'target': target,
                            'method': method,
                            'protocol': self._identify_protocol(target),
                            'location': op.get('location')
                        })
                        
                        # Mark view function if applicable
                        func_name = op.get('function')
                        if func_name in self.view_functions:
                            self.view_functions[func_name]['queries_price'] = True

    def _identify_protocol(self, target: str) -> str:
        """
        Identify which LP protocol is being queried.
        """
        for proto in self.vulnerable_lp_protocols:
            if proto in target:
                return proto
        return 'unknown'

    def _find_vulnerable_patterns(self, cfg: Dict, symbolic_results: Dict) -> List[Dict]:
        """
        Identify vulnerable read-only reentrancy patterns.
        """
        vulnerable = []
        
        # Pattern 1: External call → callback → view function queries stale state
        for ext_call in self.external_calls:
            if not ext_call['potential_callback']:
                continue
            
            caller_func = ext_call['caller_function']
            
            # Find view functions called after this external call
            view_calls_after = self._find_view_calls_after_external(
                ext_call, cfg, symbolic_results
            )
            
            for view_call in view_calls_after:
                # Check if view function reads state that may be stale
                if self._has_stale_state_risk(view_call, ext_call):
                    vulnerable.append({
                        'type': 'callback_view_manipulation',
                        'external_call': ext_call,
                        'view_function': view_call,
                        'confidence': self._calculate_confidence(ext_call, view_call),
                        'attack_vector': self._describe_attack_vector(ext_call, view_call)
                    })
        
        # Pattern 2: LP token price query during liquidity removal callback
        for lp_query in self.lp_token_queries:
            query_func = lp_query['function']
            
            # Check if this query happens during a callback
            if query_func in self.callback_functions or self._called_from_callback(query_func, cfg):
                vulnerable.append({
                    'type': 'lp_price_manipulation',
                    'lp_query': lp_query,
                    'confidence': 0.90,  # High confidence for known pattern
                    'attack_vector': self._describe_lp_attack(lp_query)
                })
        
        return vulnerable

    def _find_view_calls_after_external(self, ext_call: Dict, cfg: Dict, 
                                       symbolic_results: Dict) -> List[Dict]:
        """
        Find view function calls that occur after external call.
        """
        view_calls = []
        caller_func = ext_call['caller_function']
        
        # Search in symbolic execution paths
        for path in symbolic_results.get('paths', []):
            if path.get('function') != caller_func:
                continue
            
            found_external = False
            for op in path.get('operations', []):
                # Mark when we find the external call
                if op.get('type') == 'external_call' and op.get('target') == ext_call['target']:
                    found_external = True
                    continue
                
                # After external call, look for view function calls
                if found_external and op.get('type') in ['call', 'staticcall']:
                    target_func = op.get('method', '')
                    
                    if target_func in self.view_functions:
                        view_calls.append({
                            'function': target_func,
                            'details': self.view_functions[target_func],
                            'operation': op
                        })
        
        return view_calls

    def _has_stale_state_risk(self, view_call: Dict, ext_call: Dict) -> bool:
        """
        Determine if view function may read stale state.
        """
        view_func = view_call['function']
        view_details = view_call['details']
        
        # Risk factors:
        # 1. View function reads balances
        if view_details.get('reads_balance'):
            return True
        
        # 2. View function queries prices
        if view_details.get('queries_price'):
            return True
        
        # 3. View function reads state that external call modifies
        state_reads = self.state_reads.get(view_func, [])
        state_before = ext_call.get('state_before', {})
        
        for var in state_reads:
            if var in state_before:
                return True
        
        return False

    def _called_from_callback(self, func_name: str, cfg: Dict) -> bool:
        """
        Check if function is called from a callback.
        """
        # Analyze call graph
        for edge in cfg.get('edges', []):
            source_node = self._get_node_by_id(cfg, edge.get('from'))
            if source_node:
                source_func = source_node.get('function', '').lower()
                target_node = self._get_node_by_id(cfg, edge.get('to'))
                target_func = target_node.get('function') if target_node else None
                
                # Check if callback calls our function
                if source_func in self.callback_functions and target_func == func_name:
                    return True
        
        return False

    def _calculate_confidence(self, ext_call: Dict, view_call: Dict) -> float:
        """
        Calculate confidence score for vulnerability.
        """
        confidence = 0.0
        
        # High confidence if LP protocol involved
        if any(proto in ext_call['target'] for proto in self.vulnerable_lp_protocols):
            confidence += 0.40
        
        # High confidence if view function queries price
        if view_call['details'].get('queries_price'):
            confidence += 0.35
        
        # Medium confidence if reads balances
        if view_call['details'].get('reads_balance'):
            confidence += 0.25
        
        # Medium confidence if external call is liquidity-related
        method = ext_call['method']
        if any(term in method for term in ['remove', 'exit', 'withdraw', 'burn']):
            confidence += 0.20
        
        return min(confidence, 1.0)

    def _describe_attack_vector(self, ext_call: Dict, view_call: Dict) -> str:
        """
        Describe the attack vector in detail.
        """
        return (
            f"Attacker triggers {ext_call['method']} on {ext_call['target']}, "
            f"which calls back into contract. During callback, view function "
            f"{view_call['function']} is called, reading stale state before "
            f"external call completes. This allows state manipulation attacks."
        )

    def _describe_lp_attack(self, lp_query: Dict) -> str:
        """
        Describe LP token price manipulation attack.
        """
        protocol = lp_query['protocol'].title()
        return (
            f"Attacker removes liquidity from {protocol} pool, triggering callback. "
            f"During callback (before balances update), contract queries LP token price "
            f"via {lp_query['method']}. The inflated price can be exploited for oracle "
            f"manipulation, over-collateralized borrowing, or unfair liquidations. "
            f"This is the same pattern as Sturdy Finance hack ($800K, June 2023)."
        )

    def _create_vulnerability(self, pattern: Dict, bytecode_analysis: Dict) -> Vulnerability:
        """
        Create detailed vulnerability report.
        """
        if pattern['type'] == 'lp_price_manipulation':
            return self._create_lp_vulnerability(pattern)
        else:
            return self._create_callback_vulnerability(pattern)

    def _create_lp_vulnerability(self, pattern: Dict) -> Vulnerability:
        """
        Create LP price manipulation vulnerability.
        """
        lp_query = pattern['lp_query']
        protocol = lp_query['protocol'].title()
        
        poc = f"""// Read-Only Reentrancy: {protocol} LP Price Manipulation
// Real-world example: Sturdy Finance ($800K loss)

// Step 1: Attacker removes liquidity from {protocol} pool
{protocol}Pool.removeLiquidity(largeAmount);
// This triggers receive() callback before balances update

// Step 2: In callback, query LP token price
function receive() external {{
    // LP price is inflated because totalSupply decreased but reserves not yet updated
    uint256 inflatedPrice = vault.{lp_query['method']}();
    
    // Exploit: Use inflated price for over-collateralized borrow
    lendingProtocol.borrow(inflatedPrice * collateralAmount);
}}

// Step 3: LP price normalizes, attacker profits from over-borrowed amount

// Mitigation: Use reentrancy guard on all view functions that query external prices
// or implement Checks-Effects-Interactions pattern even for view functions
"""
        
        exploit = Exploit(
            description=f"{protocol} LP token price manipulation via read-only reentrancy",
            attack_vector=pattern['attack_vector'],
            profit_estimate=800000.0,  # Based on Sturdy Finance
            transaction_sequence=[
                {"step": 1, "action": f"Remove liquidity from {protocol} pool"},
                {"step": 2, "action": "Callback triggered before state update"},
                {"step": 3, "action": f"Query inflated LP price via {lp_query['method']}"},
                {"step": 4, "action": "Exploit inflated price for over-collateralized action"},
                {"step": 5, "action": "Profit from price discrepancy"}
            ],
            proof_of_concept=poc
        )
        
        return Vulnerability(
            type=VulnerabilityType.READ_ONLY_REENTRANCY,
            severity=Severity.HIGH,
            name="Read-Only Reentrancy: LP Token Price Manipulation",
            description=f"Contract queries {protocol} LP token price during callback execution, "
                       f"allowing attacker to manipulate oracle data through read-only reentrancy. "
                       f"Function {lp_query['function']} calls {lp_query['method']} on {lp_query['target']}.",
            location=SourceLocation(
                file="contract.sol",
                line_start=lp_query.get('location', {}).get('line', 0),
                line_end=lp_query.get('location', {}).get('line', 0),
                function=lp_query['function']
            ),
            confidence=pattern['confidence'],
            impact=f"Oracle manipulation leading to over-collateralized borrowing, unfair liquidations, "
                   f"or protocol fund drainage. Proven attack vector: Sturdy Finance lost $800K to this exact pattern (June 2023). "
                   f"{protocol} LP tokens are particularly vulnerable to this attack.",
            recommendation=f"Implement reentrancy protection on view functions: "
                         f"1) Add reentrancy guard even for view/pure functions, "
                         f"2) Use Chainlink or TWAP oracles instead of spot {protocol} prices, "
                         f"3) Implement Checks-Effects-Interactions for all external calls, "
                         f"4) Validate LP token prices are within reasonable bounds before use.",
            exploit=exploit,
            cross_contract=True,
            affected_contracts=[lp_query['target'], lp_query['function']],
            technical_details=pattern
        )

    def _create_callback_vulnerability(self, pattern: Dict) -> Vulnerability:
        """
        Create general callback reentrancy vulnerability.
        """
        ext_call = pattern['external_call']
        view_call = pattern['view_function']
        
        poc = f"""// Read-Only Reentrancy via Callback

// Vulnerable contract calls external contract
function vulnerableFunction() public {{
    externalContract.{ext_call['method']}(); // Triggers callback
    // State update happens here, AFTER external call
}}

// Attacker's malicious contract
function receive() external {{
    // Called back DURING external call, before state updates
    uint256 staleValue = victim.{view_call['function']}();
    // staleValue reflects state before external call completed
    
    // Exploit stale state for profit
    victim.exploitStaleState(staleValue);
}}

// Mitigation: Update state BEFORE external calls, even in functions with view calls after
"""
        
        exploit = Exploit(
            description="Read-only reentrancy through callback manipulation",
            attack_vector=pattern['attack_vector'],
            profit_estimate=100000.0,
            transaction_sequence=[
                {"step": 1, "action": f"Trigger external call to {ext_call['target']}"},
                {"step": 2, "action": "Receive callback before state update"},
                {"step": 3, "action": f"Query stale state via {view_call['function']}"},
                {"step": 4, "action": "Exploit state inconsistency"}
            ],
            proof_of_concept=poc
        )
        
        return Vulnerability(
            type=VulnerabilityType.READ_ONLY_REENTRANCY,
            severity=Severity.HIGH,
            name="Read-Only Reentrancy via Callback",
            description=f"View function {view_call['function']} reads stale state during callback "
                       f"from external call to {ext_call['target']}.{ext_call['method']}().",
            location=SourceLocation(
                file="contract.sol",
                line_start=0,
                line_end=0,
                function=ext_call['caller_function']
            ),
            confidence=pattern['confidence'],
            impact="State inconsistency allows manipulation of view function return values, "
                   "potentially leading to oracle manipulation, incorrect accounting, or protocol exploitation.",
            recommendation="Apply Checks-Effects-Interactions pattern even when view functions are called after external calls. "
                         "Update all state before making external calls, or use reentrancy guards on view functions.",
            exploit=exploit,
            technical_details=pattern
        )
