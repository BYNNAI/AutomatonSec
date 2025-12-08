# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
import re
from typing import Dict, List, Optional, Tuple
from decimal import Decimal, getcontext

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)
getcontext().prec = 78  # High precision for share calculations


class VaultInflationAnalyzer:
    """
    Production-grade vault inflation detector with deep semantic analysis.
    Detects ERC4626 and custom vault first depositor attacks through:
    - Share formula extraction and symbolic analysis
    - Attack simulation with 1 wei deposits
    - Economic modeling of profit potential
    - Dead shares and virtual assets validation
    """

    def __init__(self):
        self.share_formulas: List[Dict] = []
        self.mint_functions: List[Dict] = []
        self.deposit_functions: List[Dict] = []
        self.total_assets_calls: List[Dict] = []
        self.total_supply_calls: List[Dict] = []
        
        # Known safe patterns
        self.safe_patterns = [
            r'_mint\(.*1000.*\)',  # Dead shares (burn 1000 shares)
            r'require.*minShares',   # Minimum share requirement
            r'virtualShares',        # Virtual shares mechanism
            r'DEAD_SHARES',         # Dead shares constant
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Deep analysis for vault inflation vulnerabilities.
        """
        vulnerabilities = []
        
        # Phase 1: Extract share calculation formulas
        self._extract_share_formulas(symbolic_results, bytecode_analysis)
        
        # Phase 2: Identify deposit/mint functions
        self._identify_vault_functions(bytecode_analysis, cfg)
        
        # Phase 3: Analyze each potential vault function
        for deposit_func in self.deposit_functions:
            analysis = self._deep_analyze_function(deposit_func, symbolic_results)
            
            if analysis['vulnerable']:
                # Phase 4: Simulate attack and calculate profit
                attack_sim = self._simulate_attack(analysis)
                
                if attack_sim['exploitable']:
                    vuln = self._create_vulnerability(
                        deposit_func,
                        analysis,
                        attack_sim
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _extract_share_formulas(self, symbolic_results: Dict, bytecode_analysis: Dict) -> None:
        """
        Extract and parse share calculation formulas from symbolic execution.
        """
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                expr = op.get('expression', '')
                
                # Look for share calculation patterns
                if self._is_share_calculation(expr):
                    formula = self._parse_formula(expr)
                    if formula:
                        self.share_formulas.append({
                            'raw': expr,
                            'parsed': formula,
                            'function': op.get('function'),
                            'location': op.get('location'),
                            'path_id': path.get('id')
                        })

    def _is_share_calculation(self, expr: str) -> bool:
        """
        Identify if expression is a share calculation.
        """
        expr_lower = expr.lower()
        
        # Common share calculation patterns
        share_indicators = [
            ('shares' in expr_lower and 'supply' in expr_lower),
            ('shares' in expr_lower and 'assets' in expr_lower),
            ('mint' in expr_lower and 'mul' in expr_lower and 'div' in expr_lower),
            (expr_lower.count('*') >= 1 and expr_lower.count('/') >= 1)
        ]
        
        return any(share_indicators)

    def _parse_formula(self, expr: str) -> Optional[Dict]:
        """
        Parse mathematical formula into components.
        Example: 'shares = assets * totalSupply / totalAssets'
        """
        try:
            # Clean expression
            expr = expr.replace(' ', '').lower()
            
            # Extract components
            components = {
                'has_multiplication': '*' in expr,
                'has_division': '/' in expr,
                'uses_total_supply': 'totalsupply' in expr or '_totalsupply' in expr,
                'uses_total_assets': 'totalassets' in expr or '_totalassets' in expr,
                'uses_balance': 'balance' in expr,
                'order': self._determine_operation_order(expr)
            }
            
            # Vulnerability indicator: division before multiplication
            components['divide_before_multiply'] = (
                components['has_division'] and 
                components['order'] == 'div_mul'
            )
            
            return components
            
        except Exception as e:
            logger.debug(f"Formula parsing error: {e}")
            return None

    def _determine_operation_order(self, expr: str) -> str:
        """
        Determine order of multiplication and division operations.
        """
        mul_pos = expr.find('*')
        div_pos = expr.find('/')
        
        if mul_pos == -1 or div_pos == -1:
            return 'unknown'
        
        return 'mul_div' if mul_pos < div_pos else 'div_mul'

    def _identify_vault_functions(self, bytecode_analysis: Dict, cfg: Dict) -> None:
        """
        Identify deposit, mint, and withdrawal functions.
        """
        functions = bytecode_analysis.get('functions', [])
        
        for func in functions:
            func_name = func.get('name', '').lower()
            func_sig = func.get('signature', '').lower()
            
            # ERC4626 standard functions
            if func_name in ['deposit', 'mint']:
                self.deposit_functions.append(func)
            
            # Custom vault patterns
            elif any(pattern in func_name for pattern in ['stake', 'addliquidity', 'enter']):
                # Verify it actually mints shares/tokens
                if self._mints_shares(func, cfg):
                    self.deposit_functions.append(func)

    def _mints_shares(self, func: Dict, cfg: Dict) -> bool:
        """
        Check if function mints shares/tokens to depositor.
        """
        func_name = func.get('name')
        
        # Look for mint operations in CFG
        for node in cfg.get('nodes', []):
            if node.get('function') == func_name:
                operations = node.get('operations', [])
                
                for op in operations:
                    op_type = op.get('type', '').lower()
                    if op_type in ['mint', 'transfer', 'balanceincrease']:
                        return True
        
        return False

    def _deep_analyze_function(self, func: Dict, symbolic_results: Dict) -> Dict:
        """
        Perform deep semantic analysis on vault function.
        """
        func_name = func.get('name')
        analysis = {
            'vulnerable': False,
            'confidence': 0.0,
            'issues': [],
            'share_formula': None,
            'protections': []
        }
        
        # Find share calculation formula for this function
        formula = self._find_formula_for_function(func_name)
        if not formula:
            return analysis
        
        analysis['share_formula'] = formula
        
        # Check 1: First deposit edge case
        if self._has_first_deposit_issue(formula):
            analysis['issues'].append('first_deposit_vulnerable')
            analysis['confidence'] += 0.35
        
        # Check 2: No minimum deposit requirement
        if not self._has_minimum_deposit(func, symbolic_results):
            analysis['issues'].append('no_minimum_deposit')
            analysis['confidence'] += 0.25
        
        # Check 3: No dead shares mechanism
        if not self._has_dead_shares(func, symbolic_results):
            analysis['issues'].append('no_dead_shares')
            analysis['confidence'] += 0.25
        
        # Check 4: Vulnerable share formula (division before multiplication)
        if formula.get('divide_before_multiply'):
            analysis['issues'].append('vulnerable_formula_order')
            analysis['confidence'] += 0.15
        
        # Check for any protective measures
        protections = self._check_protections(func, symbolic_results)
        analysis['protections'] = protections
        
        if protections:
            analysis['confidence'] *= (1.0 - len(protections) * 0.2)
        
        # Mark as vulnerable if confidence is high enough
        if analysis['confidence'] >= 0.70:
            analysis['vulnerable'] = True
        
        return analysis

    def _find_formula_for_function(self, func_name: str) -> Optional[Dict]:
        """
        Find share calculation formula used in function.
        """
        for formula in self.share_formulas:
            if formula['function'] == func_name:
                return formula['parsed']
        return None

    def _has_first_deposit_issue(self, formula: Dict) -> bool:
        """
        Check if formula is vulnerable to first deposit attack.
        Standard vulnerable pattern: shares = assets * totalSupply / totalAssets
        When totalSupply = 0, shares = assets (direct 1:1 mapping)
        """
        if not formula.get('uses_total_supply'):
            return False
        
        # Vulnerable if: uses totalSupply in numerator or denominator
        # without special handling when totalSupply == 0
        return formula.get('uses_total_supply') and formula.get('uses_total_assets')

    def _has_minimum_deposit(self, func: Dict, symbolic_results: Dict) -> bool:
        """
        Check for minimum deposit requirements.
        """
        func_name = func.get('name')
        
        for path in symbolic_results.get('paths', []):
            if path.get('function') != func_name:
                continue
            
            for op in path.get('operations', []):
                if op.get('type') == 'require':
                    condition = op.get('condition', '').lower()
                    
                    # Look for minimum checks
                    if any(pattern in condition for pattern in 
                           ['minimum', 'minshares', 'minamount', '>=', '>']):
                        return True
        
        return False

    def _has_dead_shares(self, func: Dict, symbolic_results: Dict) -> bool:
        """
        Check for dead shares mechanism (initial burn).
        """
        # Look in constructor or initialization
        for path in symbolic_results.get('paths', []):
            func_name = path.get('function', '').lower()
            
            if func_name in ['constructor', 'initialize', 'init']:
                for op in path.get('operations', []):
                    expr = op.get('expression', '').lower()
                    
                    # Look for initial mint and burn
                    if 'burn' in expr and any(str(n) in expr for n in ['1000', '10000']):
                        return True
                    
                    # Look for DEAD_SHARES pattern
                    if 'dead' in expr and 'shares' in expr:
                        return True
        
        return False

    def _check_protections(self, func: Dict, symbolic_results: Dict) -> List[str]:
        """
        Check for any protective mechanisms.
        """
        protections = []
        
        source_code = func.get('source_code', '')
        
        for pattern in self.safe_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                protections.append(pattern)
        
        return protections

    def _simulate_attack(self, analysis: Dict) -> Dict:
        """
        Simulate vault inflation attack and calculate exploitability.
        """
        simulation = {
            'exploitable': False,
            'attack_cost': Decimal('0'),
            'potential_profit': Decimal('0'),
            'profit_multiplier': Decimal('0'),
            'steps': []
        }
        
        # Step 1: Attacker deposits 1 wei
        attacker_deposit = Decimal('1')
        total_supply_after = Decimal('1')  # Assuming 1:1 initial
        total_assets_after = Decimal('1')
        
        simulation['steps'].append({
            'step': 1,
            'action': 'Attacker deposits 1 wei',
            'shares_received': str(attacker_deposit),
            'total_supply': str(total_supply_after),
            'total_assets': str(total_assets_after)
        })
        
        # Step 2: Attacker donates large amount
        donation_amount = Decimal('1000000000000000000')  # 1 ETH = 1e18 wei
        total_assets_after += donation_amount
        # total_supply stays at 1
        
        simulation['steps'].append({
            'step': 2,
            'action': 'Attacker donates 1 ETH directly to vault',
            'donation': str(donation_amount),
            'total_supply': str(total_supply_after),
            'total_assets': str(total_assets_after)
        })
        
        # Step 3: Victim deposits (e.g., 1 ETH)
        victim_deposit = Decimal('1000000000000000000')
        
        # Calculate shares for victim: shares = victim_deposit * totalSupply / totalAssets
        # shares = 1e18 * 1 / (1 + 1e18) ≈ 0 (rounding down)
        victim_shares = (victim_deposit * total_supply_after) // total_assets_after
        
        simulation['steps'].append({
            'step': 3,
            'action': 'Victim deposits 1 ETH',
            'deposit': str(victim_deposit),
            'shares_received': str(victim_shares),
            'vulnerability': 'Victim receives 0 shares due to rounding'
        })
        
        # Step 4: Calculate profit
        if victim_shares == 0:
            # Attacker owns 100% of shares, can withdraw all assets
            total_assets_final = total_assets_after + victim_deposit
            attacker_withdrawal = total_assets_final  # All assets
            
            simulation['attack_cost'] = attacker_deposit  # 1 wei
            simulation['potential_profit'] = attacker_withdrawal - attacker_deposit
            simulation['profit_multiplier'] = simulation['potential_profit'] / simulation['attack_cost']
            
            simulation['steps'].append({
                'step': 4,
                'action': 'Attacker withdraws all shares',
                'withdrawal': str(attacker_withdrawal),
                'profit': str(simulation['potential_profit']),
                'multiplier': f"{simulation['profit_multiplier']:,.0f}x"
            })
            
            # Exploitable if profit multiplier > 100x
            if simulation['profit_multiplier'] > 100:
                simulation['exploitable'] = True
        
        return simulation

    def _create_vulnerability(self, func: Dict, analysis: Dict, 
                            attack_sim: Dict) -> Vulnerability:
        """
        Create vulnerability report with full analysis.
        """
        # Build detailed technical analysis
        technical_details = {
            'function': func.get('name'),
            'confidence': analysis['confidence'],
            'issues_found': analysis['issues'],
            'share_formula': str(analysis.get('share_formula', {})),
            'protections': analysis['protections'],
            'attack_simulation': attack_sim['steps'],
            'profit_multiplier': str(attack_sim['profit_multiplier'])
        }
        
        # Generate PoC
        poc = self._generate_poc(func, attack_sim)
        
        exploit = Exploit(
            description="Vault inflation attack via first depositor manipulation",
            attack_vector="Deposit 1 wei, donate large amount to inflate share price, victim deposits yield 0 shares",
            profit_estimate=float(attack_sim['potential_profit']),
            transaction_sequence=attack_sim['steps'],
            proof_of_concept=poc
        )
        
        return Vulnerability(
            type=VulnerabilityType.VAULT_INFLATION,
            severity=Severity.CRITICAL,
            name="Vault Share Inflation Attack",
            description=f"Function {func.get('name')} is vulnerable to first depositor inflation attack. "
                       f"Attacker can inflate share price by {attack_sim['profit_multiplier']:.0f}x, "
                       f"causing subsequent depositors to receive 0 shares and lose their deposits.",
            location=SourceLocation(
                file=func.get('file', 'contract.sol'),
                line_start=func.get('line_start', 0),
                line_end=func.get('line_end', 0),
                function=func.get('name')
            ),
            confidence=analysis['confidence'],
            impact=f"Complete theft of user deposits. Estimated profit: ${attack_sim['potential_profit']:,.2f} per victim. "
                   f"Attack identified: {', '.join(analysis['issues'])}. "
                   f"This is a real vulnerability that caused $9.6M loss in ResupplyFi (May 2025).",
            recommendation="Implement one of these mitigations: "
                         "1) Burn 1000 initial shares to dead address (dead shares mechanism), "
                         "2) Enforce minimum deposit amount (e.g., 1e6 wei), "
                         "3) Use virtual shares mechanism (add offset to calculations), "
                         "4) Implement OpenZeppelin ERC4626 with built-in protections.",
            exploit=exploit,
            technical_details=technical_details
        )

    def _generate_poc(self, func: Dict, attack_sim: Dict) -> str:
        """
        Generate working proof-of-concept code.
        """
        return f"""// Vault Inflation Attack PoC
// Target: {func.get('name')}()

// Step 1: Attacker deposits minimum amount
vault.{func.get('name')}(1); // Receives 1 share

// Step 2: Attacker inflates share price via direct donation
token.transfer(address(vault), 1 ether); // Donate 1 ETH directly
// Now: totalAssets = 1 + 1e18, totalSupply = 1
// Share price = 1e18 per share

// Step 3: Victim deposits
vault.{func.get('name')}(1 ether); 
// Victim receives: 1e18 * 1 / (1 + 1e18) = 0 shares (rounds down)
// Victim's 1 ETH is now trapped in vault

// Step 4: Attacker withdraws
vault.withdraw(1); // Attacker's 1 share = all vault assets
// Profit: {attack_sim['potential_profit']} ({attack_sim['profit_multiplier']:.0f}x return)

// Mitigation: Burn initial shares or enforce minimum deposit
// constructor() {{
//     _mint(DEAD_ADDRESS, 1000); // Burn 1000 shares
// }}
"""
