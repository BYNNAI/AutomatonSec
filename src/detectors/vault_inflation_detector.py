# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class VaultInflationDetector:
    """
    Detects vault inflation attacks where first depositor can manipulate
    share price through donation attacks. Common in ERC4626 vaults and
    liquidity pools without proper initialization.
    """

    def __init__(self):
        self.vault_functions: Set[str] = {'deposit', 'mint', 'withdraw', 'redeem'}
        self.share_calculations: List[Dict] = []

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        """
        Detect vault inflation vulnerability patterns.
        """
        vulnerabilities = []
        
        self._analyze_share_calculations(symbolic_results)
        vulnerable_vaults = self._identify_vulnerable_vaults()
        
        for vault in vulnerable_vaults:
            exploit = self._generate_exploit(vault)
            
            vuln = Vulnerability(
                type=VulnerabilityType.VAULT_INFLATION,
                severity=Severity.CRITICAL,
                name="Vault Share Inflation Attack",
                description="First depositor can inflate share price through donation attack",
                location=SourceLocation(
                    file="contract.sol",
                    line_start=vault.get('line', 0),
                    line_end=vault.get('line', 0),
                    function=vault['function']
                ),
                confidence=0.90,
                impact="Attacker can steal funds from subsequent depositors by manipulating share price",
                recommendation="Implement virtual shares, minimum deposit amount, or dead shares mechanism",
                exploit=exploit,
                technical_details=vault
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _analyze_share_calculations(self, symbolic_results: Dict) -> None:
        """Analyze share price calculation logic."""
        for path in symbolic_results.get('paths', []):
            for operation in path.get('operations', []):
                if self._is_share_calculation(operation):
                    self.share_calculations.append({
                        'function': operation.get('function'),
                        'formula': operation.get('expression'),
                        'path_id': path.get('id')
                    })

    def _is_share_calculation(self, operation: Dict) -> bool:
        """Check if operation involves share calculation."""
        expr = operation.get('expression', '')
        return any(pattern in expr.lower() for pattern in 
                   ['shares', 'totalsupply', 'totalassets', 'balanceof'])

    def _identify_vulnerable_vaults(self) -> List[Dict]:
        """Identify vaults vulnerable to inflation attacks."""
        vulnerable = []
        
        for calc in self.share_calculations:
            if self._lacks_protection(calc):
                vulnerable.append({
                    'function': calc['function'],
                    'calculation': calc['formula'],
                    'vulnerability': 'No minimum deposit or dead shares'
                })
        
        return vulnerable

    def _lacks_protection(self, calc: Dict) -> bool:
        """Check if calculation lacks inflation protection."""
        formula = calc.get('formula', '').lower()
        has_minimum = 'require' in formula and ('minimum' in formula or '>' in formula)
        has_dead_shares = 'dead' in formula or 'burn' in formula
        return not (has_minimum or has_dead_shares)

    def _generate_exploit(self, vault: Dict) -> Exploit:
        """Generate exploit PoC for vault inflation."""
        return Exploit(
            description="First depositor inflation attack",
            attack_vector="Deposit 1 wei, donate large amount, subsequent deposits receive 0 shares",
            profit_estimate=100000.0,
            transaction_sequence=[
                {"step": 1, "action": "Deposit 1 wei to vault"},
                {"step": 2, "action": "Transfer large amount directly to vault"},
                {"step": 3, "action": "Wait for victim deposit"},
                {"step": 4, "action": "Withdraw all shares"}
            ],
            proof_of_concept="""// 1. First deposit
vault.deposit(1);
// 2. Inflate share price
token.transfer(address(vault), 10000e18);
// 3. Victim deposits and receives 0 shares
// 4. Attacker withdraws"""
        )
