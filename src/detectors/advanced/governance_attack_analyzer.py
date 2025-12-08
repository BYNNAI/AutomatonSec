# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class GovernanceAttackAnalyzer:
    """
    Production-grade governance attack detector.
    Target accuracy: 65-75%
    
    Detects flash loan voting manipulation.
    """

    def __init__(self):
        self.voting_functions: List[Dict] = []
        self.flash_loan_calls: List[Dict] = []
        self.token_transfers: List[Dict] = []
        self.snapshot_checks: List[Dict] = []

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_voting_functions(bytecode_analysis)
        self._identify_flash_loans(symbolic_results)
        self._check_snapshot_mechanism(symbolic_results)
        
        # Check if voting is vulnerable to flash loan attacks
        if self.voting_functions and self.flash_loan_calls:
            if not self._has_snapshot_protection():
                vuln = self._create_flash_loan_voting_vuln()
                vulnerabilities.append(vuln)
        
        # Check for time-lock bypass
        timelock_vulns = self._check_timelock_bypass(symbolic_results)
        vulnerabilities.extend(timelock_vulns)
        
        return vulnerabilities

    def _identify_voting_functions(self, bytecode_analysis: Dict) -> None:
        functions = bytecode_analysis.get('functions', [])
        
        voting_keywords = ['vote', 'propose', 'castVote', 'delegate']
        
        for func in functions:
            func_name = func.get('name', '').lower()
            if any(kw.lower() in func_name for kw in voting_keywords):
                self.voting_functions.append(func)

    def _identify_flash_loans(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                method = op.get('method', '').lower()
                if 'flash' in method or 'borrow' in method:
                    self.flash_loan_calls.append(op)

    def _check_snapshot_mechanism(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                expr = op.get('expression', '').lower()
                if 'snapshot' in expr or 'checkpoint' in expr:
                    self.snapshot_checks.append(op)

    def _has_snapshot_protection(self) -> bool:
        return len(self.snapshot_checks) > 0

    def _check_timelock_bypass(self, symbolic_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Check for execute functions without proper time-lock
        for path in symbolic_results.get('paths', []):
            func = path.get('function', '').lower()
            
            if 'execute' in func or 'queue' in func:
                has_timelock = False
                
                for op in path.get('operations', []):
                    expr = op.get('expression', '').lower()
                    if 'timestamp' in expr or 'delay' in expr:
                        has_timelock = True
                        break
                
                if not has_timelock:
                    vuln = Vulnerability(
                        type=VulnerabilityType.GOVERNANCE_ATTACK,
                        severity=Severity.HIGH,
                        name="Missing Timelock Protection",
                        description=f"Function {func} lacks timelock delay",
                        location=SourceLocation(
                            file="contract.sol",
                            line_start=0,
                            line_end=0,
                            function=func
                        ),
                        confidence=0.75,
                        impact="Proposals can be executed immediately without delay",
                        recommendation="Add timelock delay (e.g., 2 days) before execution"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _create_flash_loan_voting_vuln(self) -> Vulnerability:
        poc = """// Flash Loan Governance Attack
// Real-world: Multiple protocols affected

// 1. Flash loan governance tokens
flashLoan(governanceToken, largeAmount);

// 2. Delegate voting power to self
token.delegate(address(this));

// 3. Create and vote on malicious proposal
governance.propose(maliciousAction);
governance.castVote(proposalId, true);

// 4. Execute proposal (if no timelock)
governance.execute(proposalId);

// 5. Return flash loan
token.transfer(lender, largeAmount);

// Result: Malicious proposal passed and executed
// No actual token ownership required!
"""
        
        return Vulnerability(
            type=VulnerabilityType.GOVERNANCE_ATTACK,
            severity=Severity.CRITICAL,
            name="Flash Loan Governance Manipulation",
            description=f"Voting system vulnerable to flash loan attacks. {len(self.voting_functions)} voting functions without snapshot protection.",
            location=SourceLocation(
                file="contract.sol",
                line_start=0,
                line_end=0,
                function="governance"
            ),
            confidence=0.82,
            impact="Attacker can pass malicious proposals using flash-loaned tokens without actual ownership. Treasury drain, parameter changes, or protocol takeover possible.",
            recommendation="Implement snapshot-based voting (check voting power at specific block), add timelock delays (2+ days), require minimum holding period before voting.",
            exploit=Exploit(
                description="Flash loan governance takeover",
                attack_vector="Flash loan → acquire voting power → pass malicious proposal → return tokens",
                profit_estimate=2000000.0,
                transaction_sequence=[
                    {"step": 1, "action": "Flash loan governance tokens"},
                    {"step": 2, "action": "Delegate voting power"},
                    {"step": 3, "action": "Create and vote on malicious proposal"},
                    {"step": 4, "action": "Execute proposal (if no timelock)"},
                    {"step": 5, "action": "Return flash loan with fee"}
                ],
                proof_of_concept=poc
            ),
            technical_details={
                'voting_functions': len(self.voting_functions),
                'flash_loan_calls': len(self.flash_loan_calls),
                'has_snapshot': self._has_snapshot_protection()
            }
        )
