# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class GovernanceAttackAnalyzer:
    """
    Production-grade governance attack detector.
    Real-world: Multiple protocols, flash loan voting manipulation
    Target accuracy: 65-75%
    """

    def __init__(self):
        self.vote_functions: List[Dict] = []
        self.proposal_functions: List[Dict] = []
        self.token_transfers: List[Dict] = []
        self.flash_loans: List[Dict] = []
        self.time_locks: List[Dict] = []
        self.snapshots: List[Dict] = []

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_governance_functions(bytecode_analysis)
        self._identify_flash_loans(symbolic_results)
        self._identify_time_locks(symbolic_results)
        self._identify_snapshots(symbolic_results)
        
        vulnerabilities.extend(self._check_flash_loan_voting())
        vulnerabilities.extend(self._check_snapshot_usage())
        vulnerabilities.extend(self._check_proposal_execution())
        vulnerabilities.extend(self._check_voting_power_delegation())
        
        return vulnerabilities

    def _identify_governance_functions(self, bytecode_analysis: Dict) -> None:
        functions = bytecode_analysis.get('functions', [])
        for func in functions:
            name = func.get('name', '').lower()
            if any(x in name for x in ['vote', 'cast']):
                self.vote_functions.append(func)
            elif any(x in name for x in ['propose', 'proposal', 'execute']):
                self.proposal_functions.append(func)

    def _identify_flash_loans(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'external_call':
                    method = op.get('method', '').lower()
                    if 'flash' in method or 'borrow' in method:
                        self.flash_loans.append({
                            'method': method,
                            'function': op.get('function'),
                            'location': op.get('location', {})
                        })

    def _identify_time_locks(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                expr = op.get('expression', '').lower()
                if 'timestamp' in expr or 'delay' in expr or 'timelock' in expr:
                    self.time_locks.append({
                        'expression': expr,
                        'function': op.get('function'),
                        'type': op.get('type')
                    })

    def _identify_snapshots(self, symbolic_results: Dict) -> None:
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if 'snapshot' in op.get('expression', '').lower():
                    self.snapshots.append({
                        'function': op.get('function'),
                        'location': op.get('location', {})
                    })

    def _check_flash_loan_voting(self) -> List[Vulnerability]:
        vulns = []
        
        if self.flash_loans and self.vote_functions:
            for vote_func in self.vote_functions:
                func_name = vote_func.get('name')
                
                # Check if flash loan and voting in same function
                flash_in_vote = any(
                    fl['function'] == func_name 
                    for fl in self.flash_loans
                )
                
                if flash_in_vote:
                    poc = f"""// Flash Loan Governance Attack
// 1. Flash loan voting tokens
flashLender.flashLoan(votingToken, largeAmount);

// 2. Vote with borrowed tokens
governance.{func_name}(proposalId, support);

// 3. Proposal passes with manipulated votes
// 4. Return flash loan tokens
votingToken.transfer(flashLender, largeAmount);

// Result: Attacker controls governance without owning tokens
"""
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.GOVERNANCE_ATTACK,
                        severity=Severity.CRITICAL,
                        name="Flash Loan Voting Manipulation",
                        description=f"Function {func_name} allows voting with flash-borrowed tokens",
                        location=SourceLocation(
                            file="contract.sol",
                            line_start=vote_func.get('line_start', 0),
                            line_end=vote_func.get('line_end', 0),
                            function=func_name
                        ),
                        confidence=0.88,
                        impact="Attacker can pass malicious proposals by flash-borrowing voting tokens. Protocol takeover possible.",
                        recommendation="Implement snapshot-based voting: record voting power at proposal creation block, not voting block. Use OpenZeppelin Governor with snapshots.",
                        exploit=Exploit(
                            description="Flash loan governance takeover",
                            attack_vector="Flash borrow → vote → pass proposal → return tokens",
                            profit_estimate=5000000.0,
                            proof_of_concept=poc
                        )
                    ))
        
        return vulns

    def _check_snapshot_usage(self) -> List[Vulnerability]:
        vulns = []
        
        if self.vote_functions and not self.snapshots:
            vulns.append(Vulnerability(
                type=VulnerabilityType.GOVERNANCE_ATTACK,
                severity=Severity.HIGH,
                name="No Snapshot-Based Voting",
                description=f"Governance has {len(self.vote_functions)} voting functions but no snapshot mechanism",
                location=SourceLocation(file="contract.sol", line_start=0, line_end=0),
                confidence=0.75,
                impact="Vulnerable to flash loan voting attacks. Voting power can be manipulated.",
                recommendation="Implement ERC20Snapshot or record voting power at proposal creation."
            ))
        
        return vulns

    def _check_proposal_execution(self) -> List[Vulnerability]:
        vulns = []
        
        for prop_func in self.proposal_functions:
            func_name = prop_func.get('name', '').lower()
            
            # Check if execution has time lock
            if 'execute' in func_name:
                has_timelock = any(
                    tl['function'] == prop_func.get('name')
                    for tl in self.time_locks
                )
                
                if not has_timelock:
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.GOVERNANCE_ATTACK,
                        severity=Severity.HIGH,
                        name="No Time Lock on Proposal Execution",
                        description=f"Function {prop_func.get('name')} executes proposals without time delay",
                        location=SourceLocation(
                            file="contract.sol",
                            line_start=prop_func.get('line_start', 0),
                            line_end=prop_func.get('line_end', 0),
                            function=prop_func.get('name')
                        ),
                        confidence=0.82,
                        impact="Malicious proposals can execute immediately. No time for community response.",
                        recommendation="Add time lock: minimum 24-48h delay between proposal passage and execution."
                    ))
        
        return vulns

    def _check_voting_power_delegation(self) -> List[Vulnerability]:
        vulns = []
        
        # Check for delegation without safeguards
        for vote_func in self.vote_functions:
            source = vote_func.get('source_code', '')
            if 'delegate' in source.lower():
                if 'snapshot' not in source.lower():
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.GOVERNANCE_ATTACK,
                        severity=Severity.MEDIUM,
                        name="Unsafe Delegation Pattern",
                        description=f"Function {vote_func.get('name')} allows delegation without snapshot",
                        location=SourceLocation(
                            file="contract.sol",
                            line_start=vote_func.get('line_start', 0),
                            line_end=vote_func.get('line_end', 0)
                        ),
                        confidence=0.70,
                        impact="Delegation can be manipulated to gain voting power.",
                        recommendation="Use snapshot-based delegation tracking."
                    ))
        
        return vulns
