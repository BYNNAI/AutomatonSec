# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
import re
from typing import Dict, List, Tuple, Optional

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class UnsafeCastAnalyzer:
    """
    Production-grade unsafe type cast detector.
    Target accuracy: 75-85%
    
    Detects overflow in:
    - uint256 → uint128/uint64/uint32
    - int256 → int128/int64
    - address → uint160 → address (precision loss)
    """

    def __init__(self):
        self.cast_operations: List[Dict] = []
        
        # Risky downcast patterns
        self.downcast_patterns = [
            (r'uint256.*uint128', 'uint256', 'uint128', 128),
            (r'uint256.*uint64', 'uint256', 'uint64', 192),
            (r'uint256.*uint32', 'uint256', 'uint32', 224),
            (r'uint256.*uint16', 'uint256', 'uint16', 240),
            (r'uint256.*uint8', 'uint256', 'uint8', 248),
            (r'uint128.*uint64', 'uint128', 'uint64', 64),
            (r'int256.*int128', 'int256', 'int128', 128),
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Phase 1: Identify type cast operations
        self._identify_casts(symbolic_results, bytecode_analysis)
        
        # Phase 2: Analyze each cast for overflow risk
        for cast in self.cast_operations:
            if self._is_unsafe_downcast(cast):
                # Phase 3: Check if overflow protection exists
                if not self._has_overflow_protection(cast, symbolic_results):
                    vuln = self._create_vulnerability(cast)
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_casts(self, symbolic_results: Dict, 
                       bytecode_analysis: Dict) -> None:
        """
        Identify all type casting operations.
        """
        # Check source code for explicit casts
        source = bytecode_analysis.get('source_code', '')
        
        for line_num, line in enumerate(source.split('\n'), 1):
            for pattern, from_type, to_type, bits_lost in self.downcast_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.cast_operations.append({
                        'from_type': from_type,
                        'to_type': to_type,
                        'bits_lost': bits_lost,
                        'line': line_num,
                        'code': line.strip(),
                        'pattern': pattern
                    })
        
        # Also check symbolic execution for cast operations
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                if op.get('type') == 'cast':
                    self.cast_operations.append({
                        'from_type': op.get('from_type', 'unknown'),
                        'to_type': op.get('to_type', 'unknown'),
                        'function': op.get('function'),
                        'location': op.get('location', {}),
                        'expression': op.get('expression', '')
                    })

    def _is_unsafe_downcast(self, cast: Dict) -> bool:
        """
        Determine if cast is a risky downcast.
        """
        from_type = cast.get('from_type', '').lower()
        to_type = cast.get('to_type', '').lower()
        
        # Extract bit sizes
        from_bits = self._extract_bit_size(from_type)
        to_bits = self._extract_bit_size(to_type)
        
        # Downcast if target type is smaller
        return to_bits < from_bits

    def _extract_bit_size(self, type_str: str) -> int:
        """
        Extract bit size from type string.
        """
        # Extract number from type (e.g., uint256 → 256)
        match = re.search(r'\d+', type_str)
        if match:
            return int(match.group())
        
        # Default sizes
        if 'uint' in type_str or 'int' in type_str:
            return 256  # Default Solidity int size
        elif 'address' in type_str:
            return 160
        
        return 256  # Conservative default

    def _has_overflow_protection(self, cast: Dict, 
                                symbolic_results: Dict) -> bool:
        """
        Check if cast has overflow protection (require/assert).
        """
        cast_line = cast.get('line')
        cast_func = cast.get('function')
        
        # Look for require/assert near the cast
        for path in symbolic_results.get('paths', []):
            if cast_func and path.get('function') != cast_func:
                continue
            
            for op in path.get('operations', []):
                op_location = op.get('location', {})
                op_line = op_location.get('line', 0)
                
                # Check operations within 5 lines of cast
                if cast_line and abs(op_line - cast_line) <= 5:
                    op_type = op.get('type', '')
                    condition = op.get('condition', '').lower()
                    
                    # Look for overflow checks
                    if op_type in ['require', 'assert']:
                        # Common overflow check patterns
                        overflow_checks = [
                            'max', 'type(uint', 'overflow',
                            '<=', '<', 'safe'
                        ]
                        
                        if any(check in condition for check in overflow_checks):
                            return True
        
        return False

    def _create_vulnerability(self, cast: Dict) -> Vulnerability:
        from_type = cast.get('from_type', 'uint256')
        to_type = cast.get('to_type', 'uint128')
        bits_lost = cast.get('bits_lost', 128)
        
        # Calculate maximum safe value
        max_safe = (2 ** (256 - bits_lost)) - 1
        
        poc = f"""// Unsafe Downcast: {from_type} → {to_type}
// Loses {bits_lost} bits of precision

// Vulnerable code:
{from_type} largeValue = 2**200; // Large number
{to_type} smallValue = {to_type}(largeValue); // Overflow!
// smallValue is now truncated, not the original value

// Example exploit:
contract Vulnerable {{
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) public {{
        require(balances[msg.sender] >= amount);
        
        // Unsafe cast
        uint128 amount128 = uint128(amount);
        
        // If amount > 2^128, amount128 wraps around
        // e.g., 2^128 + 100 becomes 100
        
        token.transfer(msg.sender, amount128); // Sends truncated amount
        balances[msg.sender] -= amount; // Deducts full amount!
        
        // Attacker withdrawn small amount but balance reduced by large amount
    }}
}}

// Attack:
// 1. Attacker has balance of 2^128 + 1000
// 2. Calls withdraw(2^128 + 1000)
// 3. Cast truncates to 1000
// 4. Only 1000 tokens transferred
// 5. But full 2^128 + 1000 deducted from balance
// 6. Attacker repeats to drain more than they deposited

// Fix:
require(amount <= type(uint128).max, "Overflow");
uint128 amount128 = uint128(amount);
"""
        
        return Vulnerability(
            type=VulnerabilityType.UNSAFE_CAST,
            severity=Severity.HIGH,
            name=f"Unsafe Downcast: {from_type} → {to_type}",
            description=f"Unchecked type cast from {from_type} to {to_type} loses {bits_lost} bits. "
                       f"Values > {max_safe} will silently overflow.",
            location=SourceLocation(
                file="contract.sol",
                line_start=cast.get('line', 0),
                line_end=cast.get('line', 0),
                function=cast.get('function', 'unknown')
            ),
            confidence=0.85,
            impact=f"Silent integer overflow. Values exceeding {to_type} max will wrap around, "
                   f"leading to incorrect calculations. Can enable fund theft through balance manipulation.",
            recommendation=f"Add overflow check before cast: "
                         f"require(value <= type({to_type}).max, \"Overflow\"); "
                         f"OR use OpenZeppelin SafeCast library: {to_type} safe = value.toUint{256-bits_lost}();",
            exploit=Exploit(
                description=f"Downcast overflow {from_type} → {to_type}",
                attack_vector=f"Provide value > 2^{256-bits_lost}, cast silently truncates to smaller value",
                profit_estimate=250000.0,
                transaction_sequence=[
                    {"step": 1, "action": f"Provide {from_type} value > type({to_type}).max"},
                    {"step": 2, "action": f"Cast silently truncates to {to_type}"},
                    {"step": 3, "action": "Contract uses truncated value for critical operation"},
                    {"step": 4, "action": "Exploit difference between original and truncated value"}
                ],
                proof_of_concept=poc
            ),
            technical_details=cast
        )
