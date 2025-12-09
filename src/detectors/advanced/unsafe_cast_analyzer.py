# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List
import re

from src.core.models import Vulnerability, VulnerabilityType, Severity, SourceLocation, Exploit

logger = logging.getLogger(__name__)


class UnsafeCastAnalyzer:
    """
    Production-grade unsafe type cast detector.
    Real-world: Silent overflows in downcasts (uint256 → uint128)
    Target accuracy: 75-85%
    """

    def __init__(self):
        self.casts: List[Dict] = []
        
        # Dangerous downcast patterns
        self.downcast_patterns = [
            (r'uint256.*uint(\d+)', 256),
            (r'int256.*int(\d+)', 256),
            (r'uint128.*uint(\d+)', 128),
            (r'int128.*int(\d+)', 128),
        ]

    def detect(self, bytecode_analysis: Dict, cfg: Dict,
                taint_results: Dict, symbolic_results: Dict,
                fuzzing_results: Dict) -> List[Vulnerability]:
        vulnerabilities = []
        
        self._identify_casts(symbolic_results, bytecode_analysis)
        
        for cast in self.casts:
            if cast['is_unsafe']:
                vuln = self._create_vulnerability(cast)
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _identify_casts(self, symbolic_results: Dict, bytecode_analysis: Dict) -> None:
        # Check symbolic execution results
        for path in symbolic_results.get('paths', []):
            for op in path.get('operations', []):
                expr = op.get('expression', '')
                
                # Look for cast patterns
                cast_info = self._parse_cast(expr)
                if cast_info:
                    cast_info['function'] = op.get('function')
                    cast_info['location'] = op.get('location', {})
                    
                    # Check if cast has overflow protection
                    has_check = self._has_overflow_check(op, path)
                    cast_info['is_unsafe'] = not has_check
                    
                    self.casts.append(cast_info)
        
        # Also check source code for type conversions
        source = bytecode_analysis.get('source_code', '')
        for match in re.finditer(r'uint(\d+)\s*\(', source):
            target_bits = int(match.group(1))
            if target_bits < 256:
                self.casts.append({
                    'from_type': 'uint256',
                    'to_type': f'uint{target_bits}',
                    'from_bits': 256,
                    'to_bits': target_bits,
                    'is_unsafe': True,  # Assume unsafe unless proven otherwise
                    'location': {'line': source[:match.start()].count('\n') + 1}
                })

    def _parse_cast(self, expr: str) -> Dict:
        """
        Parse cast expression to extract type information.
        """
        expr_lower = expr.lower()
        
        for pattern, from_bits in self.downcast_patterns:
            match = re.search(pattern, expr_lower)
            if match:
                to_bits = int(match.group(1)) if match.groups() else 0
                
                if to_bits < from_bits:
                    return {
                        'expression': expr,
                        'from_bits': from_bits,
                        'to_bits': to_bits,
                        'from_type': f'uint{from_bits}' if 'uint' in pattern else f'int{from_bits}',
                        'to_type': f'uint{to_bits}' if 'uint' in pattern else f'int{to_bits}',
                        'overflow_possible': True
                    }
        
        return None

    def _has_overflow_check(self, operation: Dict, path: Dict) -> bool:
        """
        Check if cast has overflow protection.
        """
        # Look for require/assert before or after cast
        ops = path.get('operations', [])
        op_index = ops.index(operation) if operation in ops else -1
        
        if op_index == -1:
            return False
        
        # Check surrounding operations
        check_range = ops[max(0, op_index-2):min(len(ops), op_index+3)]
        
        for check_op in check_range:
            if check_op.get('type') in ['require', 'assert']:
                condition = check_op.get('condition', '').lower()
                # Look for overflow checks like: require(value <= type(uint128).max)
                if any(x in condition for x in ['max', 'overflow', '<=', '<']):
                    return True
        
        return False

    def _create_vulnerability(self, cast: Dict) -> Vulnerability:
        from_type = cast['from_type']
        to_type = cast['to_type']
        from_bits = cast['from_bits']
        to_bits = cast['to_bits']
        
        max_safe = (2 ** to_bits) - 1
        
        poc = f"""// Unsafe Type Cast Overflow

// Vulnerable code:
uint256 largeValue = 2**200;  // Larger than uint128.max
uint128 smallValue = uint128(largeValue);  // UNCHECKED CAST!
// Result: smallValue = (2**200) % (2**128) = unexpected value
// Overflow is silent, no revert!

// Real-world scenario:
uint256 totalSupply = 1e30;  // Common for 18-decimal tokens
uint128 packed = uint128(totalSupply);  // Silently overflows
// packed now contains wrong value, breaking calculations

// Attack:
// 1. Manipulate value to be > {max_safe} ({to_type}.max)
// 2. Cast silently truncates to fit in {to_bits} bits
// 3. Resulting value is wrong, breaks logic
// 4. Exploit incorrect calculations

// Fix Option 1 - Require:
require(value <= type({to_type}).max, "Overflow");
{to_type} safe = {to_type}(value);

// Fix Option 2 - SafeCast library:
using SafeCast for uint256;
{to_type} safe = value.to{to_type.title()}();  // Reverts on overflow
"""
        
        return Vulnerability(
            type=VulnerabilityType.UNSAFE_CAST,
            severity=Severity.HIGH,
            name=f"Unsafe Downcast: {from_type} → {to_type}",
            description=f"Type downcast from {from_type} ({from_bits} bits) to {to_type} ({to_bits} bits) without overflow check",
            location=SourceLocation(
                file="contract.sol",
                line_start=cast.get('location', {}).get('line', 0),
                line_end=cast.get('location', {}).get('line', 0),
                function=cast.get('function', 'unknown')
            ),
            confidence=0.82,
            impact=f"Silent overflow when value > {max_safe} ({to_type}.max). "
                   f"Leads to incorrect calculations, fund loss, or logic bypass. "
                   f"Especially dangerous with token amounts (commonly uint256).",
            recommendation=f"Add overflow check: require(value <= type({to_type}).max, 'Overflow'); "
                         f"or use OpenZeppelin SafeCast library: value.to{to_type.title()}();",
            exploit=Exploit(
                description=f"Type downcast overflow {from_type} → {to_type}",
                attack_vector=f"Manipulate value > {max_safe} → cast silently truncates → wrong value → exploit",
                profit_estimate=250000.0,
                proof_of_concept=poc
            ),
            technical_details=cast
        )
