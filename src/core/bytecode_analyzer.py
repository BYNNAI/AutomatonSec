# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class BytecodeAnalyzer:
    """
    EVM bytecode disassembler and analyzer.
    Identifies opcodes, jump destinations, function selectors, and storage patterns.
    """
    
    OPCODES = {
        0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV', 0x05: 'SDIV',
        0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD', 0x0a: 'EXP',
        0x0b: 'SIGNEXTEND', 0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT',
        0x14: 'EQ', 0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT',
        0x1a: 'BYTE', 0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR', 0x20: 'SHA3',
        0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER',
        0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE',
        0x37: 'CALLDATACOPY', 0x38: 'CODESIZE', 0x39: 'CODECOPY',
        0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY',
        0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
        0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER',
        0x44: 'DIFFICULTY', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE',
        0x48: 'BASEFEE', 0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE',
        0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE', 0x56: 'JUMP',
        0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
        0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN',
        0xf4: 'DELEGATECALL', 0xf5: 'CREATE2', 0xfa: 'STATICCALL',
        0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT'
    }
    
    for i in range(0x60, 0x80):
        OPCODES[i] = f'PUSH{i - 0x5f}'
    
    for i in range(0x80, 0x90):
        OPCODES[i] = f'DUP{i - 0x7f}'
    
    for i in range(0x90, 0xa0):
        OPCODES[i] = f'SWAP{i - 0x8f}'
    
    for i in range(0xa0, 0xa5):
        OPCODES[i] = f'LOG{i - 0xa0}'
    
    def __init__(self):
        self.instructions = []
        self.jump_destinations = set()
        self.function_selectors = {}
        self.storage_ops = []
        self.external_calls = []
        
    def analyze(self, bytecode: str) -> Dict:
        """
        Disassemble and analyze EVM bytecode.
        
        Args:
            bytecode: Hex string of EVM bytecode
            
        Returns:
            Dict containing disassembled instructions and analysis results
        """
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        bytecode_bytes = bytes.fromhex(bytecode)
        
        logger.info(f"Analyzing bytecode: {len(bytecode_bytes)} bytes")
        
        self.instructions = self._disassemble(bytecode_bytes)
        self.jump_destinations = self._find_jump_destinations()
        self.function_selectors = self._extract_function_selectors()
        self.storage_ops = self._find_storage_operations()
        self.external_calls = self._find_external_calls()
        
        return {
            "instructions": self.instructions,
            "jump_destinations": list(self.jump_destinations),
            "function_selectors": self.function_selectors,
            "storage_operations": self.storage_ops,
            "external_calls": self.external_calls,
            "bytecode_size": len(bytecode_bytes)
        }
    
    def _disassemble(self, bytecode: bytes) -> List[Dict]:
        """
        Disassemble bytecode into instruction list.
        """
        instructions = []
        pc = 0
        
        while pc < len(bytecode):
            opcode = bytecode[pc]
            opname = self.OPCODES.get(opcode, f'UNKNOWN_{hex(opcode)}')
            
            instruction = {
                "pc": pc,
                "opcode": opcode,
                "opname": opname,
                "operand": None
            }
            
            if opname.startswith('PUSH'):
                push_size = int(opname[4:])
                operand_bytes = bytecode[pc+1:pc+1+push_size]
                instruction["operand"] = operand_bytes.hex()
                pc += push_size
            
            instructions.append(instruction)
            pc += 1
        
        return instructions
    
    def _find_jump_destinations(self) -> set:
        """
        Find all JUMPDEST opcodes (valid jump targets).
        """
        jump_dests = set()
        for inst in self.instructions:
            if inst["opname"] == 'JUMPDEST':
                jump_dests.add(inst["pc"])
        return jump_dests
    
    def _extract_function_selectors(self) -> Dict[str, int]:
        """
        Extract function selectors from bytecode dispatcher.
        """
        selectors = {}
        
        for i in range(len(self.instructions) - 3):
            if (self.instructions[i]["opname"] == 'PUSH4' and
                self.instructions[i+1]["opname"] == 'EQ'):
                
                selector = self.instructions[i]["operand"]
                
                for j in range(i+2, min(i+10, len(self.instructions))):
                    if self.instructions[j]["opname"] in ['JUMP', 'JUMPI']:
                        if j > 0 and self.instructions[j-1]["opname"].startswith('PUSH'):
                            target = int(self.instructions[j-1]["operand"], 16)
                            selectors[selector] = target
                        break
        
        return selectors
    
    def _find_storage_operations(self) -> List[Dict]:
        """
        Find all SLOAD and SSTORE operations.
        """
        storage_ops = []
        
        for inst in self.instructions:
            if inst["opname"] in ['SLOAD', 'SSTORE']:
                storage_ops.append({
                    "pc": inst["pc"],
                    "operation": inst["opname"]
                })
        
        return storage_ops
    
    def _find_external_calls(self) -> List[Dict]:
        """
        Find all external call operations (CALL, DELEGATECALL, STATICCALL, etc.).
        """
        calls = []
        call_opcodes = ['CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE']
        
        for inst in self.instructions:
            if inst["opname"] in call_opcodes:
                calls.append({
                    "pc": inst["pc"],
                    "call_type": inst["opname"]
                })
        
        return calls
