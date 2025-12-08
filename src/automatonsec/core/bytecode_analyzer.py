# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

from typing import List, Dict, Set, Optional, Tuple
import re


class EVMInstruction:
    def __init__(self, opcode: str, address: int, operand: Optional[str] = None):
        self.opcode = opcode
        self.address = address
        self.operand = operand

    def __repr__(self):
        if self.operand:
            return f"{self.address:04x}: {self.opcode} {self.operand}"
        return f"{self.address:04x}: {self.opcode}"


class BytecodeAnalyzer:
    OPCODE_MAP = {
        "00": "STOP", "01": "ADD", "02": "MUL", "03": "SUB", "04": "DIV",
        "05": "SDIV", "06": "MOD", "07": "SMOD", "08": "ADDMOD", "09": "MULMOD",
        "0a": "EXP", "0b": "SIGNEXTEND", "10": "LT", "11": "GT", "12": "SLT",
        "13": "SGT", "14": "EQ", "15": "ISZERO", "16": "AND", "17": "OR",
        "18": "XOR", "19": "NOT", "1a": "BYTE", "1b": "SHL", "1c": "SHR",
        "1d": "SAR", "20": "SHA3", "30": "ADDRESS", "31": "BALANCE", "32": "ORIGIN",
        "33": "CALLER", "34": "CALLVALUE", "35": "CALLDATALOAD", "36": "CALLDATASIZE",
        "37": "CALLDATACOPY", "38": "CODESIZE", "39": "CODECOPY", "3a": "GASPRICE",
        "3b": "EXTCODESIZE", "3c": "EXTCODECOPY", "3d": "RETURNDATASIZE",
        "3e": "RETURNDATACOPY", "3f": "EXTCODEHASH", "40": "BLOCKHASH", "41": "COINBASE",
        "42": "TIMESTAMP", "43": "NUMBER", "44": "DIFFICULTY", "45": "GASLIMIT",
        "46": "CHAINID", "47": "SELFBALANCE", "50": "POP", "51": "MLOAD",
        "52": "MSTORE", "53": "MSTORE8", "54": "SLOAD", "55": "SSTORE",
        "56": "JUMP", "57": "JUMPI", "58": "PC", "59": "MSIZE",
        "5a": "GAS", "5b": "JUMPDEST", "5f": "PUSH0",
        "f0": "CREATE", "f1": "CALL", "f2": "CALLCODE", "f3": "RETURN",
        "f4": "DELEGATECALL", "f5": "CREATE2", "fa": "STATICCALL", "fd": "REVERT",
        "fe": "INVALID", "ff": "SELFDESTRUCT",
    }

    for i in range(1, 33):
        OPCODE_MAP[f"{0x60 + i - 1:02x}"] = f"PUSH{i}"

    for i in range(1, 17):
        OPCODE_MAP[f"{0x80 + i - 1:02x}"] = f"DUP{i}"
        OPCODE_MAP[f"{0x90 + i - 1:02x}"] = f"SWAP{i}"

    for i in range(5):
        OPCODE_MAP[f"{0xa0 + i:02x}"] = f"LOG{i}"

    def __init__(self):
        self.instructions: List[EVMInstruction] = []
        self.jump_destinations: Set[int] = set()

    def disassemble(self, bytecode: str) -> List[EVMInstruction]:
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        bytecode = bytecode.lower()
        self.instructions = []
        self.jump_destinations = set()
        i = 0
        address = 0

        while i < len(bytecode):
            opcode_hex = bytecode[i:i+2]
            opcode = self.OPCODE_MAP.get(opcode_hex, f"UNKNOWN_{opcode_hex}")

            if opcode.startswith("PUSH"):
                push_size = int(opcode[4:])
                operand = bytecode[i+2:i+2+(push_size*2)]
                instr = EVMInstruction(opcode, address, operand)
                self.instructions.append(instr)
                i += 2 + (push_size * 2)
                address += 1 + push_size
            else:
                instr = EVMInstruction(opcode, address)
                self.instructions.append(instr)
                if opcode == "JUMPDEST":
                    self.jump_destinations.add(address)
                i += 2
                address += 1

        return self.instructions

    def find_external_calls(self) -> List[Dict]:
        external_calls = []
        dangerous_opcodes = {"CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"}

        for i, instr in enumerate(self.instructions):
            if instr.opcode in dangerous_opcodes:
                context = self._get_instruction_context(i, 5)
                external_calls.append({
                    "address": instr.address,
                    "type": instr.opcode,
                    "context": context,
                })

        return external_calls

    def find_selfdestruct(self) -> List[int]:
        return [instr.address for instr in self.instructions if instr.opcode == "SELFDESTRUCT"]

    def find_sstore_patterns(self) -> List[Dict]:
        sstore_locations = []
        for i, instr in enumerate(self.instructions):
            if instr.opcode == "SSTORE":
                context = self._get_instruction_context(i, 3)
                sstore_locations.append({
                    "address": instr.address,
                    "context": context,
                })
        return sstore_locations

    def find_timestamp_usage(self) -> List[int]:
        return [instr.address for instr in self.instructions if instr.opcode == "TIMESTAMP"]

    def find_origin_usage(self) -> List[int]:
        return [instr.address for instr in self.instructions if instr.opcode == "ORIGIN"]

    def analyze_control_flow(self) -> Dict:
        jumps = []
        for i, instr in enumerate(self.instructions):
            if instr.opcode in ["JUMP", "JUMPI"]:
                if i > 0 and self.instructions[i-1].opcode.startswith("PUSH"):
                    target = int(self.instructions[i-1].operand, 16)
                    jumps.append({
                        "from": instr.address,
                        "to": target,
                        "conditional": instr.opcode == "JUMPI",
                    })

        return {
            "jumps": jumps,
            "jump_destinations": list(self.jump_destinations),
        }

    def _get_instruction_context(self, index: int, window: int = 3) -> List[str]:
        start = max(0, index - window)
        end = min(len(self.instructions), index + window + 1)
        return [str(self.instructions[i]) for i in range(start, end)]

    def detect_reentrancy_pattern(self) -> List[Dict]:
        potential_reentrancy = []

        for i, instr in enumerate(self.instructions):
            if instr.opcode in ["CALL", "DELEGATECALL"]:
                sstore_after = False
                for j in range(i + 1, min(i + 20, len(self.instructions))):
                    if self.instructions[j].opcode == "SSTORE":
                        sstore_after = True
                        potential_reentrancy.append({
                            "call_address": instr.address,
                            "call_type": instr.opcode,
                            "sstore_address": self.instructions[j].address,
                        })
                        break

        return potential_reentrancy

    def extract_function_selectors(self) -> List[str]:
        selectors = []
        for i, instr in enumerate(self.instructions):
            if instr.opcode == "PUSH4" and instr.operand:
                if i + 1 < len(self.instructions) and self.instructions[i + 1].opcode == "EQ":
                    selectors.append(instr.operand)
        return selectors