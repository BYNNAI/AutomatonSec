# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

import re
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
import json


class ContractParser:
    def __init__(self):
        self.pragma_pattern = re.compile(r"pragma\s+solidity\s+([^;]+);")
        self.contract_pattern = re.compile(r"contract\s+(\w+)\s*(?:is\s+([^{]+))?\s*{")
        self.function_pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)\s*(?:(public|private|internal|external))?\s*(?:(view|pure|payable|nonpayable))?[^{]*{"
        )
        self.modifier_pattern = re.compile(r"modifier\s+(\w+)\s*\([^)]*\)")
        self.event_pattern = re.compile(r"event\s+(\w+)\s*\([^)]*\)")
        self.state_var_pattern = re.compile(
            r"^\s*(mapping|uint256|uint|address|bool|string|bytes32)\s+(public|private|internal)?\s+(\w+)"
        )

    def parse_file(self, file_path: str) -> Dict:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Contract file not found: {file_path}")

        source_code = path.read_text(encoding="utf-8")
        return self.parse_source(source_code, str(path))

    def parse_source(self, source_code: str, file_name: str = "<source>") -> Dict:
        result = {
            "file_name": file_name,
            "pragma": self._extract_pragma(source_code),
            "contracts": self._extract_contracts(source_code),
            "imports": self._extract_imports(source_code),
        }
        return result

    def _extract_pragma(self, source: str) -> Optional[str]:
        match = self.pragma_pattern.search(source)
        return match.group(1).strip() if match else None

    def _extract_imports(self, source: str) -> List[str]:
        import_pattern = re.compile(r'import\s+["\']([^"\';]+)["\'];')
        return import_pattern.findall(source)

    def _extract_contracts(self, source: str) -> List[Dict]:
        contracts = []
        for match in self.contract_pattern.finditer(source):
            contract_name = match.group(1)
            inheritance = match.group(2)
            start_pos = match.end()

            contract_body = self._extract_contract_body(source, start_pos)

            contracts.append(
                {
                    "name": contract_name,
                    "inheritance": (
                        [i.strip() for i in inheritance.split(",")]
                        if inheritance
                        else []
                    ),
                    "functions": self._extract_functions(contract_body),
                    "modifiers": self._extract_modifiers(contract_body),
                    "events": self._extract_events(contract_body),
                    "state_variables": self._extract_state_variables(contract_body),
                }
            )

        return contracts

    def _extract_contract_body(self, source: str, start_pos: int) -> str:
        brace_count = 1
        i = start_pos
        while i < len(source) and brace_count > 0:
            if source[i] == "{":
                brace_count += 1
            elif source[i] == "}":
                brace_count -= 1
            i += 1
        return source[start_pos:i]

    def _extract_functions(self, contract_body: str) -> List[Dict]:
        functions = []
        for match in self.function_pattern.finditer(contract_body):
            func_name = match.group(1)
            visibility = match.group(2) or "public"
            state_mutability = match.group(3) or "nonpayable"

            functions.append(
                {
                    "name": func_name,
                    "visibility": visibility,
                    "state_mutability": state_mutability,
                    "modifiers": self._extract_function_modifiers(match.group(0)),
                }
            )

        return functions

    def _extract_function_modifiers(self, func_signature: str) -> List[str]:
        modifier_usage = re.findall(r"\s+(\w+)(?:\([^)]*\))?\s*(?={|$)", func_signature)
        excluded = {"public", "private", "internal", "external", "view", "pure", "payable", "returns"}
        return [m for m in modifier_usage if m not in excluded]

    def _extract_modifiers(self, contract_body: str) -> List[str]:
        return [match.group(1) for match in self.modifier_pattern.finditer(contract_body)]

    def _extract_events(self, contract_body: str) -> List[str]:
        return [match.group(1) for match in self.event_pattern.finditer(contract_body)]

    def _extract_state_variables(self, contract_body: str) -> List[Dict]:
        variables = []
        lines = contract_body.split("\n")

        for line in lines:
            if "function" in line or "modifier" in line or "event" in line:
                continue

            match = self.state_var_pattern.search(line)
            if match:
                var_type = match.group(1)
                visibility = match.group(2) or "internal"
                var_name = match.group(3)
                variables.append(
                    {"name": var_name, "type": var_type, "visibility": visibility}
                )

        return variables

    def extract_external_calls(self, source: str) -> List[Dict]:
        call_patterns = [
            (r"(\w+)\.call\{value:\s*([^}]+)\}\(([^)]*)\)", "call"),
            (r"(\w+)\.delegatecall\(([^)]*)\)", "delegatecall"),
            (r"(\w+)\.transfer\(([^)]*)\)", "transfer"),
            (r"(\w+)\.send\(([^)]*)\)", "send"),
        ]

        calls = []
        for pattern, call_type in call_patterns:
            for match in re.finditer(pattern, source):
                calls.append({"type": call_type, "target": match.group(1), "match": match.group(0)})

        return calls

    def find_loops(self, source: str) -> List[Dict]:
        loop_patterns = [
            r"for\s*\([^)]+\)",
            r"while\s*\([^)]+\)",
            r"do\s*{[^}]*}\s*while\s*\([^)]+\)",
        ]

        loops = []
        for pattern in loop_patterns:
            for match in re.finditer(pattern, source):
                loops.append({"type": "loop", "code": match.group(0)})

        return loops