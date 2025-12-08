# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import re
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ContractParser:
    """
    Advanced Solidity contract parser with AST generation.
    Extracts functions, state variables, modifiers, and dependencies.
    """
    
    def __init__(self):
        self.ast = None
        self.functions = []
        self.state_vars = []
        self.modifiers = []
        
    def parse(self, source_code: str) -> Dict:
        """
        Parse Solidity source code into structured representation.
        
        Args:
            source_code: Solidity source code string
            
        Returns:
            Dict containing parsed contract components
        """
        logger.info("Parsing contract source code")
        
        self.functions = self._extract_functions(source_code)
        self.state_vars = self._extract_state_variables(source_code)
        self.modifiers = self._extract_modifiers(source_code)
        imports = self._extract_imports(source_code)
        
        return {
            "functions": self.functions,
            "state_variables": self.state_vars,
            "modifiers": self.modifiers,
            "imports": imports,
            "bytecode": None
        }
    
    def _extract_functions(self, source: str) -> List[Dict]:
        """
        Extract all function definitions with visibility, modifiers, and parameters.
        """
        functions = []
        
        function_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(\w+\s*)*\s*(?:returns\s*\(([^)]*)\))?'
        
        matches = re.finditer(function_pattern, source)
        for match in matches:
            func_name = match.group(1)
            params = match.group(2)
            visibility = match.group(3) or "public"
            state_mutability = match.group(4)
            modifiers = match.group(5)
            returns = match.group(6)
            
            functions.append({
                "name": func_name,
                "parameters": self._parse_parameters(params),
                "visibility": visibility,
                "state_mutability": state_mutability,
                "modifiers": modifiers.strip().split() if modifiers else [],
                "returns": self._parse_parameters(returns) if returns else []
            })
        
        return functions
    
    def _extract_state_variables(self, source: str) -> List[Dict]:
        """
        Extract state variable declarations.
        """
        state_vars = []
        
        var_pattern = r'(\w+)(?:\[\])?\s+(public|private|internal)?\s+(\w+)'
        
        in_contract = False
        for line in source.split('\n'):
            line = line.strip()
            if 'contract ' in line and '{' in line:
                in_contract = True
                continue
            if in_contract and not line.startswith('function') and not line.startswith('//'):
                match = re.match(var_pattern, line)
                if match:
                    var_type = match.group(1)
                    visibility = match.group(2) or "internal"
                    var_name = match.group(3)
                    
                    state_vars.append({
                        "name": var_name,
                        "type": var_type,
                        "visibility": visibility
                    })
        
        return state_vars
    
    def _extract_modifiers(self, source: str) -> List[Dict]:
        """
        Extract modifier definitions.
        """
        modifiers = []
        
        modifier_pattern = r'modifier\s+(\w+)\s*\(([^)]*)\)'
        
        matches = re.finditer(modifier_pattern, source)
        for match in matches:
            modifiers.append({
                "name": match.group(1),
                "parameters": self._parse_parameters(match.group(2))
            })
        
        return modifiers
    
    def _extract_imports(self, source: str) -> List[str]:
        """
        Extract import statements.
        """
        imports = []
        import_pattern = r'import\s+["\']([^"\']+)["\']'
        
        matches = re.finditer(import_pattern, source)
        for match in matches:
            imports.append(match.group(1))
        
        return imports
    
    def _parse_parameters(self, params_str: str) -> List[Dict]:
        """
        Parse function parameters into structured format.
        """
        if not params_str or not params_str.strip():
            return []
        
        parameters = []
        param_list = params_str.split(',')
        
        for param in param_list:
            param = param.strip()
            if param:
                parts = param.split()
                if len(parts) >= 2:
                    param_type = ' '.join(parts[:-1])
                    param_name = parts[-1]
                    parameters.append({
                        "type": param_type,
                        "name": param_name
                    })
        
        return parameters
