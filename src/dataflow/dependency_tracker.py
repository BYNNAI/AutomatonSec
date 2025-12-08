# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class DependencyTracker:
    """
    Tracks data and control dependencies between instructions.
    Used for precise vulnerability detection and exploit chain analysis.
    """
    
    def __init__(self):
        self.data_dependencies = defaultdict(set)
        self.control_dependencies = defaultdict(set)
        
    def analyze_dependencies(self, cfg: Dict, bytecode_analysis: Dict) -> Dict:
        """
        Analyze data and control dependencies.
        
        Args:
            cfg: Control flow graph
            bytecode_analysis: Bytecode analysis results
            
        Returns:
            Dict containing dependency information
        """
        logger.info("Analyzing dependencies")
        
        instructions = bytecode_analysis.get("instructions", [])
        
        self._analyze_data_dependencies(instructions)
        self._analyze_control_dependencies(cfg, instructions)
        
        return {
            "data_dependencies": dict(self.data_dependencies),
            "control_dependencies": dict(self.control_dependencies),
            "dependency_chains": self._find_dependency_chains()
        }
    
    def _analyze_data_dependencies(self, instructions: List[Dict]):
        """
        Analyze data dependencies through stack operations.
        """
        stack_sources = {}
        
        for i, inst in enumerate(instructions):
            pc = inst["pc"]
            opname = inst["opname"]
            
            if opname.startswith('PUSH'):
                stack_sources[i] = {pc}
            
            elif opname.startswith('DUP'):
                dup_pos = int(opname[3:])
                if i >= dup_pos and (i - dup_pos) in stack_sources:
                    stack_sources[i] = stack_sources[i - dup_pos].copy()
                    self.data_dependencies[pc].update(stack_sources[i])
            
            elif opname in ['ADD', 'SUB', 'MUL', 'DIV']:
                deps = set()
                if i > 0 and (i-1) in stack_sources:
                    deps.update(stack_sources[i-1])
                if i > 1 and (i-2) in stack_sources:
                    deps.update(stack_sources[i-2])
                
                if deps:
                    stack_sources[i] = deps
                    self.data_dependencies[pc] = deps
    
    def _analyze_control_dependencies(self, cfg: Dict, instructions: List[Dict]):
        """
        Analyze control dependencies using CFG.
        """
        for edge in cfg.get("edges", []):
            source_pc, target_pc, edge_type = edge
            
            if edge_type in ["jump_true", "jump_false"]:
                self.control_dependencies[target_pc].add(source_pc)
    
    def _find_dependency_chains(self) -> List[List[int]]:
        """
        Find chains of dependent instructions.
        """
        chains = []
        visited = set()
        
        def build_chain(pc: int, current_chain: List[int]):
            if pc in visited or len(current_chain) > 20:
                return
            
            visited.add(pc)
            current_chain.append(pc)
            
            for dep_pc in self.data_dependencies.get(pc, []):
                build_chain(dep_pc, current_chain.copy())
            
            if len(current_chain) > 2:
                chains.append(current_chain)
        
        for pc in self.data_dependencies.keys():
            if pc not in visited:
                build_chain(pc, [])
        
        return chains
