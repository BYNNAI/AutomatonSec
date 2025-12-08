# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import deque
import time

from src.symbolic.constraint_solver import ConstraintSolver
from src.symbolic.path_explorer import PathExplorer
from src.symbolic.evm_state import EVMState

logger = logging.getLogger(__name__)


class SymbolicExecutor:
    """
    Custom symbolic execution engine for EVM bytecode.
    Uses constraint solving to explore execution paths and detect vulnerabilities.
    """
    
    def __init__(self, max_depth: int = 128, timeout: int = 300):
        self.max_depth = max_depth
        self.timeout = timeout
        self.constraint_solver = ConstraintSolver()
        self.path_explorer = PathExplorer(max_depth=max_depth)
        
        self.explored_paths = []
        self.vulnerable_states = []
        
    def execute(self, bytecode_analysis: Dict, cfg: Dict, 
                taint_sinks: Optional[List] = None) -> Dict:
        """
        Perform symbolic execution on bytecode.
        
        Args:
            bytecode_analysis: Disassembled bytecode from BytecodeAnalyzer
            cfg: Control flow graph
            taint_sinks: Tainted data sinks from taint analysis
            
        Returns:
            Dict containing explored paths and detected vulnerabilities
        """
        logger.info("Starting symbolic execution")
        start_time = time.time()
        
        instructions = bytecode_analysis.get("instructions", [])
        if not instructions:
            return {"explored_paths": [], "vulnerable_states": []}
        
        initial_state = EVMState()
        work_queue = deque([(initial_state, 0, [])])
        
        visited_states = set()
        path_count = 0
        
        while work_queue and (time.time() - start_time) < self.timeout:
            if len(self.explored_paths) >= 10000:
                logger.warning("Maximum path limit reached")
                break
            
            current_state, pc, path_constraints = work_queue.popleft()
            
            state_hash = self._hash_state(current_state, pc)
            if state_hash in visited_states:
                continue
            visited_states.add(state_hash)
            
            if pc >= len(instructions):
                self.explored_paths.append({
                    "path_id": path_count,
                    "constraints": path_constraints,
                    "final_state": current_state.to_dict()
                })
                path_count += 1
                continue
            
            if len(path_constraints) > self.max_depth:
                continue
            
            instruction = instructions[pc]
            next_states = self._execute_instruction(current_state, instruction, path_constraints)
            
            for next_state, new_pc, new_constraints in next_states:
                if self._is_vulnerable_state(next_state, instruction, taint_sinks):
                    self.vulnerable_states.append({
                        "pc": pc,
                        "instruction": instruction,
                        "state": next_state.to_dict(),
                        "constraints": new_constraints,
                        "vulnerability_type": self._classify_vulnerability(next_state, instruction)
                    })
                
                work_queue.append((next_state, new_pc, new_constraints))
        
        logger.info(f"Symbolic execution complete: {len(self.explored_paths)} paths, "
                   f"{len(self.vulnerable_states)} vulnerable states")
        
        return {
            "explored_paths": self.explored_paths,
            "vulnerable_states": self.vulnerable_states,
            "interesting_paths": self._rank_interesting_paths(),
            "coverage": len(visited_states) / len(instructions) if instructions else 0
        }
    
    def _execute_instruction(self, state: EVMState, instruction: Dict, 
                            constraints: List) -> List[Tuple[EVMState, int, List]]:
        """
        Symbolically execute a single EVM instruction.
        Returns list of (next_state, next_pc, new_constraints) tuples.
        """
        opname = instruction["opname"]
        pc = instruction["pc"]
        
        next_states = []
        
        if opname == 'JUMPI':
            if len(state.stack) >= 2:
                condition = state.stack[-2]
                
                true_state = state.copy()
                true_constraints = constraints + [(condition, True)]
                if self.constraint_solver.is_satisfiable(true_constraints):
                    jump_target = int(state.stack[-1]) if isinstance(state.stack[-1], (int, str)) else 0
                    true_state.stack = true_state.stack[:-2]
                    next_states.append((true_state, jump_target, true_constraints))
                
                false_state = state.copy()
                false_constraints = constraints + [(condition, False)]
                if self.constraint_solver.is_satisfiable(false_constraints):
                    false_state.stack = false_state.stack[:-2]
                    next_states.append((false_state, pc + 1, false_constraints))
        
        elif opname == 'JUMP':
            if state.stack:
                jump_target = int(state.stack[-1]) if isinstance(state.stack[-1], (int, str)) else pc + 1
                new_state = state.copy()
                new_state.stack = new_state.stack[:-1]
                next_states.append((new_state, jump_target, constraints))
        
        elif opname in ['CALL', 'DELEGATECALL', 'STATICCALL']:
            new_state = state.copy()
            new_state.external_calls.append({
                "pc": pc,
                "call_type": opname,
                "gas": state.stack[-1] if state.stack else None
            })
            next_states.append((new_state, pc + 1, constraints))
        
        elif opname == 'SSTORE':
            if len(state.stack) >= 2:
                new_state = state.copy()
                key = state.stack[-1]
                value = state.stack[-2]
                new_state.storage[key] = value
                new_state.stack = new_state.stack[:-2]
                next_states.append((new_state, pc + 1, constraints))
        
        elif opname == 'SLOAD':
            if state.stack:
                new_state = state.copy()
                key = state.stack[-1]
                value = new_state.storage.get(key, 0)
                new_state.stack = new_state.stack[:-1] + [value]
                next_states.append((new_state, pc + 1, constraints))
        
        else:
            new_state = self._execute_generic_instruction(state, instruction)
            next_states.append((new_state, pc + 1, constraints))
        
        return next_states
    
    def _execute_generic_instruction(self, state: EVMState, instruction: Dict) -> EVMState:
        """
        Execute generic stack/memory operations.
        """
        new_state = state.copy()
        opname = instruction["opname"]
        
        if opname.startswith('PUSH'):
            operand = instruction.get("operand", "0")
            new_state.stack.append(int(operand, 16) if operand else 0)
        
        elif opname.startswith('DUP'):
            dup_pos = int(opname[3:])
            if len(new_state.stack) >= dup_pos:
                new_state.stack.append(new_state.stack[-dup_pos])
        
        elif opname.startswith('SWAP'):
            swap_pos = int(opname[4:])
            if len(new_state.stack) > swap_pos:
                new_state.stack[-1], new_state.stack[-swap_pos-1] = \
                    new_state.stack[-swap_pos-1], new_state.stack[-1]
        
        elif opname == 'POP' and new_state.stack:
            new_state.stack = new_state.stack[:-1]
        
        elif opname in ['ADD', 'SUB', 'MUL', 'DIV']:
            if len(new_state.stack) >= 2:
                new_state.stack = new_state.stack[:-2] + [f"({opname.lower()})"]
        
        return new_state
    
    def _is_vulnerable_state(self, state: EVMState, instruction: Dict, 
                            taint_sinks: Optional[List]) -> bool:
        """
        Check if current state represents a potential vulnerability.
        """
        opname = instruction["opname"]
        
        if opname in ['CALL', 'DELEGATECALL'] and state.external_calls:
            if len(state.external_calls) > 1:
                return True
        
        if opname == 'SELFDESTRUCT':
            return True
        
        if taint_sinks and instruction["pc"] in [sink.get("pc") for sink in taint_sinks]:
            return True
        
        return False
    
    def _classify_vulnerability(self, state: EVMState, instruction: Dict) -> str:
        """
        Classify the type of vulnerability detected.
        """
        opname = instruction["opname"]
        
        if opname in ['CALL', 'DELEGATECALL'] and len(state.external_calls) > 1:
            return "POTENTIAL_REENTRANCY"
        
        if opname == 'SELFDESTRUCT':
            return "UNPROTECTED_SELFDESTRUCT"
        
        return "UNKNOWN_VULNERABILITY"
    
    def _rank_interesting_paths(self) -> List[Dict]:
        """
        Rank paths by potential for exploitation.
        """
        ranked = sorted(
            self.explored_paths,
            key=lambda p: len(p.get("constraints", [])),
            reverse=True
        )
        return ranked[:100]
    
    def _hash_state(self, state: EVMState, pc: int) -> str:
        """
        Create hash of state for deduplication.
        """
        return f"{pc}_{hash(str(state.stack))}_{hash(str(state.storage))}"
