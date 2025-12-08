# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class BasicBlock:
    """
    Represents a basic block in the control flow graph.
    """
    
    def __init__(self, start_pc: int, end_pc: int):
        self.start_pc = start_pc
        self.end_pc = end_pc
        self.instructions = []
        self.successors = []
        self.predecessors = []
        self.dominators = set()
        
    def add_instruction(self, instruction: Dict):
        self.instructions.append(instruction)
    
    def add_successor(self, block: 'BasicBlock'):
        if block not in self.successors:
            self.successors.append(block)
            block.predecessors.append(self)
    
    def __repr__(self):
        return f"BasicBlock({self.start_pc}-{self.end_pc})"


class CFGBuilder:
    """
    Control Flow Graph builder for EVM bytecode.
    Constructs CFG with basic blocks, edges, and dominance analysis.
    """
    
    def __init__(self):
        self.basic_blocks = {}
        self.entry_block = None
        self.edges = []
        
    def build(self, bytecode_analysis: Dict) -> Dict:
        """
        Build control flow graph from bytecode analysis.
        
        Args:
            bytecode_analysis: Output from BytecodeAnalyzer
            
        Returns:
            Dict containing CFG structure and analysis
        """
        instructions = bytecode_analysis.get("instructions", [])
        jump_dests = set(bytecode_analysis.get("jump_destinations", []))
        
        if not instructions:
            return {"basic_blocks": [], "edges": [], "entry": None}
        
        logger.info("Building control flow graph")
        
        self.basic_blocks = self._identify_basic_blocks(instructions, jump_dests)
        
        self._connect_blocks(instructions)
        
        self._compute_dominance()
        
        loops = self._detect_loops()
        
        return {
            "basic_blocks": {pc: self._block_to_dict(block) 
                           for pc, block in self.basic_blocks.items()},
            "edges": self.edges,
            "entry": self.entry_block.start_pc if self.entry_block else None,
            "loops": loops,
            "complexity": self._calculate_cyclomatic_complexity()
        }
    
    def _identify_basic_blocks(self, instructions: List[Dict], 
                               jump_dests: Set[int]) -> Dict[int, BasicBlock]:
        """
        Identify basic block boundaries.
        """
        blocks = {}
        block_starts = {0}
        
        block_starts.update(jump_dests)
        
        for i, inst in enumerate(instructions):
            if inst["opname"] in ['JUMP', 'JUMPI', 'RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT']:
                if i + 1 < len(instructions):
                    block_starts.add(instructions[i + 1]["pc"])
        
        block_starts_list = sorted(block_starts)
        
        for i, start_pc in enumerate(block_starts_list):
            end_pc = block_starts_list[i + 1] if i + 1 < len(block_starts_list) else instructions[-1]["pc"]
            
            block = BasicBlock(start_pc, end_pc)
            
            for inst in instructions:
                if start_pc <= inst["pc"] < end_pc:
                    block.add_instruction(inst)
            
            blocks[start_pc] = block
        
        if 0 in blocks:
            self.entry_block = blocks[0]
        
        logger.info(f"Identified {len(blocks)} basic blocks")
        return blocks
    
    def _connect_blocks(self, instructions: List[Dict]):
        """
        Connect basic blocks with edges based on control flow.
        """
        for block in self.basic_blocks.values():
            if not block.instructions:
                continue
            
            last_inst = block.instructions[-1]
            opname = last_inst["opname"]
            
            if opname == 'JUMP':
                if last_inst.get("operand"):
                    target = int(last_inst["operand"], 16)
                    if target in self.basic_blocks:
                        block.add_successor(self.basic_blocks[target])
                        self.edges.append((block.start_pc, target, "jump"))
            
            elif opname == 'JUMPI':
                if last_inst.get("operand"):
                    target = int(last_inst["operand"], 16)
                    if target in self.basic_blocks:
                        block.add_successor(self.basic_blocks[target])
                        self.edges.append((block.start_pc, target, "jump_true"))
                
                next_pc = last_inst["pc"] + 1
                next_block = self._find_block_containing(next_pc)
                if next_block:
                    block.add_successor(next_block)
                    self.edges.append((block.start_pc, next_block.start_pc, "jump_false"))
            
            elif opname not in ['RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT']:
                next_pc = last_inst["pc"] + 1
                next_block = self._find_block_containing(next_pc)
                if next_block:
                    block.add_successor(next_block)
                    self.edges.append((block.start_pc, next_block.start_pc, "fallthrough"))
        
        logger.info(f"Created {len(self.edges)} control flow edges")
    
    def _find_block_containing(self, pc: int) -> Optional[BasicBlock]:
        """
        Find the basic block containing a given program counter.
        """
        for block in self.basic_blocks.values():
            if block.start_pc <= pc <= block.end_pc:
                return block
        return None
    
    def _compute_dominance(self):
        """
        Compute dominator sets for all basic blocks.
        """
        if not self.entry_block:
            return
        
        all_blocks = set(self.basic_blocks.values())
        
        for block in self.basic_blocks.values():
            block.dominators = all_blocks.copy()
        
        self.entry_block.dominators = {self.entry_block}
        
        changed = True
        iterations = 0
        max_iterations = len(all_blocks) * 10
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for block in self.basic_blocks.values():
                if block == self.entry_block:
                    continue
                
                if not block.predecessors:
                    continue
                
                new_dominators = all_blocks.copy()
                for pred in block.predecessors:
                    new_dominators &= pred.dominators
                
                new_dominators.add(block)
                
                if new_dominators != block.dominators:
                    block.dominators = new_dominators
                    changed = True
        
        logger.info(f"Dominator analysis completed in {iterations} iterations")
    
    def _detect_loops(self) -> List[Dict]:
        """
        Detect loops in the control flow graph using back edges.
        """
        loops = []
        
        visited = set()
        rec_stack = set()
        
        def dfs_detect_cycle(block: BasicBlock, path: List[BasicBlock]):
            visited.add(block)
            rec_stack.add(block)
            path.append(block)
            
            for successor in block.successors:
                if successor not in visited:
                    dfs_detect_cycle(successor, path.copy())
                elif successor in rec_stack:
                    loop_start_idx = path.index(successor)
                    loop_blocks = path[loop_start_idx:]
                    loops.append({
                        "header": successor.start_pc,
                        "blocks": [b.start_pc for b in loop_blocks],
                        "back_edge": (block.start_pc, successor.start_pc)
                    })
            
            rec_stack.remove(block)
        
        if self.entry_block:
            dfs_detect_cycle(self.entry_block, [])
        
        logger.info(f"Detected {len(loops)} loops")
        return loops
    
    def _calculate_cyclomatic_complexity(self) -> int:
        """
        Calculate cyclomatic complexity: E - N + 2P
        E = number of edges, N = number of nodes, P = number of connected components
        """
        E = len(self.edges)
        N = len(self.basic_blocks)
        P = 1
        
        complexity = E - N + 2 * P
        return max(1, complexity)
    
    def _block_to_dict(self, block: BasicBlock) -> Dict:
        """
        Convert basic block to dictionary representation.
        """
        return {
            "start_pc": block.start_pc,
            "end_pc": block.end_pc,
            "instruction_count": len(block.instructions),
            "successors": [s.start_pc for s in block.successors],
            "predecessors": [p.start_pc for p in block.predecessors],
            "dominator_count": len(block.dominators)
        }
