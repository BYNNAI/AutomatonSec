# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import List, Tuple, Any, Optional, Dict
from collections import defaultdict

logger = logging.getLogger(__name__)


class ConstraintSolver:
    """
    Custom constraint solver for symbolic execution path constraints.
    Integrates with Z3 for SMT solving when available, falls back to heuristics.
    """
    
    def __init__(self):
        self.solver = None
        self.use_z3 = self._init_z3()
        self.cache = {}
        
    def _init_z3(self) -> bool:
        """
        Initialize Z3 solver if available.
        """
        try:
            import z3
            self.solver = z3.Solver()
            logger.info("Z3 solver initialized")
            return True
        except ImportError:
            logger.warning("Z3 not available, using heuristic constraint solving")
            return False
    
    def is_satisfiable(self, constraints: List[Tuple[Any, bool]]) -> bool:
        """
        Check if a set of constraints is satisfiable.
        
        Args:
            constraints: List of (condition, expected_value) tuples
            
        Returns:
            True if constraints are satisfiable, False otherwise
        """
        constraint_hash = hash(str(constraints))
        if constraint_hash in self.cache:
            return self.cache[constraint_hash]
        
        if self.use_z3:
            result = self._solve_with_z3(constraints)
        else:
            result = self._solve_heuristic(constraints)
        
        self.cache[constraint_hash] = result
        return result
    
    def _solve_with_z3(self, constraints: List[Tuple[Any, bool]]) -> bool:
        """
        Use Z3 SMT solver to check constraint satisfiability.
        """
        try:
            import z3
            
            self.solver.reset()
            
            symbolic_vars = {}
            
            for condition, expected in constraints:
                z3_constraint = self._convert_to_z3(condition, symbolic_vars)
                if z3_constraint is not None:
                    if expected:
                        self.solver.add(z3_constraint)
                    else:
                        self.solver.add(z3.Not(z3_constraint))
            
            result = self.solver.check()
            return result == z3.sat
            
        except Exception as e:
            logger.warning(f"Z3 solving failed: {e}, falling back to heuristic")
            return self._solve_heuristic(constraints)
    
    def _convert_to_z3(self, condition: Any, symbolic_vars: Dict):
        """
        Convert a condition to Z3 expression.
        """
        try:
            import z3
            
            if isinstance(condition, str):
                if condition not in symbolic_vars:
                    symbolic_vars[condition] = z3.BitVec(condition, 256)
                return symbolic_vars[condition]
            
            elif isinstance(condition, int):
                return z3.BitVecVal(condition, 256)
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to convert condition to Z3: {e}")
            return None
    
    def _solve_heuristic(self, constraints: List[Tuple[Any, bool]]) -> bool:
        """
        Heuristic-based constraint solving without SMT solver.
        Uses simple rules and assumes most paths are feasible.
        """
        if len(constraints) > 100:
            return False
        
        contradictions = self._find_contradictions(constraints)
        if contradictions:
            return False
        
        return True
    
    def _find_contradictions(self, constraints: List[Tuple[Any, bool]]) -> List:
        """
        Find obvious contradictions in constraints.
        """
        contradictions = []
        constraint_map = defaultdict(list)
        
        for condition, expected in constraints:
            constraint_map[str(condition)].append(expected)
        
        for condition, values in constraint_map.items():
            if True in values and False in values:
                contradictions.append(condition)
        
        return contradictions
    
    def solve_for_input(self, constraints: List[Tuple[Any, bool]]) -> Optional[Dict]:
        """
        Solve constraints to generate concrete input values.
        
        Returns:
            Dict of variable assignments, or None if unsatisfiable
        """
        if not self.is_satisfiable(constraints):
            return None
        
        if self.use_z3:
            return self._get_z3_model(constraints)
        else:
            return self._generate_heuristic_input(constraints)
    
    def _get_z3_model(self, constraints: List[Tuple[Any, bool]]) -> Optional[Dict]:
        """
        Extract concrete values from Z3 model.
        """
        try:
            import z3
            
            self.solver.reset()
            symbolic_vars = {}
            
            for condition, expected in constraints:
                z3_constraint = self._convert_to_z3(condition, symbolic_vars)
                if z3_constraint is not None:
                    if expected:
                        self.solver.add(z3_constraint)
                    else:
                        self.solver.add(z3.Not(z3_constraint))
            
            if self.solver.check() == z3.sat:
                model = self.solver.model()
                result = {}
                for var_name, var in symbolic_vars.items():
                    if model[var] is not None:
                        result[var_name] = model[var].as_long()
                return result
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to extract Z3 model: {e}")
            return None
    
    def _generate_heuristic_input(self, constraints: List[Tuple[Any, bool]]) -> Dict:
        """
        Generate heuristic input values satisfying constraints.
        """
        inputs = {}
        
        for condition, expected in constraints:
            if isinstance(condition, str) and condition.startswith("input_"):
                inputs[condition] = 1 if expected else 0
        
        return inputs
