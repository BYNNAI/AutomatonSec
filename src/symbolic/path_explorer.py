# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import deque, defaultdict
import heapq

logger = logging.getLogger(__name__)


class PathExplorer:
    """
    Advanced path exploration strategies for symbolic execution.
    Implements DFS, BFS, and profit-guided search.
    """
    
    def __init__(self, max_depth: int = 128):
        self.max_depth = max_depth
        self.explored_paths = []
        self.coverage_map = set()
        
    def prioritize_paths(self, paths: List[Dict], strategy: str = "profit") -> List[Dict]:
        """
        Prioritize exploration paths based on strategy.
        
        Args:
            paths: List of path dictionaries
            strategy: "profit", "coverage", "depth", or "random"
            
        Returns:
            Sorted list of paths by priority
        """
        if strategy == "profit":
            return self._profit_guided_priority(paths)
        elif strategy == "coverage":
            return self._coverage_guided_priority(paths)
        elif strategy == "depth":
            return sorted(paths, key=lambda p: len(p.get("constraints", [])), reverse=True)
        else:
            return paths
    
    def _profit_guided_priority(self, paths: List[Dict]) -> List[Dict]:
        """
        Prioritize paths that maximize potential profit extraction.
        Focuses on paths with external calls, storage modifications, and value transfers.
        """
        scored_paths = []
        
        for path in paths:
            score = 0
            final_state = path.get("final_state", {})
            
            score += final_state.get("external_calls", 0) * 10
            score += final_state.get("storage_writes", 0) * 5
            
            if final_state.get("reverted", False):
                score -= 20
            
            scored_paths.append((score, path))
        
        scored_paths.sort(reverse=True, key=lambda x: x[0])
        return [path for score, path in scored_paths]
    
    def _coverage_guided_priority(self, paths: List[Dict]) -> List[Dict]:
        """
        Prioritize paths that increase code coverage.
        """
        prioritized = []
        
        for path in paths:
            new_coverage = 0
            constraints = path.get("constraints", [])
            
            for constraint in constraints:
                constraint_hash = hash(str(constraint))
                if constraint_hash not in self.coverage_map:
                    new_coverage += 1
            
            prioritized.append((new_coverage, path))
        
        prioritized.sort(reverse=True, key=lambda x: x[0])
        return [path for score, path in prioritized]
    
    def detect_path_explosion(self, current_paths: int, threshold: int = 10000) -> bool:
        """
        Detect if path explosion is occurring.
        """
        return current_paths > threshold
    
    def merge_similar_paths(self, paths: List[Dict], similarity_threshold: float = 0.8) -> List[Dict]:
        """
        Merge similar execution paths to reduce state space.
        """
        if not paths:
            return []
        
        merged = []
        used = set()
        
        for i, path1 in enumerate(paths):
            if i in used:
                continue
            
            similar_group = [path1]
            
            for j, path2 in enumerate(paths[i+1:], start=i+1):
                if j in used:
                    continue
                
                similarity = self._calculate_path_similarity(path1, path2)
                if similarity >= similarity_threshold:
                    similar_group.append(path2)
                    used.add(j)
            
            merged.append(self._merge_path_group(similar_group))
        
        logger.info(f"Merged {len(paths)} paths into {len(merged)} paths")
        return merged
    
    def _calculate_path_similarity(self, path1: Dict, path2: Dict) -> float:
        """
        Calculate similarity between two paths (0.0 to 1.0).
        """
        constraints1 = set(str(c) for c in path1.get("constraints", []))
        constraints2 = set(str(c) for c in path2.get("constraints", []))
        
        if not constraints1 and not constraints2:
            return 1.0
        
        if not constraints1 or not constraints2:
            return 0.0
        
        intersection = len(constraints1 & constraints2)
        union = len(constraints1 | constraints2)
        
        return intersection / union if union > 0 else 0.0
    
    def _merge_path_group(self, paths: List[Dict]) -> Dict:
        """
        Merge a group of similar paths into a single representative path.
        """
        if len(paths) == 1:
            return paths[0]
        
        representative = paths[0].copy()
        representative["merged_count"] = len(paths)
        
        all_constraints = []
        for path in paths:
            all_constraints.extend(path.get("constraints", []))
        
        representative["constraints"] = all_constraints
        
        return representative
    
    def identify_interesting_paths(self, paths: List[Dict]) -> List[Dict]:
        """
        Identify paths with high exploit potential.
        """
        interesting = []
        
        for path in paths:
            final_state = path.get("final_state", {})
            
            if final_state.get("external_calls", 0) > 1:
                interesting.append({
                    **path,
                    "reason": "multiple_external_calls",
                    "priority": "high"
                })
            
            elif final_state.get("storage_writes", 0) > 5:
                interesting.append({
                    **path,
                    "reason": "extensive_storage_modification",
                    "priority": "medium"
                })
        
        return interesting
