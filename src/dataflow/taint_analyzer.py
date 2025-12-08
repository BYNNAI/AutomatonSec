# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    """
    Advanced taint analysis for tracking data flow from sources to sinks.
    Detects when untrusted input reaches sensitive operations.
    """
    
    TAINT_SOURCES = [
        'CALLDATALOAD', 'CALLDATACOPY', 'CALLER', 'ORIGIN',
        'CALLVALUE', 'GASPRICE', 'BLOCKHASH', 'TIMESTAMP',
        'NUMBER', 'COINBASE', 'DIFFICULTY'
    ]
    
    TAINT_SINKS = [
        'CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE',
        'SSTORE', 'SELFDESTRUCT', 'CREATE', 'CREATE2'
    ]
    
    def __init__(self):
        self.taint_map = defaultdict(set)
        self.sources = []
        self.sinks = []
        self.taint_flows = []
        
    def analyze(self, cfg: Dict, bytecode_analysis: Dict) -> Dict:
        """
        Perform inter-procedural taint analysis.
        
        Args:
            cfg: Control flow graph from CFGBuilder
            bytecode_analysis: Bytecode analysis results
            
        Returns:
            Dict containing taint sources, sinks, and flows
        """
        logger.info("Starting taint analysis")
        
        instructions = bytecode_analysis.get("instructions", [])
        
        self._identify_sources_and_sinks(instructions)
        
        self._propagate_taint(instructions, cfg)
        
        self._detect_taint_flows()
        
        return {
            "sources": self.sources,
            "sinks": self.sinks,
            "taint_flows": self.taint_flows,
            "vulnerable_flows": self._classify_vulnerable_flows()
        }
    
    def _identify_sources_and_sinks(self, instructions: List[Dict]):
        """
        Identify taint sources and sinks in the bytecode.
        """
        for inst in instructions:
            opname = inst["opname"]
            pc = inst["pc"]
            
            if opname in self.TAINT_SOURCES:
                self.sources.append({
                    "pc": pc,
                    "type": opname,
                    "taint_id": f"source_{pc}"
                })
                self.taint_map[pc].add(f"source_{pc}")
            
            if opname in self.TAINT_SINKS:
                self.sinks.append({
                    "pc": pc,
                    "type": opname,
                    "criticality": self._assess_sink_criticality(opname)
                })
        
        logger.info(f"Found {len(self.sources)} taint sources and {len(self.sinks)} taint sinks")
    
    def _propagate_taint(self, instructions: List[Dict], cfg: Dict):
        """
        Propagate taint information through the program using data flow analysis.
        """
        max_iterations = 100
        iteration = 0
        changed = True
        
        while changed and iteration < max_iterations:
            changed = False
            iteration += 1
            
            for inst in instructions:
                pc = inst["pc"]
                opname = inst["opname"]
                
                old_taint = self.taint_map[pc].copy()
                
                if opname in self.TAINT_SOURCES:
                    self.taint_map[pc].add(f"source_{pc}")
                
                elif opname.startswith('DUP'):
                    dup_pos = int(opname[3:])
                    if pc > dup_pos:
                        self.taint_map[pc].update(self.taint_map[pc - dup_pos])
                
                elif opname in ['ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'EXP']:
                    if pc > 0:
                        self.taint_map[pc].update(self.taint_map[pc - 1])
                        if pc > 1:
                            self.taint_map[pc].update(self.taint_map[pc - 2])
                
                elif opname in ['AND', 'OR', 'XOR']:
                    if pc > 0:
                        self.taint_map[pc].update(self.taint_map[pc - 1])
                        if pc > 1:
                            self.taint_map[pc].update(self.taint_map[pc - 2])
                
                elif opname == 'SLOAD':
                    if pc > 0:
                        self.taint_map[pc].update(self.taint_map[pc - 1])
                
                if self.taint_map[pc] != old_taint:
                    changed = True
        
        logger.info(f"Taint propagation completed in {iteration} iterations")
    
    def _detect_taint_flows(self):
        """
        Detect taint flows from sources to sinks.
        """
        for sink in self.sinks:
            sink_pc = sink["pc"]
            sink_taints = self.taint_map[sink_pc]
            
            if sink_taints:
                for taint_id in sink_taints:
                    source_pc = int(taint_id.split("_")[1]) if "_" in taint_id else -1
                    
                    self.taint_flows.append({
                        "source_pc": source_pc,
                        "sink_pc": sink_pc,
                        "sink_type": sink["type"],
                        "taint_id": taint_id,
                        "severity": self._calculate_flow_severity(sink)
                    })
        
        logger.info(f"Detected {len(self.taint_flows)} taint flows")
    
    def _assess_sink_criticality(self, opname: str) -> str:
        """
        Assess the criticality of a taint sink.
        """
        critical_sinks = ['DELEGATECALL', 'SELFDESTRUCT', 'CALL']
        high_sinks = ['SSTORE', 'CREATE', 'CREATE2']
        
        if opname in critical_sinks:
            return "CRITICAL"
        elif opname in high_sinks:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _calculate_flow_severity(self, sink: Dict) -> str:
        """
        Calculate severity of a taint flow.
        """
        return sink.get("criticality", "MEDIUM")
    
    def _classify_vulnerable_flows(self) -> List[Dict]:
        """
        Classify vulnerable taint flows by vulnerability type.
        """
        vulnerable = []
        
        for flow in self.taint_flows:
            sink_type = flow["sink_type"]
            
            if sink_type in ['CALL', 'DELEGATECALL']:
                vulnerable.append({
                    **flow,
                    "vulnerability_type": "UNCONTROLLED_EXTERNAL_CALL",
                    "severity": "HIGH"
                })
            
            elif sink_type == 'SELFDESTRUCT':
                vulnerable.append({
                    **flow,
                    "vulnerability_type": "UNPROTECTED_SELFDESTRUCT",
                    "severity": "CRITICAL"
                })
            
            elif sink_type == 'SSTORE':
                vulnerable.append({
                    **flow,
                    "vulnerability_type": "UNVALIDATED_STORAGE_WRITE",
                    "severity": "MEDIUM"
                })
        
        return vulnerable
