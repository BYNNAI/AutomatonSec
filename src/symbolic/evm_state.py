# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

from typing import Dict, List, Any, Optional
from copy import deepcopy


class EVMState:
    """
    Represents the complete EVM execution state during symbolic execution.
    Tracks stack, memory, storage, and execution context.
    """
    
    def __init__(self):
        self.stack: List[Any] = []
        self.memory: Dict[int, Any] = {}
        self.storage: Dict[Any, Any] = {}
        self.balance: int = 0
        self.pc: int = 0
        self.gas: int = 1000000
        
        self.call_stack: List[Dict] = []
        self.external_calls: List[Dict] = []
        self.storage_writes: List[Dict] = []
        
        self.msg_sender: str = "symbolic_sender"
        self.msg_value: int = 0
        self.block_timestamp: int = 0
        self.block_number: int = 0
        
        self.returndata: bytes = b""
        self.reverted: bool = False
        
    def copy(self) -> 'EVMState':
        """
        Create a deep copy of the current state.
        """
        new_state = EVMState()
        new_state.stack = self.stack.copy()
        new_state.memory = self.memory.copy()
        new_state.storage = deepcopy(self.storage)
        new_state.balance = self.balance
        new_state.pc = self.pc
        new_state.gas = self.gas
        new_state.call_stack = deepcopy(self.call_stack)
        new_state.external_calls = deepcopy(self.external_calls)
        new_state.storage_writes = deepcopy(self.storage_writes)
        new_state.msg_sender = self.msg_sender
        new_state.msg_value = self.msg_value
        new_state.block_timestamp = self.block_timestamp
        new_state.block_number = self.block_number
        new_state.returndata = self.returndata
        new_state.reverted = self.reverted
        return new_state
    
    def to_dict(self) -> Dict:
        """
        Convert state to dictionary representation.
        """
        return {
            "stack": self.stack[:10],
            "storage_keys": len(self.storage),
            "external_calls": len(self.external_calls),
            "storage_writes": len(self.storage_writes),
            "gas_used": 1000000 - self.gas,
            "reverted": self.reverted
        }
    
    def add_external_call(self, call_type: str, target: Any, value: Any, data: Any):
        """
        Record an external call.
        """
        self.external_calls.append({
            "type": call_type,
            "target": target,
            "value": value,
            "data": data,
            "depth": len(self.call_stack)
        })
    
    def add_storage_write(self, key: Any, value: Any):
        """
        Record a storage write operation.
        """
        self.storage_writes.append({
            "key": key,
            "value": value,
            "pc": self.pc
        })
    
    def enter_call(self, call_type: str, target: Any):
        """
        Enter a new call context.
        """
        self.call_stack.append({
            "type": call_type,
            "target": target,
            "pc": self.pc
        })
    
    def exit_call(self):
        """
        Exit current call context.
        """
        if self.call_stack:
            self.call_stack.pop()
