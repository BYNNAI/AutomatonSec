# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(Enum):
    REENTRANCY = "reentrancy"
    CROSS_FUNCTION_REENTRANCY = "cross_function_reentrancy"
    READ_ONLY_REENTRANCY = "read_only_reentrancy"
    FLASHLOAN_ATTACK = "flashloan_attack"
    ACCESS_CONTROL = "access_control"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    ORACLE_MANIPULATION = "oracle_manipulation"
    PRICE_MANIPULATION = "price_manipulation"
    VAULT_INFLATION = "vault_inflation"
    DONATION_ATTACK = "donation_attack"
    ROUNDING_ERROR = "rounding_error"
    STORAGE_COLLISION = "storage_collision"
    SELECTOR_COLLISION = "selector_collision"
    UNCHECKED_RETURN = "unchecked_return"
    UNSAFE_CAST = "unsafe_cast"
    SIGNATURE_MALLEABILITY = "signature_malleability"
    PERMIT_FRONTRUN = "permit_frontrun"
    GOVERNANCE_ATTACK = "governance_attack"
    SANDWICH_ATTACK = "sandwich_attack"
    JIT_LIQUIDITY = "jit_liquidity"
    CALLBACK_REENTRANCY = "callback_reentrancy"
    MULTI_TOKEN_ACCOUNTING = "multi_token_accounting"
    STALE_PRICE = "stale_price"
    SLIPPAGE_MANIPULATION = "slippage_manipulation"
    REBASING_TOKEN = "rebasing_token"
    FRONTRUNNING = "frontrunning"
    DELEGATECALL_INJECTION = "delegatecall_injection"
    UNPROTECTED_SELFDESTRUCT = "unprotected_selfdestruct"
    UNCHECKED_CALL = "unchecked_call"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    TX_ORIGIN_AUTH = "tx_origin_auth"
    LOGIC_BUG = "logic_bug"
    STATE_VARIABLE_SHADOWING = "state_variable_shadowing"


@dataclass
class SourceLocation:
    file: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    function: Optional[str] = None

    def __str__(self) -> str:
        if self.function:
            return f"{self.file}:{self.line_start}:{self.column_start} in {self.function}()"
        return f"{self.file}:{self.line_start}:{self.column_start}"


@dataclass
class Exploit:
    description: str
    attack_vector: str
    profit_estimate: float
    transaction_sequence: List[Dict[str, Any]]
    proof_of_concept: Optional[str] = None


@dataclass
class Vulnerability:
    type: VulnerabilityType
    severity: Severity
    name: str
    description: str
    location: SourceLocation
    confidence: float
    impact: str
    recommendation: str
    exploit: Optional[Exploit] = None
    cross_contract: bool = False
    affected_contracts: List[str] = field(default_factory=list)
    technical_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "name": self.name,
            "description": self.description,
            "location": str(self.location),
            "confidence": self.confidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "cross_contract": self.cross_contract,
            "affected_contracts": self.affected_contracts,
            "technical_details": self.technical_details,
        }


@dataclass
class AnalysisResult:
    contract_name: str
    contract_address: Optional[str]
    vulnerabilities: List[Vulnerability]
    analysis_time: float
    timestamp: datetime
    engine_version: str
    total_functions: int
    analyzed_paths: int
    coverage: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_critical(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]

    def get_high(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == Severity.HIGH]

    def get_by_type(self, vuln_type: VulnerabilityType) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.type == vuln_type]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_name": self.contract_name,
            "contract_address": self.contract_address,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "analysis_time": self.analysis_time,
            "timestamp": self.timestamp.isoformat(),
            "engine_version": self.engine_version,
            "statistics": {
                "total_functions": self.total_functions,
                "analyzed_paths": self.analyzed_paths,
                "coverage": self.coverage,
            },
            "metadata": self.metadata,
        }


@dataclass
class ContractInfo:
    name: str
    source_code: str
    bytecode: Optional[str] = None
    abi: Optional[List[Dict]] = None
    compiler_version: Optional[str] = None
    optimization_enabled: bool = False
    functions: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
