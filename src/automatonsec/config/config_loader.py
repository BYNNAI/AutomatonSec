# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
import yaml


@dataclass
class AnalysisConfig:
    parallel_workers: int = 8
    timeout: int = 300
    max_memory_mb: int = 4096

    symbolic_execution_enabled: bool = True
    symbolic_max_depth: int = 10
    symbolic_max_paths: int = 1000
    solver_timeout: int = 30
    path_pruning: bool = True

    data_flow_enabled: bool = True
    inter_procedural: bool = True
    cross_contract: bool = True
    taint_sources: List[str] = field(
        default_factory=lambda: [
            "msg.sender",
            "msg.value",
            "tx.origin",
            "block.timestamp",
            "block.number",
        ]
    )
    taint_sinks: List[str] = field(
        default_factory=lambda: ["call", "delegatecall", "transfer", "send", "selfdestruct"]
    )

    fuzzing_enabled: bool = True
    fuzzing_iterations: int = 10000
    mutation_rate: float = 0.3
    profit_guided: bool = True
    coverage_guided: bool = True

    ml_enabled: bool = True
    anomaly_threshold: float = 0.85
    embedding_dim: int = 768

    build_cfg: bool = True
    detect_loops: bool = True
    max_loop_iterations: int = 100

    report_format: str = "json"
    include_source: bool = True
    include_exploits: bool = True
    confidence_threshold: float = 0.7

    cache_results: bool = True
    incremental_analysis: bool = True
    parallel_detectors: bool = True

    log_level: str = "INFO"
    log_file: str = "logs/automatonsec.log"


def load_config(config_path: Optional[str] = None) -> AnalysisConfig:
    if config_path is None:
        return AnalysisConfig()

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    config = AnalysisConfig()

    if "engine" in data:
        engine = data["engine"]
        config.parallel_workers = engine.get("parallel_workers", config.parallel_workers)
        config.timeout = engine.get("timeout", config.timeout)
        config.max_memory_mb = engine.get("max_memory_mb", config.max_memory_mb)

    if "symbolic_execution" in data:
        sym = data["symbolic_execution"]
        config.symbolic_execution_enabled = sym.get("enabled", config.symbolic_execution_enabled)
        config.symbolic_max_depth = sym.get("max_depth", config.symbolic_max_depth)
        config.symbolic_max_paths = sym.get("max_paths", config.symbolic_max_paths)
        config.solver_timeout = sym.get("solver_timeout", config.solver_timeout)
        config.path_pruning = sym.get("path_pruning", config.path_pruning)

    if "data_flow" in data:
        df = data["data_flow"]
        config.data_flow_enabled = df.get("enabled", config.data_flow_enabled)
        config.inter_procedural = df.get("inter_procedural", config.inter_procedural)
        config.cross_contract = df.get("cross_contract", config.cross_contract)
        config.taint_sources = df.get("taint_sources", config.taint_sources)
        config.taint_sinks = df.get("taint_sinks", config.taint_sinks)

    if "fuzzing" in data:
        fuzz = data["fuzzing"]
        config.fuzzing_enabled = fuzz.get("enabled", config.fuzzing_enabled)
        config.fuzzing_iterations = fuzz.get("iterations", config.fuzzing_iterations)
        config.mutation_rate = fuzz.get("mutation_rate", config.mutation_rate)
        config.profit_guided = fuzz.get("profit_guided", config.profit_guided)
        config.coverage_guided = fuzz.get("coverage_guided", config.coverage_guided)

    if "reporting" in data:
        rep = data["reporting"]
        config.report_format = rep.get("format", config.report_format)
        config.include_source = rep.get("include_source", config.include_source)
        config.include_exploits = rep.get("include_exploits", config.include_exploits)
        config.confidence_threshold = rep.get("confidence_threshold", config.confidence_threshold)

    return config