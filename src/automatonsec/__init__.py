# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

"""AutomatonSec - Advanced Smart Contract Security Analysis Engine"""

__version__ = "1.0.0"
__author__ = "BYNNΛI"

from automatonsec.core.engine import SecurityEngine
from automatonsec.core.models import (
    AnalysisResult,
    Vulnerability,
    Severity,
    VulnerabilityType,
)
from automatonsec.config.config_loader import AnalysisConfig

__all__ = [
    "SecurityEngine",
    "AnalysisResult",
    "Vulnerability",
    "Severity",
    "VulnerabilityType",
    "AnalysisConfig",
]