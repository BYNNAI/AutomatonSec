# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

"""Advanced production-grade vulnerability detectors."""

from .vault_inflation_analyzer import VaultInflationAnalyzer
from .read_only_reentrancy_analyzer import ReadOnlyReentrancyAnalyzer
from .storage_collision_analyzer import StorageCollisionAnalyzer
from .price_manipulation_analyzer import PriceManipulationAnalyzer
from .governance_attack_analyzer import GovernanceAttackAnalyzer
from .unchecked_return_analyzer import UncheckedReturnAnalyzer
from .unsafe_cast_analyzer import UnsafeCastAnalyzer
from .callback_reentrancy_analyzer import CallbackReentrancyAnalyzer
from .rounding_error_analyzer import RoundingErrorAnalyzer

# NEW: 5 stub detectors upgraded to production
from .stale_price_analyzer import StalePriceAnalyzer
from .donation_attack_analyzer import DonationAttackAnalyzer
from .sandwich_attack_analyzer import SandwichAttackAnalyzer
from .oracle_analyzer import OracleAnalyzer
from .jit_liquidity_analyzer import JITLiquidityAnalyzer

__all__ = [
    # Original 9 production detectors
    'VaultInflationAnalyzer',
    'ReadOnlyReentrancyAnalyzer',
    'StorageCollisionAnalyzer',
    'PriceManipulationAnalyzer',
    'GovernanceAttackAnalyzer',
    'UncheckedReturnAnalyzer',
    'UnsafeCastAnalyzer',
    'CallbackReentrancyAnalyzer',
    'RoundingErrorAnalyzer',
    
    # NEW: 5 upgraded detectors
    'StalePriceAnalyzer',        # 75-85%
    'DonationAttackAnalyzer',    # 65-75%
    'SandwichAttackAnalyzer',    # 60-70%
    'OracleAnalyzer',            # 70-80%
    'JITLiquidityAnalyzer',      # 60-70%
]
