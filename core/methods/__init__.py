"""
Injection method modules for pySIDHistory.

Provides two injection methods:
- DSInternals: Offline ntds.dit modification via PowerShell/SCMR
- DRSUAPI: DRSAddSidHistory cross-forest injection
"""

from .dsinternals import DSInternalsInjector
from .drsuapi import DRSUAPIClient

__all__ = [
    'DSInternalsInjector',
    'DRSUAPIClient',
]
