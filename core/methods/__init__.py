"""
Injection method modules for pySIDHistory.

Provides three distinct injection methods:
- DSInternals: Offline ntds.dit modification via PowerShell/SCMR
- DRSUAPI: DRSAddSidHistory cross-forest injection
- DCShadow: AD replication-based injection via rogue DC
"""

from .dsinternals import DSInternalsInjector
from .drsuapi import DRSUAPIClient
from .dcshadow import DCShadowAttack

__all__ = [
    'DSInternalsInjector',
    'DRSUAPIClient',
    'DCShadowAttack',
]
