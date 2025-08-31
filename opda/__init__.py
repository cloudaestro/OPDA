"""
OPDA - Okta Privilege Drift Auditor

Enterprise-grade IAM security auditing tool that detects privilege drift
in Okta environments using policy-as-code approach.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("opda")
except PackageNotFoundError:
    # Package is not installed
    __version__ = "0.1.0-dev"

__author__ = "OPDA Team"
__email__ = "security@company.com"
__description__ = "Okta Privilege Drift Auditor - Enterprise IAM security audit tool"

# Package metadata
__all__ = [
    "__author__",
    "__description__",
    "__email__",
    "__version__",
]
