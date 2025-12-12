"""Configuration constants for awsio.

Contains default file locations and other small constants used across the package.
"""

import os

# Path to a small json cache used by the SSO OIDC flow to store short-lived tokens.
CACHE_FILE = os.path.expanduser("~/.aws_sso_oidc_cache.json")
