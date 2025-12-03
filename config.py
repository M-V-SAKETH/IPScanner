"""
Configuration file for IOC Scanner
Contains all constants and configuration settings
"""

import os

# -----------------------------------------------------------------------------
# VirusTotal API configuration
# -----------------------------------------------------------------------------

# VirusTotal API Keys
# NOTE: Free public API keys are limited to 4 lookups/minute and 500/day per key.
# These keys are kept here because this is a local tool – do NOT commit real
# production keys to any public repository.
API_KEYS = [
    "cd451f89b27b58807d5641039c6889383a2c7c341dcfac85ed0b363017e29968",  # me
]

# Free public VirusTotal quota limits
DAILY_QUOTA_PER_KEY = 500        # 500 lookups / day / key
REQUESTS_PER_MINUTE = 4          # 4 lookups / minute / key

# API Configuration
RATE_LIMIT_DELAY = 60  # Seconds to wait when all API keys are rate limited/exhausted
API_TIMEOUT = 30       # Request timeout in seconds
# Minimum delay between requests when no other constraint applies. The
# VirusTotal free limit is 4/minute (15s). We will respect that in the client
# logic, this value is a lower bound.
API_REQUEST_DELAY = 1
MAX_RETRIES = 3        # Maximum number of retries for failed API requests
RETRY_DELAY = 5        # Base delay between retries in seconds (will be backoff)

# -----------------------------------------------------------------------------
# File / CSV configuration
# -----------------------------------------------------------------------------

INPUT_FILE = "ioc_input.csv"
CSV_ENCODING = "windows-1252"

# CSV Save Configuration
BATCH_SAVE_INTERVAL = 10  # Save CSV after processing every N IOCs (prevents frequent I/O)
FORCE_SAVE_INTERVAL = 50  # Force save every N IOCs regardless

# Country Mapping API
COUNTRY_API_URL = 'https://api.first.org/data/v1/countries?limit=300'
COUNTRY_API_TIMEOUT = 10

