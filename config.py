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
    # '504a439e74d6bd4a5c930e268a7ee61153e828ea998736220c2b7bbd8567d88a', #IT Vision A/c
    # '04110b16553493a82bcdaa2633dcd6da5224f53fc37d57ecd4c0693ecf3eb058', #Sehran Rasool A/c
    # '67cbd99da652226dbdf160af45ebd3b04b3aa5a813ed8353bfbe09e185dd5c07', #Sehran Jan A/c
    '0fb6213d1c5e9fcbda92c07f0a2bac77601f4910d170896e238f90deeb50a7d5',  # Muhasib A/c
    'e35ca39c007c541348e3d1abfb06c146e069e8be406d283a88c939b7dce88004',  # Amar A/c
    '5b58c950234f8fc3614e5f3108bfc5c727eee0a75aefcecb957f30b09b46cf7d',  # Asmita A/c
    "6f375549dd84e5c2216600390479a1d18a433522535831c5330a78f74eca7a87",  # Saketh 1
    "8c806eef158bdd510f2f39c900676b304b5a344c91c5789de47803ac0ccec0d6",  # Saketh 2
    "3d3f544667e2f1b2eebda3b40a748993c15872d308995e017046af8d94167aed",  # Saketh 3
]

# Free public VirusTotal quota limits
DAILY_QUOTA_PER_KEY = 500        # 500 lookups / day / key
REQUESTS_PER_MINUTE = 4          # 4 lookups / minute / key

# JSON file used to track per-key usage so long-running scans are quota-aware.
# Stored next to this config file by default.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VT_USAGE_FILE = os.path.join(BASE_DIR, "vt_key_usage.json")

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

