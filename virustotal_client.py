"""
VirusTotal API Client Module
Handles all interactions with VirusTotal API
"""

import time
from datetime import datetime, timezone

import requests

from loggerConfig import logger
from config import (
    API_KEYS,
    RATE_LIMIT_DELAY,
    API_TIMEOUT,
    API_REQUEST_DELAY,
    MAX_RETRIES,
    RETRY_DELAY,
    DAILY_QUOTA_PER_KEY,
    REQUESTS_PER_MINUTE,
)
# stop_event will be passed as parameter to avoid circular import


class VirusTotalClient:
    """Client for interacting with VirusTotal API"""
    
    def __init__(self):
        self.api_index = 0
        self.api_request_count = 0

        # Track per-key daily usage in memory only (no JSON file)
        self.usage = self._init_usage_state()

        # Track last request timestamps per key to enforce per-minute rate
        self.last_request_times = [0.0] * len(API_KEYS)
        self.last_used_key_index = None
        
        # API endpoint mapping
        self.api_type_map = {
            "ip": "ip_addresses",
            "domain": "domains", 
            "file": "files"
        }
        
        # GUI URL mapping
        self.gui_type_map = {
            "ip": "ip-address",
            "domain": "domain",
            "file": "file"
        }

    # ------------------------------------------------------------------
    # Usage / quota tracking helpers (in-memory only)
    # ------------------------------------------------------------------

    def _get_today_str(self):
        return datetime.utcnow().strftime("%Y-%m-%d")

    def _init_usage_state(self):
        """
        Initialize per-key usage information in memory.
        This is reset on each run; no JSON file is used.
        """
        today = self._get_today_str()
        keys = []
        for idx, _ in enumerate(API_KEYS):
            keys.append({
                "key_index": idx,
                "label": f"key_{idx + 1}",
                "last_reset_date": today,
                "requests_today": 0,
            })
        return {"keys": keys}

    def _reset_if_new_day(self, key_index):
        """Reset the usage counter for a key if a new day has started."""
        today = self._get_today_str()
        key_info = self.usage["keys"][key_index]
        if key_info.get("last_reset_date") != today:
            key_info["last_reset_date"] = today
            key_info["requests_today"] = 0

    def _has_quota(self, key_index):
        """Check if the given key has remaining daily quota."""
        self._reset_if_new_day(key_index)
        key_info = self.usage["keys"][key_index]
        return key_info.get("requests_today", 0) < DAILY_QUOTA_PER_KEY

    def _increment_usage(self, key_index):
        """Increment the request counter for a key (in memory only)."""
        try:
            self._reset_if_new_day(key_index)
            key_info = self.usage["keys"][key_index]
            key_info["requests_today"] = int(key_info.get("requests_today", 0)) + 1
        except Exception as e:
            logger.warning(f"Failed to increment VT usage for key {key_index}: {e}")

    def _select_active_key(self):
        """
        Ensure self.api_index points to a key with available daily quota.
        If all keys are exhausted, wait and retry after RATE_LIMIT_DELAY.
        """
        attempts = 0
        total_keys = len(API_KEYS)

        while True:
            # Try each key at most once in this pass
            for offset in range(total_keys):
                idx = (self.api_index + offset) % total_keys
                if self._has_quota(idx):
                    if idx != self.api_index:
                        logger.info(f"Switching to API key index {idx} due to quota/rotation.")
                    self.api_index = idx
                    return API_KEYS[self.api_index]

            # All keys exhausted for today or temporarily blocked
            attempts += 1
            logger.warning(
                f"All VirusTotal API keys appear to be at daily quota. "
                f"Sleeping for {RATE_LIMIT_DELAY} seconds before retrying (attempt {attempts})."
            )
            print(
                f"All VirusTotal API keys reached daily quota or are blocked. "
                f"Waiting {RATE_LIMIT_DELAY} seconds before retrying..."
            )
            time.sleep(RATE_LIMIT_DELAY)

    def get_next_api_key(self):
        """Switch to the next available API key that still has quota."""
        # Move to next index then select a key with quota
        self.api_index = (self.api_index + 1) % len(API_KEYS)
        self.api_request_count = 0
        active_key = self._select_active_key()
        print(f"Switching to next API key: {self.api_index}")
        logger.info(f"Switching to next API key: {self.api_index}")
        return active_key
    
    def check_ioc(self, ioc, ioc_type, country_mapping=None, stop_event=None):
        """
        Check an IOC against VirusTotal API with retry logic
        
        Args:
            ioc: The IOC to check
            ioc_type: Type of IOC ("ip", "domain", "file")
            country_mapping: Dictionary mapping country codes to names
            stop_event: Threading event to check if scanner should stop
            
        Returns:
            tuple: (status_code: int, result: dict or None)
                status_code 0 means scanner was stopped
        """
        api_path = self.api_type_map[ioc_type]
        gui_path = self.gui_type_map[ioc_type]
        
        for attempt in range(MAX_RETRIES):
            if stop_event and stop_event.is_set():
                return 0, None  # Scanner stopped
            
            status_code, result = self._make_api_request(
                ioc, ioc_type, api_path, gui_path, country_mapping, stop_event
            )
            
            # If successful or scanner stopped, return immediately
            if status_code in [0, 200, 404]:
                return status_code, result
            
            # If it's a retryable error and we have retries left, wait and retry
            # Network/timeout errors (408, 499) and server errors (5xx) are retryable.
            if attempt < MAX_RETRIES - 1 and status_code in [408, 499, 500]:
                wait_time = RETRY_DELAY * (attempt + 1)
                print(f"Retryable error for {ioc}. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{MAX_RETRIES})")
                logger.warning(f"Retryable error for {ioc}. Retrying in {wait_time} seconds. Attempt {attempt + 1}/{MAX_RETRIES}")
                time.sleep(wait_time)
            else:
                # Non-retryable error or max retries reached
                return status_code, result
        
        return status_code, result
    
    def _make_api_request(self, ioc, ioc_type, api_path, gui_path, country_mapping, stop_event=None):
        """Make a single API request to VirusTotal"""
        while True:
            if stop_event and stop_event.is_set():
                return 0, None

            # Ensure we are using a key that still has daily quota
            api_key = self._select_active_key()
            url = f'https://www.virustotal.com/api/v3/{api_path}/{ioc}'
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            try:
                logger.info(f"Checking {ioc_type.upper()}: {ioc}")

                # Track timing for rate limiting
                now = time.time()
                self.last_request_times[self.api_index] = now
                self.last_used_key_index = self.api_index

                response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
                self.api_request_count += 1
                
                logger.info(f"API Response Status: {response.status_code}")

                # Handle rate limiting
                if response.status_code == 429:
                    print(f"Rate limit exceeded for API key {self.api_index}. Switching to next API key...")
                    logger.warning(f"Rate limit exceeded for API key {self.api_index}. Switching API key.")
                    api_key = self.get_next_api_key()
                    if self.api_index == 0:  
                        print(f"All API keys have reached their rate limit. Waiting for {RATE_LIMIT_DELAY} seconds...")
                        logger.warning(f"All API keys reached rate limit. Waiting {RATE_LIMIT_DELAY} sec.")
                        time.sleep(RATE_LIMIT_DELAY)
                    continue

                # Handle blocked API keys
                if response.status_code in [400, 403, 500]:
                    if response.status_code == 403:
                        print(f"API key {self.api_index} might be blocked (Status: {response.status_code}). Switching to next API key...")
                        logger.warning(f"API key {self.api_index} might be blocked. Status: {response.status_code}. Switching API key.")
                        api_key = self.get_next_api_key()
                        continue
                    # For 400 and 500, return to allow retry logic
                    return response.status_code, None

                # Handle not found case
                if response.status_code == 404:
                    logger.info(f"IOC not found in VirusTotal: {ioc}")
                    self._increment_usage(self.api_index)
                    return 404, {
                        "Status": "Not found",
                        "Link": f"https://www.virustotal.com/gui/{gui_path}/{ioc}",
                        "last_analysis_stats": "{}",
                        "Country": "",
                        "whois_date": "",
                        "Last_Modification_Date": "",
                        "AS_Owner": ""
                    }

                # Handle successful response
                if response.status_code == 200:
                    self._increment_usage(self.api_index)
                    return self._parse_successful_response(response, ioc, ioc_type, gui_path, country_mapping)
                else:
                    print(f"IOC {ioc} returned status code {response.status_code}")
                    logger.warning(f"IOC {ioc} returned {response.status_code}")
                    # Count non-timeout, non-network errors against quota
                    if response.status_code not in [408]:
                        self._increment_usage(self.api_index)
                    return response.status_code, None

            except requests.exceptions.Timeout:
                logger.error(f"Request timeout for {ioc}")
                # 408: request timeout, retryable and not counted towards daily quota
                return 408, None
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error for {ioc}: {str(e)}")
                # 499: synthetic code for network-level issues, retryable and not counted
                return 499, None
            except Exception as e:
                logger.error(f"Unexpected error for {ioc}: {str(e)}")
                return 500, None
    
    def _parse_successful_response(self, response, ioc, ioc_type, gui_path, country_mapping):
        """Parse a successful API response"""
        try:
            response_data = response.json()
            
            attr = response_data.get("data", {}).get("attributes", {})
            last_analysis_stats = attr.get("last_analysis_stats", {})
            mal = last_analysis_stats.get("malicious", 0)
            sus = last_analysis_stats.get("suspicious", 0)
            unrated = last_analysis_stats.get("undetected", 0)
            
            link = f"https://www.virustotal.com/gui/{gui_path}/{ioc}"
            
            # Extract data based on IOC type
            country = ""
            whois_date = ""
            last_modification_date = ""
            as_owner = ""
            
            if ioc_type == "ip":
                country_code = attr.get("country")
                whois_date_utc = attr.get("whois_date")
                last_modification_date_utc = attr.get("last_modification_date", None)
                as_owner = attr.get("as_owner")
                
                if country_mapping and country_code:
                    country = country_mapping.get(country_code, country_code)
                elif country_code:
                    country = country_code
                
                # Convert timestamps
                if whois_date_utc:
                    try:
                        whois_date = datetime.fromtimestamp(whois_date_utc, tz=timezone.utc).isoformat()
                    except Exception:
                        whois_date = ""

                if last_modification_date_utc:
                    try:
                        last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                    except Exception:
                        last_modification_date = ""
                        
            elif ioc_type == "domain":
                whois_date_utc = attr.get("whois_date")
                last_modification_date_utc = attr.get("last_modification_date", None)
                
                if whois_date_utc:
                    try:
                        whois_date = datetime.fromtimestamp(whois_date_utc, tz=timezone.utc).isoformat()
                    except Exception:
                        whois_date = ""

                if last_modification_date_utc:
                    try:
                        last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                    except Exception:
                        last_modification_date = ""
                        
            elif ioc_type == "file":
                last_modification_date_utc = attr.get("last_modification_date", None)
                
                if last_modification_date_utc:
                    try:
                        last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                    except Exception:
                        last_modification_date = ""

            # Determine status
            if mal >= 1:
                status = f"Malicious (Mal:{mal}, Sus:{sus})"
            elif sus >= 1:
                status = f"Suspicious (Mal:{mal}, Sus:{sus})"
            elif unrated >= 1:
                status = f"Unrated (Mal:{mal}, Sus:{sus})"
            else:
                status = f"Clean (Mal:{mal}, Sus:{sus})"
            
            result = {
                "Status": status,
                "Link": link,
                "last_analysis_stats": str(last_analysis_stats),
                "Country": country,
                "whois_date": whois_date,
                "Last_Modification_Date": last_modification_date,
                "AS_Owner": as_owner or ""
            }
            
            logger.info(f"Successfully processed {ioc}: {status}")
            return 200, result
            
        except Exception as e:
            logger.error(f"Error parsing response for {ioc}: {str(e)}")
            return 500, None
    
    def apply_rate_limit(self, stop_event=None):
        """Apply rate limiting delay between requests.

        Ensures we do not exceed the free API rate of 4 lookups/minute per key
        while also respecting the configured minimum API_REQUEST_DELAY.
        """
        if stop_event is not None and stop_event.is_set():
            return

        # If we do not yet know which key was used, fall back to simple delay
        if self.last_used_key_index is None:
            time.sleep(API_REQUEST_DELAY)
            return

        min_interval = max(60.0 / float(REQUESTS_PER_MINUTE), float(API_REQUEST_DELAY))
        last_ts = self.last_request_times[self.last_used_key_index] or 0.0
        if last_ts <= 0:
            time.sleep(API_REQUEST_DELAY)
            return

        elapsed = time.time() - last_ts
        if elapsed < min_interval:
            sleep_for = min_interval - elapsed
            if sleep_for > 0 and (stop_event is None or not stop_event.is_set()):
                time.sleep(sleep_for)


def fetch_country_mapping():
    """
    Fetch the mapping of country codes to country names from the external API.
    
    Returns:
        dict: Dictionary with country codes as keys and country names as values
    """
    from config import COUNTRY_API_URL, COUNTRY_API_TIMEOUT
    
    try:
        response = requests.get(COUNTRY_API_URL, timeout=COUNTRY_API_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            mapping = {}
            for code, details in data.get("data", {}).items():
                mapping[code] = details.get("country")
            return mapping
        else:
            print("Failed to fetch country mapping, status code:", response.status_code)
            logger.warning(f"Failed to fetch country mapping. Status: {response.status_code}")
            return {}
    except Exception as e:
        print("Error fetching country mapping:", e)
        logger.error(f"Error fetching country mapping: {e}")
        return {}

