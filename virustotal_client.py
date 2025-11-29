"""
VirusTotal API Client Module
Handles all interactions with VirusTotal API with proper quota tracking
"""

import requests
import time
import json
import os
from datetime import datetime, timezone, date
from collections import defaultdict
from loggerConfig import logger
from config import (
    API_KEYS, RATE_LIMIT_DELAY, API_TIMEOUT, 
    API_REQUEST_DELAY, MAX_RETRIES, RETRY_DELAY,
    MAX_REQUESTS_PER_MINUTE, MAX_REQUESTS_PER_DAY,
    MIN_DELAY_BETWEEN_REQUESTS, QUOTA_WARNING_THRESHOLD, QUOTA_FILE
)


class VirusTotalClient:
    """Client for interacting with VirusTotal API with quota management"""
    
    def __init__(self):
        self.api_index = 0
        self.start_index = 0  # Track where we started to detect full cycle
        
        # Per-minute tracking: {key_index: [list of timestamps]}
        self.requests_per_minute = defaultdict(list)
        
        # Daily quota tracking: {key_index: {date: count}}
        self.daily_quota = defaultdict(dict)
        
        # Track last request time per key to enforce minimum delay
        self.last_request_time = defaultdict(float)
        
        # Quota file path for persistence
        self.quota_file = QUOTA_FILE
        
        # Load persisted quota data on startup
        self._load_quota_data()
        
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
    
    def _cleanup_old_requests(self, key_index):
        """Remove request timestamps older than 1 minute"""
        current_time = time.time()
        self.requests_per_minute[key_index] = [
            ts for ts in self.requests_per_minute[key_index]
            if current_time - ts < 60
        ]
    
    def _get_daily_count(self, key_index):
        """Get the number of requests made today for a given key"""
        today = date.today().isoformat()
        return self.daily_quota[key_index].get(today, 0)
    
    def _increment_daily_count(self, key_index, save=True):
        """Increment the daily request count for a given key"""
        today = date.today().isoformat()
        if today not in self.daily_quota[key_index]:
            self.daily_quota[key_index][today] = 0
        self.daily_quota[key_index][today] += 1
        
        # Save quota data after each increment
        if save:
            self._save_quota_data()
    
    def _load_quota_data(self):
        """Load quota tracking data from JSON file"""
        if os.path.exists(self.quota_file):
            try:
                with open(self.quota_file, 'r') as f:
                    data = json.load(f)
                    # Convert date strings back to dict structure
                    if 'daily_quota' in data:
                        for key_index_str, dates_dict in data['daily_quota'].items():
                            key_index = int(key_index_str)
                            self.daily_quota[key_index] = dates_dict
                logger.info(f"Loaded quota data from {self.quota_file}")
                
                # Print quota status for debugging
                self.print_quota_status()
            except Exception as e:
                logger.error(f"Error loading quota data: {e}")
                # Continue with empty quota tracking
        else:
            logger.info(f"Quota file {self.quota_file} not found. Starting with fresh tracking.")
    
    def _save_quota_data(self):
        """Save quota tracking data to JSON file"""
        try:
            # Convert to JSON-serializable format
            data = {
                'daily_quota': {
                    str(key_index): dates_dict
                    for key_index, dates_dict in self.daily_quota.items()
                },
                'last_updated': datetime.now().isoformat()
            }
            with open(self.quota_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving quota data: {e}")
    
    def _is_key_available(self, key_index):
        """Check if a key is available (not rate limited and has quota)"""
        # Clean up old requests first
        self._cleanup_old_requests(key_index)
        
        # Check daily quota
        daily_count = self._get_daily_count(key_index)
        if daily_count >= MAX_REQUESTS_PER_DAY:
            return False, f"Daily quota exhausted ({daily_count}/{MAX_REQUESTS_PER_DAY})"
        
        # Check per-minute rate limit
        requests_in_last_minute = len(self.requests_per_minute[key_index])
        if requests_in_last_minute >= MAX_REQUESTS_PER_MINUTE:
            # Calculate wait time needed
            oldest_request = min(self.requests_per_minute[key_index])
            wait_time = 60 - (time.time() - oldest_request) + 1
            return False, f"Rate limit reached ({requests_in_last_minute}/{MAX_REQUESTS_PER_MINUTE} per minute), wait {wait_time:.1f}s"
        
        return True, "Available"
    
    def _find_available_key(self, stop_event=None):
        """Find an available API key, waiting if necessary"""
        max_wait_iterations = len(API_KEYS) * 10  # Prevent infinite loops
        iterations = 0
        
        while iterations < max_wait_iterations:
            if stop_event and stop_event.is_set():
                return None, "Scanner stopped"
            
            # Check current key
            is_available, reason = self._is_key_available(self.api_index)
            if is_available:
                return self.api_index, "Available"
            
            # Try next key
            self.api_index = (self.api_index + 1) % len(API_KEYS)
            iterations += 1
            
            # If we've cycled through all keys, wait a bit and try again
            if self.api_index == self.start_index and iterations > 0:
                wait_time = min(10, MIN_DELAY_BETWEEN_REQUESTS)
                if stop_event and stop_event.is_set():
                    return None, "Scanner stopped"
                logger.info(f"All keys checked, waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                self.start_index = self.api_index  # Reset start tracking
        
        return None, "All keys exhausted after multiple attempts"
    
    def _wait_for_rate_limit(self, key_index, stop_event=None):
        """Wait until the key is available for the next request"""
        # Clean up old requests
        self._cleanup_old_requests(key_index)
        
        requests_in_last_minute = len(self.requests_per_minute[key_index])
        
        if requests_in_last_minute >= MAX_REQUESTS_PER_MINUTE:
            # Need to wait until the oldest request is 60 seconds old
            oldest_request = min(self.requests_per_minute[key_index])
            wait_time = 60 - (time.time() - oldest_request) + 1
            
            if wait_time > 0:
                logger.info(f"Key {key_index}: Rate limit reached. Waiting {wait_time:.1f} seconds...")
                elapsed = 0
                while elapsed < wait_time:
                    if stop_event and stop_event.is_set():
                        return False
                    sleep_chunk = min(1, wait_time - elapsed)
                    time.sleep(sleep_chunk)
                    elapsed += sleep_chunk
        else:
            # Ensure minimum delay between requests
            time_since_last = time.time() - self.last_request_time[key_index]
            if time_since_last < MIN_DELAY_BETWEEN_REQUESTS:
                wait_time = MIN_DELAY_BETWEEN_REQUESTS - time_since_last
                time.sleep(wait_time)
        
        return True
    
    def get_next_api_key(self):
        """Switch to the next available API key (legacy method, use _find_available_key instead)"""
        self.api_index = (self.api_index + 1) % len(API_KEYS)
        self.start_index = self.api_index
        print(f"Switching to next API key: {self.api_index}")
        logger.info(f"Switching to next API key: {self.api_index}")
        return API_KEYS[self.api_index]
    
    def check_ioc(self, ioc, ioc_type, country_mapping=None, stop_event=None):
        """
        Check an IOC against VirusTotal API with retry logic and quota management
        
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
            
            status_code, result = self._make_api_request(ioc, ioc_type, api_path, gui_path, country_mapping, stop_event)
            
            # If successful or scanner stopped, return immediately
            if status_code in [0, 200, 404]:
                return status_code, result
            
            # If it's a retryable error and we have retries left, wait and retry
            if attempt < MAX_RETRIES - 1 and status_code in [400, 500]:
                wait_time = RETRY_DELAY * (attempt + 1)
                print(f"Retryable error for {ioc}. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{MAX_RETRIES})")
                logger.warning(f"Retryable error for {ioc}. Retrying in {wait_time} seconds. Attempt {attempt + 1}/{MAX_RETRIES}")
                time.sleep(wait_time)
            else:
                # Non-retryable error or max retries reached
                return status_code, result
        
        return status_code, result
    
    def _make_api_request(self, ioc, ioc_type, api_path, gui_path, country_mapping, stop_event=None):
        """Make a single API request to VirusTotal with proper quota management"""
        while True:
            if stop_event and stop_event.is_set():
                return 0, None
            
            # Find an available key
            key_index, reason = self._find_available_key(stop_event)
            if key_index is None:
                if reason == "Scanner stopped":
                    return 0, None
                logger.error(f"Could not find available API key: {reason}")
                return 429, None
            
            # Update current index
            self.api_index = key_index
            
            # Wait for rate limit if needed
            if not self._wait_for_rate_limit(key_index, stop_event):
                return 0, None  # Scanner stopped
            
            # Check daily quota warning
            daily_count = self._get_daily_count(key_index)
            if daily_count >= MAX_REQUESTS_PER_DAY * QUOTA_WARNING_THRESHOLD:
                logger.warning(f"API key {key_index} has used {daily_count}/{MAX_REQUESTS_PER_DAY} requests today ({daily_count/MAX_REQUESTS_PER_DAY*100:.1f}%)")
            
            # Make the request
            api_key = API_KEYS[key_index]
            url = f'https://www.virustotal.com/api/v3/{api_path}/{ioc}'
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
        
            try:
                logger.info(f"Checking {ioc_type.upper()}: {ioc} (using key {key_index}, daily: {daily_count}/{MAX_REQUESTS_PER_DAY})")
                response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
                
                logger.info(f"API Response Status: {response.status_code}")

                # Handle rate limiting - DON'T count toward quota
                if response.status_code == 429:
                    logger.warning(f"Rate limit 429 for key {key_index}. Not counting toward quota. Switching to next key...")
                    # Clean up and try next key - DON'T increment quota for failed requests
                    self.requests_per_minute[key_index] = []  # Reset
                    self.api_index = (self.api_index + 1) % len(API_KEYS)
                    self.start_index = self.api_index
                    time.sleep(MIN_DELAY_BETWEEN_REQUESTS)
                    continue

                # Handle blocked API keys - DON'T count toward quota
                if response.status_code in [400, 403, 500]:
                    if response.status_code == 403:
                        print(f"API key {key_index} might be blocked (Status: {response.status_code}). Not counting toward quota. Switching to next API key...")
                        logger.warning(f"API key {key_index} might be blocked. Status: {response.status_code}. Not counting toward quota. Switching API key.")
                        self.api_index = (self.api_index + 1) % len(API_KEYS)
                        self.start_index = self.api_index
                        continue
                    # For 400 and 500, return to allow retry logic - DON'T count toward quota
                    return response.status_code, None

                # Only track successful requests (200, 404) toward quota
                if response.status_code in [200, 404]:
                    # Track the request only on success
                    current_time = time.time()
                    self.requests_per_minute[key_index].append(current_time)
                    self.last_request_time[key_index] = current_time
                    self._increment_daily_count(key_index, save=True)  # Only increment on success

                # Handle not found case (successful response)
                if response.status_code == 404:
                    logger.info(f"IOC not found in VirusTotal: {ioc}")
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
                    return self._parse_successful_response(response, ioc, ioc_type, gui_path, country_mapping)
                else:
                    print(f"IOC {ioc} returned status code {response.status_code}")
                    logger.warning(f"IOC {ioc} returned {response.status_code}")
                    return response.status_code, None

            except requests.exceptions.Timeout:
                logger.error(f"Request timeout for {ioc}")
                return 408, None  # Request timeout
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error for {ioc}: {str(e)}")
                return 400, None
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
        """Apply rate limiting delay between requests"""
        # The rate limiting is now handled automatically in _wait_for_rate_limit
        # This method is kept for backward compatibility but does minimal work
        if stop_event and stop_event.is_set():
            return
        # Small delay to prevent CPU spinning
        time.sleep(0.1)
    
    def get_quota_status(self):
        """Get status of all API keys' quotas"""
        today = date.today().isoformat()
        status = {}
        for i in range(len(API_KEYS)):
            daily_count = self.daily_quota[i].get(today, 0)
            self._cleanup_old_requests(i)
            per_minute_count = len(self.requests_per_minute[i])
            status[i] = {
                'daily_used': daily_count,
                'daily_remaining': MAX_REQUESTS_PER_DAY - daily_count,
                'per_minute_count': per_minute_count,
                'per_minute_remaining': MAX_REQUESTS_PER_MINUTE - per_minute_count
            }
        return status
    
    def print_quota_status(self):
        """Print current quota status for all keys"""
        today = date.today().isoformat()
        print("\n" + "=" * 50)
        print("API Key Quota Status (Today: " + today + ")")
        print("=" * 50)
        total_used = 0
        total_remaining = 0
        for i in range(len(API_KEYS)):
            daily_count = self.daily_quota[i].get(today, 0)
            remaining = MAX_REQUESTS_PER_DAY - daily_count
            percentage = (daily_count / MAX_REQUESTS_PER_DAY * 100) if MAX_REQUESTS_PER_DAY > 0 else 0
            status_symbol = "✓" if remaining > 0 else "✗"
            print(f"{status_symbol} Key {i}: {daily_count:3d}/{MAX_REQUESTS_PER_DAY} used ({remaining:3d} remaining) [{percentage:5.1f}%]")
            total_used += daily_count
            total_remaining += remaining
        
        print("-" * 50)
        print(f"Total: {total_used:3d}/{len(API_KEYS) * MAX_REQUESTS_PER_DAY} used ({total_remaining:3d} remaining)")
        print("=" * 50 + "\n")
        logger.info(f"Quota status - Total used: {total_used}/{len(API_KEYS) * MAX_REQUESTS_PER_DAY}, Remaining: {total_remaining}")


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
