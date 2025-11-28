import requests
import pandas as pd
import time 
import ipaddress
import re
from datetime import datetime, timezone
import io
from loggerConfig import logger  # Import the logger from loggerConfig.py
import signal
import threading
import sys


API_KEYS = [
    # '504a439e74d6bd4a5c930e268a7ee61153e828ea998736220c2b7bbd8567d88a', #IT Vision A/c
    # '04110b16553493a82bcdaa2633dcd6da5224f53fc37d57ecd4c0693ecf3eb058', #Sehran Rasool A/c
    # '67cbd99da652226dbdf160af45ebd3b04b3aa5a813ed8353bfbe09e185dd5c07', #Sehran Jan A/c
    '0fb6213d1c5e9fcbda92c07f0a2bac77601f4910d170896e238f90deeb50a7d5', #Muhasib A/c
    'e35ca39c007c541348e3d1abfb06c146e069e8be406d283a88c939b7dce88004', #Amar A/c
    '5b58c950234f8fc3614e5f3108bfc5c727eee0a75aefcecb957f30b09b46cf7d',  #Asmita A/c
    "6f375549dd84e5c2216600390479a1d18a433522535831c5330a78f74eca7a87", #Saketh 1
    "8c806eef158bdd510f2f39c900676b304b5a344c91c5789de47803ac0ccec0d6", #Saketh 2
    "3d3f544667e2f1b2eebda3b40a748993c15872d308995e017046af8d94167aed" #Saketh 3
]
api_index = 0
api_request_count = 0
RATE_LIMIT_DELAY = 60  
INPUT_FILE = "ioc_input.csv"

COUNTRY_MAPPING = {}

# Global variables for scanner control
stop_reason = None
stop_event = threading.Event()
processed_ips = 0
total_ips = 0

def detect_ioc_type(ioc):
    """Detect the type of IOC (IP, domain, or file hash) - ENHANCED"""
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    hash_pattern = r"^[a-fA-F0-9]{32,64}$"  # Support both MD5 and SHA-256

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(hash_pattern, ioc):
        return "file"
    elif re.match(domain_pattern, ioc):
        return "domain"
    else:
        return None

def command_listener():
    """Enhanced command listener with more options"""
    print("\nScanner command interface active.")
    print("Available commands: 'stop', 'q', 'quit', 'exit' (to stop), 'status' (for status)")
    logger.info("Enhanced scanner command interface active")
    
    while not stop_event.is_set():
        try:
            command = input().strip().lower()
            if command in ['q', 'stop', 'quit', 'exit']:  
                stop_scanner(f"User entered '{command}' command")
                break
            elif command == 'status':
                print(f"Scanner is running. Processed {processed_ips} out of {total_ips} items")
            elif command:
                print("Unknown command. Available: 'stop'/'q'/'quit'/'exit' (quit), 'status'")
        except EOFError:
            time.sleep(1)
        except KeyboardInterrupt:
            stop_scanner("KeyboardInterrupt in command listener")
            break
        except Exception as e:
            print(f"Error in command listener: {e}")
            logger.error(f"Error in command listener: {e}")

def signal_handler(sig, frame):
    """Handle signals like CTRL+C"""
    signal_name = signal.Signals(sig).name
    stop_scanner(f"Received {signal_name} signal")

def stop_scanner(reason):
    """Stop the scanner with a specified reason"""
    global stop_reason
    if not stop_event.is_set():
        stop_reason = reason
        print(f"\nStopping scanner: {reason}")
        logger.info(f"Stopping scanner: {reason}")
        stop_event.set()

def is_valid_ip(ip_address):
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def get_next_api_key():
    global api_index, api_request_count
    api_index = (api_index + 1) % len(API_KEYS)
    api_request_count = 0
    print(f"Switching to next API key: {api_index}")
    logger.info(f"Switching to next API key: {api_index}")
    return API_KEYS[api_index]

def check_ioc_virustotal(ioc, ioc_type):
    """Enhanced IOC checking supporting IP, domain, and file hash"""
    global api_request_count
    
    # API endpoint mapping
    api_type_map = {
        "ip": "ip_addresses",
        "domain": "domains", 
        "file": "files"
    }
    
    # GUI URL mapping
    gui_type_map = {
        "ip": "ip-address",
        "domain": "domain",
        "file": "file"
    }
    
    while True:
        if stop_event.is_set():
            return 0, None  # Return 0 to indicate scanner stopped
            
        api_key = API_KEYS[api_index]
        api_path = api_type_map[ioc_type]
        gui_path = gui_type_map[ioc_type]
        
        url = f'https://www.virustotal.com/api/v3/{api_path}/{ioc}'
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
    
        try:
            logger.info(f"Checking {ioc_type.upper()}: {ioc}")
            response = requests.get(url, headers=headers, timeout=30)
            api_request_count += 1
            
            logger.info(f"API Response Status: {response.status_code}")

            if response.status_code == 429:
                print(f"Rate limit exceeded for API key {api_index}. Switching to next API key...")
                logger.warning(f"Rate limit exceeded for API key {api_index}. Switching API key.")
                api_key = get_next_api_key()
                if api_index == 0:  
                    print(f"All API keys have reached their rate limit. Waiting for {RATE_LIMIT_DELAY} seconds...")
                    logger.warning(f"All API keys reached rate limit. Waiting {RATE_LIMIT_DELAY} sec.")
                    time.sleep(RATE_LIMIT_DELAY)
                continue

            if response.status_code in [400, 403, 500]:
                print(f"API key {api_index} might be blocked (Status: {response.status_code}). Switching to next API key...")
                logger.warning(f"API key {api_index} might be blocked. Status: {response.status_code}. Switching API key.")
                api_key = get_next_api_key()
                continue 

            # Handle not found case
            if response.status_code == 404:
                logger.info(f"IOC not found in VirusTotal: {ioc}")
                result = {
                    "Status": "Not found",
                    "Link": f"https://www.virustotal.com/gui/{gui_path}/{ioc}",
                    "last_analysis_stats": "{}",
                    "Country": "",
                    "whois_date": "",
                    "Last_Modification_Date": "",
                    "AS_Owner": ""
                }
                return 200, result

            if response.status_code == 200:
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
                        country = attr.get("country")   
                        whois_date_utc = attr.get("whois_date")      
                        last_modification_date_utc = attr.get("last_modification_date", None)
                        as_owner = attr.get("as_owner")
                        
                        country_fullname = get_country_name(country)
                        country = country_fullname or ""
                        
                        # Convert timestamps
                        if whois_date_utc:
                            try:
                                whois_date = datetime.fromtimestamp(whois_date_utc, tz=timezone.utc).isoformat()
                            except:
                                whois_date = ""

                        if last_modification_date_utc:
                            try:
                                last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                            except:
                                last_modification_date = ""
                                
                    elif ioc_type == "domain":
                        # Domain-specific attributes
                        whois_date_utc = attr.get("whois_date")
                        last_modification_date_utc = attr.get("last_modification_date", None)
                        
                        if whois_date_utc:
                            try:
                                whois_date = datetime.fromtimestamp(whois_date_utc, tz=timezone.utc).isoformat()
                            except:
                                whois_date = ""

                        if last_modification_date_utc:
                            try:
                                last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                            except:
                                last_modification_date = ""
                                
                    elif ioc_type == "file":
                        # File-specific attributes
                        last_modification_date_utc = attr.get("last_modification_date", None)
                        
                        if last_modification_date_utc:
                            try:
                                last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc).isoformat()
                            except:
                                last_modification_date = ""

                    # Determine status
                    if mal >= 1:
                        status = f"Malicious (Mal:{mal}, Sus:{sus})"  #added extra info for status. you can remove those mal and sus if unnecessary.
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
            else:
                print(f"IOC {ioc} {response.status_code} gave non 200 status code... \n")
                logger.warning(f"IOC {ioc} returned {response.status_code}")
                return response.status_code, None

        except requests.exceptions.RequestException as e:
            print("Error in exception:\n", e)
            logger.error(f"Network error for {ioc}: {str(e)}")
            return 400, None
        except Exception as e:
            logger.error(f"Unexpected error for {ioc}: {str(e)}")
            return 500, None

def callAPI(df, start_index):
    global processed_ips, total_ips, stop_reason
    
    # Log the start of IOC scanning process
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{current_time}] IOC Scanner started - Processing from index {start_index}")
    logger.info(f"IOC Scanner started - Processing from index {start_index}")
    
    total_ips = len(df) - (start_index - 1)
    processed_ips = 0
    skipped_count = 0
    
    # Start the command listener in a separate thread
    command_thread = threading.Thread(target=command_listener, daemon=True)
    command_thread.start()
    
    try:
        for index in range(start_index - 1, len(df)):
            # Check if stop was requested
            if stop_event.is_set():
                logger.info(f"Scanner stopped at index {index + 1}. Reason: {stop_reason}")
                break
                
            ioc = str(df.at[index, 'IOC']).strip()
            status = str(df.at[index, 'Status']).strip()
            
            logger.info(f"Processing row {index + 1}/{len(df)}: {ioc}")

            # Enhanced validation
            if pd.isna(ioc) or ioc == "" or ioc.lower() == "nan":
                logger.info(f"Skipping empty IOC at row {index + 1}")
                skipped_count += 1
                continue
            
            # Check for wildcard entries
            if '*' in ioc:
                print(f"{index + 1}. Wildcard entry detected: {ioc} - Skipping")
                logger.info(f"Wildcard entry detected at row {index + 1}: {ioc} - Skipping")
                df.at[index, 'Status'] = "Wildcard"
                df.to_csv(INPUT_FILE, index=False)
                skipped_count += 1
                continue
                
            if status != "" and status.lower() != "nan":
                print(f"{index + 1}. Finished scanning successfully: {ioc}")
                logger.info(f"Already processed IOC: {ioc}")
                skipped_count += 1
                continue

            # Detect IOC type
            ioc_type = detect_ioc_type(ioc)
            if not ioc_type:
                print(f"{index + 1}. {ioc} is not a valid IOC (IP/Domain/Hash) - Skipping")
                logger.error(f"{ioc} is not a valid IOC type")
                df.at[index, 'Status'] = "Invalid IOC type"
                df.to_csv(INPUT_FILE, index=False)
                skipped_count += 1
                continue

            # Process IOC based on type
            status_code, result = check_ioc_virustotal(ioc, ioc_type)
            
            # Check if stop was requested during API call
            if status_code == 0:  # Scanner stopped
                logger.info(f"Scanner stopped while processing {ioc}. Reason: {stop_reason}")
                break
                
            if status_code == 200 and result is not None:
                # Update DataFrame
                for key, value in result.items():
                    df.at[index, key] = str(value)

                print(f"\n{index+1}. IOC {ioc} ({ioc_type.upper()}): {result['Status']}, Country: {result['Country']}, Owner: {result['AS_Owner']} \n")
                logger.info(f"Processing IOC: {ioc} ({ioc_type.upper()}), Status: {result['Status']}, Country: {result['Country']}, Owner: {result['AS_Owner']}")
                
                # Save progress
                try:
                    df.to_csv(INPUT_FILE, index=False)
                    logger.info(f"Progress saved after processing {ioc}")
                except Exception as e:
                    logger.error(f"Failed to save progress: {str(e)}")
            else:
                print(f"Failed to process IOC {ioc}. Status code: {status_code}")
                logger.warning(f"Failed to process IOC {ioc}. Status code: {status_code}")
                
            processed_ips += 1
            
            # Rate limiting - CHANGED TO 1 SECOND
            if not stop_event.is_set():
                logger.info("Waiting 1 second before next request...")
                time.sleep(1)  # Changed from 15 to 1 second
    
    except Exception as e:
        # Log any unexpected error that causes the scanner to stop
        error_message = f"Error during IOC scanning: {e}"
        stop_scanner(error_message)
        logger.error(error_message)
        
    finally:
        if not stop_reason:
            stop_reason = "Completed successfully"
            
        # Enhanced completion logging
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if stop_event.is_set():
            print(f"\n[{end_time}] Scanner stopped. Processed: {processed_ips}, Skipped: {skipped_count}")
            logger.info(f"Scanner stopped. Processed: {processed_ips}, Skipped: {skipped_count}. Reason: {stop_reason}")
        else:
            print(f"\n[{end_time}] Scanner completed successfully. Processed: {processed_ips}, Skipped: {skipped_count}")
            logger.info(f"Scanner completed successfully. Processed: {processed_ips}, Skipped: {skipped_count}")

def fetch_country_mapping():
    """
    Fetch the mapping of country codes to country names from the external API.
    Returns a dictionary with country codes as keys and country names as values.
    """
    url = 'https://api.first.org/data/v1/countries?limit=300'
    try:
        response = requests.get(url, timeout=10)
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

def get_country_name(country_code):
    """
    Returns the full country name corresponding to the given country code using the dynamic mapping.
    If the mapping does not have the code, return the code itself.
    """
    if country_code in COUNTRY_MAPPING:
        return COUNTRY_MAPPING[country_code]
    else:
        return country_code

def main():
    """Enhanced main function supporting all IOC types"""
    global COUNTRY_MAPPING, stop_event
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signal
    
    # Reset stop event (in case the script is run multiple times in the same process)
    stop_event.clear()
    
    # Log application startup
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{start_time}] IOC Scanner application starting...")
    logger.info("IOC Scanner application starting")
    
    print("Fetching the latest country mapping...")
    logger.info("Fetching latest country mapping...")
    COUNTRY_MAPPING = fetch_country_mapping()
    if not COUNTRY_MAPPING:
        print("Warning: Country mapping is empty. Country names will default to the country code.")
        logger.warning("Country mapping is empty.")

    try:
        # Enhanced file loading with better error handling
        try:
            logger.info(f"Loading CSV file: {INPUT_FILE}")
            df = pd.read_csv(INPUT_FILE, encoding='windows-1252', dtype=str)
            logger.info(f"Loaded {len(df)} rows with columns: {list(df.columns)}")
        except FileNotFoundError:
            logger.error(f"CSV file '{INPUT_FILE}' not found!")
            print(f"Error: CSV file '{INPUT_FILE}' not found!")
            return
        except Exception as e:
            logger.error(f"Error loading CSV file: {str(e)}")
            print(f"Error loading CSV file: {str(e)}")
            return

        # Verify IOC column exists
        if 'IOC' not in df.columns:
            logger.error("'IOC' column not found in CSV file!")
            print("Error: 'IOC' column not found in CSV file!")
            return

        # Enhanced user interface
        print("IOC Scanner started successfully!")
        print("Supports: IP addresses, Domain names, and File hashes (MD5/SHA256)")
        print("Type 'stop', 'q', 'quit', or 'exit' to stop the scanner.")
        print("You can also press Ctrl+C to stop the scanner.")
        print("-" * 50)

        # Enhanced input validation
        try:
            start_index = int(input("\nEnter the starting row number (1-based): "))
            if start_index < 1 or start_index > len(df):
                logger.error(f"Invalid start index: {start_index}")
                print(f"Error: Invalid start index. Please enter a number between 1 and {len(df)}")
                return
        except ValueError:
            logger.error("Invalid start index provided")
            print("Error: Please enter a valid number")
            return
            
        callAPI(df, start_index)
        
    except Exception as e:
        # Log any unexpected error in the main function
        print(f"Critical error in main function: {e}")
        logger.critical(f"Critical error in main function: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Ensure the stop event is set to clean up any threads
        stop_event.set()
        
        # Log application shutdown
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{end_time}] IOC Scanner application shutting down...")
        logger.info("IOC Scanner application shutting down")

if __name__ == "__main__":
    main()