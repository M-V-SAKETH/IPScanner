"""
Main Scanner Module
Handles the core scanning logic and orchestration
"""

import time
import signal
import threading
from datetime import datetime
from loggerConfig import logger
from config import INPUT_FILE
from ioc_validator import detect_ioc_type, validate_ioc
from virustotal_client import VirusTotalClient, fetch_country_mapping
from csv_handler import CSVHandler


# Global variables for scanner control
stop_reason = None
stop_event = threading.Event()
processed_ips = 0
total_ips = 0


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


def scan_iocs(df, start_index, country_mapping=None):
    """
    Main function to scan IOCs from DataFrame
    
    Args:
        df: DataFrame containing IOCs
        start_index: Starting row index (1-based)
        country_mapping: Dictionary mapping country codes to names
    """
    global processed_ips, total_ips, stop_reason
    
    # Log the start of IOC scanning process
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{current_time}] IOC Scanner started - Processing from index {start_index}")
    logger.info(f"IOC Scanner started - Processing from index {start_index}")
    
    total_ips = len(df) - (start_index - 1)
    processed_ips = 0
    skipped_count = 0
    
    # Initialize components
    vt_client = VirusTotalClient()
    csv_handler = CSVHandler()
    
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

            # Validate IOC
            is_valid, error_msg = validate_ioc(ioc)
            if not is_valid:
                if error_msg == "Empty IOC":
                    logger.info(f"Skipping empty IOC at row {index + 1}")
                    skipped_count += 1
                elif error_msg == "Wildcard entry":
                    print(f"{index + 1}. Wildcard entry detected: {ioc} - Skipping")
                    logger.info(f"Wildcard entry detected at row {index + 1}: {ioc} - Skipping")
                    df.at[index, 'Status'] = "Wildcard"
                    csv_handler.save_csv(df, force=True)
                    skipped_count += 1
                elif error_msg == "Invalid IOC type":
                    print(f"{index + 1}. {ioc} is not a valid IOC (IP/Domain/Hash) - Skipping")
                    logger.error(f"{ioc} is not a valid IOC type")
                    df.at[index, 'Status'] = "Invalid IOC type"
                    csv_handler.save_csv(df, force=True)
                    skipped_count += 1
                continue
                
            # Skip if already processed
            if status != "" and status.lower() != "nan":
                print(f"{index + 1}. Already processed: {ioc}")
                logger.info(f"Already processed IOC: {ioc}")
                skipped_count += 1
                continue

            # Detect IOC type
            ioc_type = detect_ioc_type(ioc)
            if not ioc_type:
                print(f"{index + 1}. {ioc} is not a valid IOC (IP/Domain/Hash) - Skipping")
                logger.error(f"{ioc} is not a valid IOC type")
                df.at[index, 'Status'] = "Invalid IOC type"
                csv_handler.save_csv(df, force=True)
                skipped_count += 1
                continue

            # Process IOC via VirusTotal API
            status_code, result = vt_client.check_ioc(ioc, ioc_type, country_mapping, stop_event)
            
            # Check if stop was requested during API call
            if status_code == 0:  # Scanner stopped
                logger.info(f"Scanner stopped while processing {ioc}. Reason: {stop_reason}")
                # Save progress before stopping
                csv_handler.save_csv(df, force=True)
                break
                
            if status_code == 200 and result is not None:
                # Update DataFrame
                csv_handler.update_row(df, index, result)

                print(f"\n{index+1}. IOC {ioc} ({ioc_type.upper()}): {result['Status']}, Country: {result['Country']}, Owner: {result['AS_Owner']} \n")
                logger.info(f"Processing IOC: {ioc} ({ioc_type.upper()}), Status: {result['Status']}, Country: {result['Country']}, Owner: {result['AS_Owner']}")
            elif status_code == 404 and result is not None:
                # Not found is also a valid result
                csv_handler.update_row(df, index, result)
                print(f"\n{index+1}. IOC {ioc} ({ioc_type.upper()}): Not found in VirusTotal\n")
                logger.info(f"IOC {ioc} ({ioc_type.upper()}): Not found in VirusTotal")
            else:
                print(f"Failed to process IOC {ioc}. Status code: {status_code}")
                logger.warning(f"Failed to process IOC {ioc}. Status code: {status_code}")
                
            processed_ips += 1
            
            # Batch save CSV (saves every N items instead of every single item)
            if csv_handler.should_save(force=False):
                csv_handler.save_csv(df, force=False)
            
            # Apply rate limiting
            vt_client.apply_rate_limit(stop_event)
    
    except Exception as e:
        # Log any unexpected error that causes the scanner to stop
        error_message = f"Error during IOC scanning: {e}"
        stop_scanner(error_message)
        logger.error(error_message)
        import traceback
        logger.error(traceback.format_exc())
        
    finally:
        # Always save progress before exiting
        csv_handler.save_csv(df, force=True)
        
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

