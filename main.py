"""
Main Entry Point for IOC Scanner Application
"""

import signal
from datetime import datetime
from loggerConfig import logger
from config import INPUT_FILE
from csv_handler import CSVHandler
from scanner import (
    stop_event, stop_scanner, signal_handler, 
    scan_iocs, fetch_country_mapping
)


def main():
    """Enhanced main function supporting all IOC types"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signal
    
    # Reset stop event 
    # (in case the script is stopped and started again 
    # then we need to clear the stop event and reset the event to false so that the scanner can start again)
    stop_event.clear()
    
    # Log application startup
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{start_time}] IOC Scanner application starting...")
    logger.info("IOC Scanner application starting")
    
    print("Fetching the latest country mapping...")
    logger.info("Fetching latest country mapping...")
    country_mapping = fetch_country_mapping()
    if not country_mapping:
        print("Warning: Country mapping is empty. Country names will default to the country code.")
        logger.warning("Country mapping is empty.")

    try:
        # Load CSV file
        csv_handler = CSVHandler()
        df, error = csv_handler.load_csv()
        
        if error:
            print(f"Error: {error}")
            return
        
        if df is None:
            print("Error: Failed to load CSV file.")
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
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            logger.info("Operation cancelled by user")
            return
            
        # Start scanning
        scan_iocs(df, start_index, country_mapping)
        
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

