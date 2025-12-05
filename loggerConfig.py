import logging
import os
import glob
import re
from datetime import datetime

# Get the directory where loggerConfig.py is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Generate monthly log file name (format: ipscannerLogs_YYYY_MM.log)
current_date = datetime.now()
log_filename = f"ipscannerLogs_{current_date.strftime('%Y_%m')}.log"
log_file = os.path.join(script_dir, log_filename)

# Check if the log file exists; if not, create it
if not os.path.exists(log_file):
    with open(log_file, "a") as file:
        pass  # Just create the file

# Configure logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create a logger instance
logger = logging.getLogger("ipscanner")


def cleanup_old_logs():
    """
    Clean up log files older than 3 months.
    Deletes log files matching pattern ipscannerLogs_YYYY_MM.log that are older than 3 months.
    """
    try:
        # Get current date
        current_date = datetime.now()
        current_year = current_date.year
        current_month = current_date.month
        
        # Calculate cutoff year and month (3 months ago)
        cutoff_year = current_year
        cutoff_month = current_month - 3
        
        # Handle year rollover
        while cutoff_month <= 0:
            cutoff_month += 12
            cutoff_year -= 1
        
        # Pattern to match log files: ipscannerLogs_YYYY_MM.log
        log_pattern = os.path.join(script_dir, "ipscannerLogs_*.log")
        log_files = glob.glob(log_pattern)
        
        deleted_count = 0
        for log_file_path in log_files:
            # Extract filename
            filename = os.path.basename(log_file_path)
            
            # Try to parse date from filename (ipscannerLogs_YYYY_MM.log)
            match = re.match(r'ipscannerLogs_(\d{4})_(\d{2})\.log', filename)
            if match:
                year = int(match.group(1))
                month = int(match.group(2))
                
                # Check if log file is older than 3 months
                # Compare year and month directly
                if year < cutoff_year or (year == cutoff_year and month < cutoff_month):
                    try:
                        os.remove(log_file_path)
                        deleted_count += 1
                        logger.info(f"Deleted old log file: {filename} (from {year}-{month:02d})")
                    except OSError as e:
                        logger.error(f"Failed to delete log file {filename}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Log cleanup completed: {deleted_count} old log file(s) deleted")
        else:
            logger.info("Log cleanup completed: No old log files to delete")
            
    except Exception as e:
        # Log error but don't fail the application
        logger.error(f"Error during log cleanup: {e}")