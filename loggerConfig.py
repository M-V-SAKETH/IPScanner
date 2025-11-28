import logging
import os

# Get the directory where loggerConfig.py is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the log file path within the script's directory
log_file = os.path.join(script_dir, "ipscannerLogs.log")

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