# IOC Scanner

A modular IOC (Indicators of Compromise) scanner that checks IP addresses, domain names, and file hashes against the VirusTotal API.

## Features

- **Multi-IOC Support**: Scans IP addresses, domain names, and file hashes (MD5/SHA256)
- **Batch Processing**: Efficiently handles large CSV files (5000-10,000+ entries)
- **Batch Saving**: Saves progress periodically instead of after every row (prevents I/O bottlenecks)
- **Retry Logic**: Automatic retry mechanism for transient network errors
- **API Key Rotation**: Automatic rotation through multiple VirusTotal API keys
- **Rate Limiting**: Built-in rate limiting and API quota management
- **Resume Capability**: Can resume scanning from any starting row index
- **Error Handling**: Robust error handling for network issues, timeouts, and API errors
- **Command Interface**: Interactive commands to stop or check status during scanning
- **Logging**: Comprehensive logging for debugging and audit trails

## Project Structure

The project is now modularized for better maintainability:

```
IPScanner/
├── main.py                 # Entry point for the application
├── config.py               # Configuration constants and settings
├── ioc_validator.py        # IOC detection and validation logic
├── virustotal_client.py    # VirusTotal API client with retry logic
├── csv_handler.py          # CSV file operations with batch saving
├── scanner.py              # Main scanning logic and orchestration
├── loggerConfig.py         # Logging configuration
├── requirements.txt        # Python dependencies
├── ioc_input.csv          # Input CSV file with IOCs
└── README.md              # This file
```

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Prepare your CSV file (`ioc_input.csv`) with the following columns:
   - `Sno` (optional): Serial number
   - `IOC`: The IOC to scan (IP, domain, or hash)
   - `Status`: Leave empty for new entries
   - `Link`: Will be populated automatically
   - `last_analysis_stats`: Will be populated automatically
   - `Country`: Will be populated automatically (for IPs)
   - `whois_date`: Will be populated automatically
   - `Last_Modification_Date`: Will be populated automatically
   - `AS_Owner`: Will be populated automatically (for IPs)

2. Run the scanner:
```bash
python main.py
```

3. Enter the starting row number (1-based index) when prompted.

4. The scanner will process IOCs and save progress periodically.

## Configuration

Edit `config.py` to customize:

- **API Keys**: Add or modify VirusTotal API keys
- **Rate Limiting**: Adjust delays between API requests
- **Batch Saving**: Configure how often to save CSV (default: every 10 IOCs)
- **Retry Settings**: Configure retry attempts and delays
- **File Paths**: Change input file path if needed

## Key Improvements for Large Files

### Batch Saving
- **Old**: Saved entire CSV after every single IOC (extremely slow for large files)
- **New**: Saves in batches (every 10 IOCs by default), reducing I/O operations by ~90%

### Retry Logic
- Automatic retry for transient network errors
- Exponential backoff between retries
- Maximum 3 retry attempts by default

### Memory Management
- More efficient DataFrame operations
- Reduced memory footprint for large datasets

### Error Handling
- Better exception handling prevents unexpected stops
- Network timeout handling (30 seconds default)
- API error handling with automatic key rotation

## Commands During Execution

While the scanner is running, you can type:

- `stop`, `q`, `quit`, or `exit`: Stop the scanner gracefully
- `status`: Check current progress (processed/total items)
- `Ctrl+C`: Emergency stop (also handled gracefully)

## Logging

Logs are written to `ipscannerLogs.log` in the same directory as the script.

## Notes

- The scanner automatically skips already processed IOCs (those with a Status value)
- Wildcard entries and invalid IOC types are marked and skipped
- Progress is saved periodically to prevent data loss
- The scanner can be safely stopped and resumed later from any row index
