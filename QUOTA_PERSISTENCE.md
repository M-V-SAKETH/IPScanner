# Quota Persistence Implementation

## Problem Solved

Previously, the quota tracking was **in-memory only**, meaning:
- ❌ Quota data was lost when the script restarted
- ❌ The script didn't remember how many requests were made today
- ❌ All keys would appear to have full quota (0/500) after restart
- ❌ Failed requests (429 errors) were incorrectly counted toward quota

## Solution

Implemented **JSON-based quota persistence** that:
- ✅ Saves quota data to a file (`api_quota_tracking.json`)
- ✅ Loads quota data on script startup
- ✅ Remembers daily usage across script restarts
- ✅ Only counts **successful requests** (200, 404) toward quota
- ✅ **Does NOT count** failed requests (429, 400, 403, 500)

## Changes Made

### 1. Configuration (`config.py`)

Added quota file path:
```python
QUOTA_FILE = "api_quota_tracking.json"  # File to persist quota tracking data
```

### 2. VirusTotal Client (`virustotal_client.py`)

**New Features:**
- `_load_quota_data()` - Loads quota data from JSON file on startup
- `_save_quota_data()` - Saves quota data after each successful request
- `print_quota_status()` - Displays quota status for all keys on startup
- Fixed quota counting to only increment on successful requests

**Quota Counting Logic:**
- ✅ **Increments quota**: Status codes 200 (success) and 404 (not found)
- ❌ **Does NOT increment**: Status codes 429 (rate limit), 400 (bad request), 403 (forbidden), 500 (server error)

## JSON File Structure

The quota file (`api_quota_tracking.json`) stores:

```json
{
  "daily_quota": {
    "0": {"2025-11-29": 450},
    "1": {"2025-11-29": 380},
    "2": {"2025-11-29": 500},
    "3": {"2025-11-29": 200},
    "4": {"2025-11-29": 150},
    "5": {"2025-11-29": 320}
  },
  "last_updated": "2025-11-29T18:45:23.123456"
}
```

## How It Works

### On Script Startup:
1. Script loads quota data from `api_quota_tracking.json`
2. Displays quota status for all keys:
   ```
   ==================================================
   API Key Quota Status (Today: 2025-11-29)
   ==================================================
   ✓ Key 0: 450/500 used ( 50 remaining) [90.0%]
   ✓ Key 1: 380/500 used (120 remaining) [76.0%]
   ✗ Key 2: 500/500 used (  0 remaining) [100.0%]
   ...
   ```

### During Scanning:
1. Before each request: Checks if key has quota available
2. Makes request to VirusTotal API
3. If successful (200 or 404):
   - Increments daily quota count
   - Saves to JSON file immediately
4. If failed (429, 400, etc.):
   - Does NOT increment quota
   - Tries next key or waits

### After Script Restart:
- Quota data is preserved
- Script knows exactly how many requests were made today
- Won't try to use keys that are already exhausted

## Benefits

1. **Persistent Tracking**: Remembers quota across restarts
2. **Accurate Counting**: Only counts successful API calls
3. **Automatic Management**: No manual intervention needed
4. **Easy Inspection**: Can open JSON file to see usage
5. **No Database Required**: Simple JSON file is sufficient

## Example Scenario

**Before (Old System):**
```
Run 1: Processed 1000 IOCs, used 1000 quota
Stop script
Run 2: Script thinks all keys have 0/500 used (WRONG!)
      → Tries to use exhausted keys
      → Gets 429 errors immediately
```

**After (New System):**
```
Run 1: Processed 1000 IOCs, used 1000 quota
      → Saved to api_quota_tracking.json
Stop script
Run 2: Script loads quota from file
      → Shows: Key 0: 500/500 used, Key 1: 500/500 used
      → Automatically skips exhausted keys
      → Only uses keys with remaining quota
```

## Manual Quota Management

If needed, you can manually edit or reset the quota file:

### Reset All Quotas:
```bash
# Delete the file to start fresh
rm api_quota_tracking.json
```

### Manual Edit:
```bash
# Edit the JSON file to adjust quota counts
# (Use with caution - could cause incorrect tracking)
```

### View Current Quotas:
```bash
# The quota status is printed automatically on startup
# Or check the JSON file:
cat api_quota_tracking.json
```

## Troubleshooting

### If quota file is missing:
- Script will create it automatically on first successful request
- All keys will start at 0/500

### If quota shows incorrect counts:
- Check if failed requests were previously counted (old version)
- Delete the file to reset
- New version only counts successful requests

### If all keys show as exhausted:
- Check the JSON file to verify
- Wait until next day (quotas reset daily based on date)
- Or manually reset specific keys in the JSON file

## File Location

The quota file is saved in the same directory as the script:
- File: `api_quota_tracking.json`
- Path: Same as `ipscannerLogs.log` and `ioc_input.csv`

## Notes

- Quota tracking is per-day (resets at midnight)
- Old dates in the JSON file are automatically ignored
- File is updated after each successful API request
- Failed requests (429, etc.) are NOT counted toward quota

