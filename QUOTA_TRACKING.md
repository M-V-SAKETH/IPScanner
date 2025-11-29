# Quota Tracking Implementation

## Overview

The IOC Scanner now includes comprehensive quota tracking to properly manage VirusTotal API rate limits and daily quotas. This prevents the scanner from hitting limits prematurely and allows it to process all 3000+ IOCs across your 6 API keys.

## VirusTotal Free Tier Limits

Each API key has:
- **Per-minute rate limit**: 4 requests per minute
- **Daily quota**: 500 requests per day
- **Monthly quota**: 15,500 requests per month

With 6 API keys, you have:
- **Total daily capacity**: 6 × 500 = 3,000 requests/day
- **Total per-minute capacity**: 6 × 4 = 24 requests/minute (when properly distributed)

## How It Works

### 1. Per-Minute Rate Tracking

The system tracks request timestamps for each API key:
- Maintains a sliding window of requests in the last 60 seconds
- Automatically removes timestamps older than 1 minute
- Ensures no more than 4 requests are made per key per minute
- Calculates wait time if limit is approached

### 2. Daily Quota Tracking

The system tracks daily usage per API key:
- Resets automatically each day (based on date)
- Warns when a key reaches 90% of daily quota
- Prevents using keys that have exhausted their daily quota
- Distributes load evenly across all available keys

### 3. Proactive Key Switching

The scanner now:
- Checks key availability **before** making a request
- Switches to available keys automatically
- Waits intelligently when all keys are temporarily rate-limited
- Distributes requests evenly across all 6 keys

### 4. Smart Rate Limiting

The system enforces:
- Minimum 15 seconds between requests per key (respects 4/min limit)
- Automatic wait when rate limit is reached
- Proper cleanup of old request timestamps

## Key Improvements

### Before (Old Implementation)
- ❌ Only switched keys **after** getting 429 errors
- ❌ 1 second delay was too fast (violated 4/min limit)
- ❌ No daily quota tracking
- ❌ All keys would hit limits simultaneously
- ❌ Stopped at ~1041 IOCs instead of 3000

### After (New Implementation)
- ✅ Proactively checks key availability before requests
- ✅ Enforces proper delays (15 seconds per key minimum)
- ✅ Tracks daily quota per key
- ✅ Distributes load evenly across keys
- ✅ Can process all 3000+ IOCs efficiently

## Configuration

Settings in `config.py`:

```python
MAX_REQUESTS_PER_MINUTE = 4  # Per API key
MAX_REQUESTS_PER_DAY = 500   # Per API key
MIN_DELAY_BETWEEN_REQUESTS = 15  # Seconds (60/4 = 15)
QUOTA_WARNING_THRESHOLD = 0.9  # Warn at 90% usage
```

## Expected Performance

With 6 API keys:
- **Per-minute throughput**: Up to 24 requests/minute (4 per key)
- **Hourly capacity**: ~1,440 requests/hour
- **Daily capacity**: 3,000 requests/day
- **Time for 3000 IOCs**: ~2-3 hours (with proper rate limiting)

## Monitoring

The system logs:
- Daily quota usage per key
- Per-minute request counts
- Automatic key switching
- Rate limit wait times
- Quota warnings (at 90% usage)

Check the logs for messages like:
```
Checking IP: 1.2.3.4 (using key 0, daily: 450/500)
API key 0 has used 450/500 requests today (90.0%)
```

## Troubleshooting

### If scanner stops before 3000 IOCs:

1. **Check daily quotas**: Keys may have been used earlier today
   - Solution: Wait for next day or use additional API keys

2. **Check logs**: Look for quota exhaustion messages
   - All keys show "Daily quota exhausted"

3. **Verify rate limiting**: Ensure no external processes are using the keys

### If requests are too slow:

The 15-second minimum delay per key is necessary to respect VirusTotal's 4 requests/minute limit. This is normal and expected behavior.

## Best Practices

1. **Run scans during off-peak hours** to maximize throughput
2. **Monitor quota usage** in logs
3. **Don't run multiple scanner instances** simultaneously (would share quotas)
4. **Resume from where you left off** using the start_index feature

## Technical Details

### Data Structures

```python
# Per-minute tracking
requests_per_minute = {
    0: [timestamp1, timestamp2, ...],  # Key 0's requests
    1: [timestamp1, timestamp2, ...],  # Key 1's requests
    ...
}

# Daily quota tracking
daily_quota = {
    0: {"2025-11-29": 450},  # Key 0 used 450 today
    1: {"2025-11-29": 380},  # Key 1 used 380 today
    ...
}
```

### Key Methods

- `_is_key_available()`: Checks if a key can be used
- `_find_available_key()`: Finds the next available key
- `_wait_for_rate_limit()`: Waits until a key is available
- `get_quota_status()`: Returns current quota status for all keys

