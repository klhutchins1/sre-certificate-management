# Domain Scanning Performance Investigation Report

## Executive Summary

**Issue**: Domain scanning takes 5+ minutes for 30 domains despite configured 2-second timeouts and 120 requests/minute rate limiting.

**Root Cause**: Sequential processing architecture with multiple scan types per domain, conservative default rate limits, and lack of parallel processing.

**Expected vs Actual Performance**:
- **Expected**: ~30 seconds (30 domains × 1 second average)
- **Actual**: 5+ minutes (300+ seconds)
- **Performance Gap**: 10x slower than expected

## Key Findings

### 1. Sequential Processing Architecture (Primary Bottleneck)

**Problem**: All domains are processed sequentially in a single-threaded loop:

```python
# From ScanService.run_scan()
while self.scan_manager.has_pending_targets():
    target = self.scan_manager.get_next_target()
    scan_result = self.scan_manager.scan_target(
        session=session,
        domain=target[0], 
        port=target[1],
        **options
    )
```

**Impact**: Each domain must complete fully before the next domain begins, preventing any parallelization.

### 2. Multiple Scan Types Per Domain

**Problem**: Each domain undergoes 5-7 different scan operations sequentially:

For **Domain Targets**:
1. Certificate scan (with chain validation)
2. DNS records lookup
3. WHOIS query  
4. IP address resolution
5. Platform detection
6. Subdomain discovery (if enabled)
7. SAN processing (if enabled)

For **IP Targets**:
1. Certificate scan (with chain validation)
2. WHOIS query
3. Platform detection

**Impact**: Each domain requires 5-7 network operations, significantly multiplying scan time.

### 3. Rate Limiting Bottlenecks

**Configured Rate Limits** (from config analysis):
- DNS queries: 120/minute (2 per second) ✓ Matches user setting
- WHOIS queries: **10/minute (1 every 6 seconds)** ❌ Major bottleneck
- Certificate scans: 30/minute (1 every 2 seconds)
- Default operations: 360/minute (6 per second)

**Problem**: WHOIS rate limiting is extremely conservative at 10/minute, meaning each WHOIS query introduces a 6-second delay.

### 4. Timeout Configuration Issues

**User Configuration**: 2-second timeouts
**System Defaults** (from settings.py):
```yaml
timeouts:
  dns: 5.0
  request: 15
  socket: 10
  whois: 10
```

**Problem**: Multiple timeout windows per domain:
- DNS resolution: 5 seconds
- Certificate retrieval: 10 seconds  
- WHOIS lookup: 10 seconds
- Chain validation: Additional 10 seconds

### 5. Lack of Concurrency

**Observation**: No threading, async/await, or parallel processing found in:
- `ScanManager`
- `DomainScanner` 
- `CertificateScanner`
- `ScanService`

**Impact**: Cannot leverage multiple CPU cores or concurrent I/O operations.

## Performance Calculation

### Current Sequential Model (30 domains):
```
Per Domain Operations:
- Certificate scan: 2-10 seconds (timeout + rate limiting)
- DNS lookup: 2-5 seconds  
- WHOIS query: 6+ seconds (rate limiting: 10/minute)
- Platform detection: 1-3 seconds
- Chain validation: 2-10 seconds

Total per domain: 13-34 seconds
30 domains × 20 seconds average = 600 seconds (10 minutes)
```

### With Rate Limiting Delays:
```
WHOIS bottleneck: 30 domains × 6 seconds = 180 seconds (3 minutes)
Other operations: 30 domains × 10 seconds = 300 seconds (5 minutes)
Total: 480 seconds (8 minutes)
```

**Matches observed 5+ minute performance**.

## Solution Recommendations

### 1. Implement Parallel Domain Processing (High Impact)

**Current Architecture**:
```python
for domain in domains:
    scan_domain_sequential(domain)  # 20+ seconds each
```

**Recommended Architecture**:
```python
import concurrent.futures
import asyncio

async def scan_domains_parallel(domains):
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = [executor.submit(scan_domain, domain) for domain in domains]
        results = await asyncio.gather(*tasks)
    return results
```

**Expected Improvement**: 5-10x faster (limited by slowest domain rather than sum of all domains)

### 2. Optimize Rate Limiting Configuration (Medium Impact)

**Current WHOIS Rate Limit**: 10/minute (major bottleneck)
**Recommended WHOIS Rate Limit**: 60/minute (matches other services)

**Configuration Change**:
```yaml
scanning:
  whois:
    rate_limit: 60  # Change from 10 to 60
```

**Expected Improvement**: 6x faster WHOIS operations

### 3. Implement Concurrent Scan Types Per Domain (High Impact)

**Current**: Sequential scan types per domain
**Recommended**: Parallel scan types per domain

```python
async def scan_domain_concurrent(domain):
    tasks = [
        scan_certificate(domain),
        scan_dns(domain), 
        scan_whois(domain),
        detect_platform(domain)
    ]
    results = await asyncio.gather(*tasks)
    return merge_results(results)
```

**Expected Improvement**: 3-4x faster per domain

### 4. Implement Smart Timeouts (Medium Impact)

**Current**: Fixed timeouts for all operations
**Recommended**: Adaptive timeouts based on operation type

```python
OPTIMIZED_TIMEOUTS = {
    'dns': 2.0,        # DNS is usually fast
    'certificate': 5.0, # Certificate retrieval
    'whois': 10.0,     # WHOIS can be slower
    'socket': 3.0,     # Connection establishment
}
```

### 5. Add Caching Layer (Medium Impact)

**Problem**: Repeated scans hit the same external services
**Solution**: Implement scan result caching

```python
@cached(ttl=300)  # 5-minute cache
def whois_lookup(domain):
    return whois.query(domain)
```

## Implementation Priority

### Phase 1: Quick Wins (1-2 days)
1. **Increase WHOIS rate limit** from 10 to 60/minute
2. **Reduce timeout values** to user-specified 2 seconds where appropriate
3. **Enable DNS caching** for repeated queries

**Expected Improvement**: 2-3x faster scanning

### Phase 2: Parallel Domain Processing (1 week)
1. **Implement ThreadPoolExecutor** for concurrent domain scanning
2. **Add domain-level batching** (process 5-10 domains simultaneously)
3. **Implement progress tracking** for parallel operations

**Expected Improvement**: 5-10x faster scanning

### Phase 3: Advanced Optimizations (2-3 weeks)
1. **Concurrent scan types** per domain
2. **Async/await implementation** throughout scanning pipeline  
3. **Result streaming** instead of batch processing
4. **Advanced caching strategies**

**Expected Improvement**: 10-20x faster scanning

## Configuration Changes for Immediate Relief

### Update config.yaml:
```yaml
scanning:
  whois:
    rate_limit: 60    # Increase from 10
    timeout: 2        # Reduce from 10
  dns:
    rate_limit: 120   # Keep existing
    timeout: 2        # Reduce from 5
  timeouts:
    socket: 2         # Reduce from 10
    request: 2        # Reduce from 15
    dns: 2.0         # Reduce from 5.0
```

### Expected Result:
- **30 domains in ~60-90 seconds** instead of 5+ minutes
- **4-5x performance improvement** with configuration changes alone

## Monitoring and Validation

### Add Performance Metrics:
```python
import time

def scan_with_metrics(domains):
    start_time = time.time()
    results = scan_domains(domains)
    end_time = time.time()
    
    metrics = {
        'total_time': end_time - start_time,
        'domains_per_second': len(domains) / (end_time - start_time),
        'avg_time_per_domain': (end_time - start_time) / len(domains)
    }
    return results, metrics
```

### Target Performance Goals:
- **30 domains in 30-60 seconds** (1-2 seconds per domain average)
- **500+ domains per minute** throughput with full parallelization
- **Sub-second response** for cached results

## Conclusion

The 5+ minute scanning time for 30 domains is caused by:
1. **Sequential processing** (biggest factor)
2. **Conservative WHOIS rate limiting** (10/minute bottleneck)
3. **Multiple sequential operations** per domain
4. **Lack of caching** for repeated queries

**Immediate relief** can be achieved through configuration changes (4-5x improvement).
**Long-term solution** requires architectural changes to support parallel processing (10-20x improvement).

The scanning system was designed for thoroughness rather than speed, but with the recommended optimizations, it can achieve both comprehensive scanning and high performance.