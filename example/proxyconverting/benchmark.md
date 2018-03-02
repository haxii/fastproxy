# Benchmark

## Benchmark With Socks SuperProxy

SuperProxy is a VPS in ShangHai

### Fastproxy

wrk -t4 -c16 -d10s http://127.0.0.1:8080 -s proxy.lua http://icanhazip.com

```bash
Running 10s test @ http://127.0.0.1:8080
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   609.60ms  160.71ms   1.84s    95.80%
    Req/Sec     7.86      4.90    20.00     85.43%
  259 requests in 10.05s, 99.91KB read
Requests/sec:     25.78
Transfer/sec:      9.94KB
```

### Privoxy

wrk -t4 -c16 -d10s http://127.0.0.1:8118 -s proxy.lua http://icanhazip.com

```bash
Running 10s test @ http://127.0.0.1:8118
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   623.58ms  248.39ms   1.72s    92.65%
    Req/Sec     3.51      3.69    19.00     80.33%
  68 requests in 10.06s, 43.51KB read
  Socket errors: connect 0, read 2, write 0, timeout 0
  Non-2xx or 3xx responses: 2
Requests/sec:      6.76
Transfer/sec:      4.32KB
```