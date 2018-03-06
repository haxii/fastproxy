# Benchmark

## Benchmark With Socks SuperProxy

Test with a local socks5 proxy server and a local http server

### Fastproxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8080 -s proxy.lua http://localhost:9090
```

```bash
Running 10s test @ http://127.0.0.1:8080
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     6.37ms    8.34ms 127.97ms   98.65%
    Req/Sec   702.18    117.54   830.00     93.97%
  16364 requests in 10.10s, 2.18MB read
  Socket errors: connect 14, read 17, write 0, timeout 0
Requests/sec:   1620.07
Transfer/sec:    221.49KB
```

### Privoxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8118 -s proxy.lua http://localhost:9090
```

```bash
Running 10s test @ http://127.0.0.1:8118
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    77.48ms  235.06ms   1.28s    91.57%
    Req/Sec   638.29    166.12   810.00     89.02%
  16386 requests in 10.10s, 2.79MB read
  Socket errors: connect 12, read 20, write 0, timeout 0
  Non-2xx or 3xx responses: 20
Requests/sec:   1621.60
Transfer/sec:    283.14KB
```

### Polipo

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8123 -s proxy.lua http://localhost:9090
```

```bash
Running 10s test @ http://127.0.0.1:8123
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   619.81us  426.42us   3.82ms   63.42%
    Req/Sec     6.68k   180.68     7.20k    70.30%
  268559 requests in 10.10s, 44.06MB read
Requests/sec:  26591.35
Transfer/sec:      4.36MB
```

### V2ray

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:5000 -s proxy.lua http://localhost:9090
```

```bash
Running 10s test @ http://127.0.0.1:5000
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.99ms   90.91ms 814.86ms   93.80%
    Req/Sec   431.23    141.82   525.00     87.50%
  8333 requests in 10.01s, 1.71MB read
  Socket errors: connect 0, read 8204, write 0, timeout 0
  Non-2xx or 3xx responses: 129
Requests/sec:    832.53
Transfer/sec:    174.94KB
```
