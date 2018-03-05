# Benchmark

## Benchmark With Socks SuperProxy

SuperProxy is a VPS in ShangHai

### Fastproxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8080 -s proxy.lua http://www.duolaima.com
```

```bash
Running 10s test @ http://127.0.0.1:8080
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   319.51ms   41.61ms 468.80ms   72.32%
    Req/Sec    12.94      6.52    30.00     73.90%
  495 requests in 10.07s, 2.42MB read
Requests/sec:     49.16
Transfer/sec:    246.47KB
```

### Privoxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8118 -s proxy.lua http://www.duolaima.com
```

```bash
Running 10s test @ http://127.0.0.1:8118
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   323.21ms   44.22ms 461.85ms   69.73%
    Req/Sec    12.47      5.95    30.00     67.01%
  489 requests in 10.08s, 2.41MB read
  Socket errors: connect 0, read 1, write 0, timeout 0
  Non-2xx or 3xx responses: 1
Requests/sec:     48.52
Transfer/sec:    244.92KB
```

### Polipo

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8123 -s proxy.lua http://www.duolaima.com
```

```bash
Running 10s test @ http://127.0.0.1:8123
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   188.45ms  195.90ms   1.63s    96.72%
    Req/Sec     5.98      3.10    10.00     76.56%
  64 requests in 10.10s, 322.41KB read
  Socket errors: connect 0, read 0, write 0, timeout 3
Requests/sec:      6.34
Transfer/sec:     31.93KB
```

### V2ray

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:5000 -s proxy.lua http://www.duolaima.com
```

```bash
Running 10s test @ http://127.0.0.1:5000
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   335.91ms   52.15ms 521.57ms   72.51%
    Req/Sec    12.38      6.06    30.00     60.41%
  422 requests in 10.08s, 2.10MB read
  Socket errors: connect 0, read 422, write 0, timeout 0
Requests/sec:     41.88
Transfer/sec:    213.11KB
```
