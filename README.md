# Fastproxy

## Benchmark

### Without Any Proxy Benchmark

#### Get method for localhost 

wrk -t5 -c50 -d60s http://localhost:9000

```bash
Running 1m test @ http://localhost:9000
  5 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    15.50ms  705.52us  30.95ms   70.44%
    Req/Sec   647.74     27.02   707.00     62.43%
  193600 requests in 1.00m, 715.08MB read
Requests/sec:   3223.27
Transfer/sec:     11.91MB
```

### Privoxy Benchmark

#### Get method for localhost in Privoxy

wrk -t5 -c50 -d60s http://127.0.0.1:8118 -s proxy.lua -- http://localhost:9000

```bash
Running 1m test @ http://127.0.0.1:8118
  5 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    63.38ms   65.76ms 802.00ms   91.50%
    Req/Sec   170.61    123.25   434.00     70.23%
  32786 requests in 1.00m, 122.19MB read
  Socket errors: connect 46, read 51, write 0, timeout 0
  Non-2xx or 3xx responses: 51
Requests/sec:    545.96
Transfer/sec:      2.03MB
```

### FastProxy Benchmark

#### Get method for localhost in FastProxy

wrk -t5 -c50 -d60s http://127.0.0.1:8080 -s proxy.lua -- http://localhost:9000

```bash
Running 1m test @ http://127.0.0.1:8080
  5 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    29.07ms   78.82ms 908.86ms   97.31%
    Req/Sec   535.26    120.44   656.00     89.00%
  32689 requests in 1.00m, 120.74MB read
  Socket errors: connect 0, read 32690, write 49, timeout 0
Requests/sec:    544.78
Transfer/sec:      2.01MB
```

### GoProxy Benchmark

#### Get method for localhost in GoProxy

wrk -t5 -c50 -d60s http://127.0.0.1:8081 -s proxy.lua -- http://localhost:9000

```bash
Running 1m test @ http://127.0.0.1:8081
  5 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    16.68ms    2.29ms  51.63ms   94.62%
    Req/Sec   602.02     30.99   670.00     84.03%
  179836 requests in 1.00m, 664.24MB read
Requests/sec:   2994.94
Transfer/sec:     11.06MB
```