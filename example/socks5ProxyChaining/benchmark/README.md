# Benchmark using wrk

This example converts a local [socks5 proxy](socksserver) to http proxy using [fastproxy](main.go), [Privoxy](https://www.privoxy.org/), [Polipo](https://www.irif.fr/~jch/software/polipo/) and [V2Ray](https://www.v2ray.com/) respectively, then benchmark a [local http server](httpserver)

## Fastproxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8080 -s proxy.lua http://localhost:9090
```

```
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

## Privoxy

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8118 -s proxy.lua http://localhost:9090
```

with config

```ini
forward-socks5   /               127.0.0.1:9099 .
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

## Polipo

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:8123 -s proxy.lua http://localhost:9090
```

with config

```ini
socksParentProxy = "127.0.0.1:9099"
socksProxyType = socks5
diskCacheRoot = ""
```

```
Running 10s test @ http://127.0.0.1:8123
  4 threads and 16 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    61.78ms   93.19ms 746.39ms   90.80%
    Req/Sec   123.58    122.62   400.00     76.78%
  4724 requests in 10.04s, 761.19KB read
Requests/sec:    470.64
Transfer/sec:     75.84KB
```

## V2ray

```bash
wrk -t4 -c16 -d10s http://127.0.0.1:5000 -s proxy.lua http://localhost:9090
```

with config

```JSON
{
    "log":{"loglevel":"debug"},
    "inbound":{"port":5000,"listen":"127.0.0.1","protocol":"http","settings":{"auth":"noauth","udp":false,"ip":"127.0.0.1"}},
    "outbound":{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":9099}]}},
    "policy":{"levels":{"0":{"uplinkOnly":0}}},
    "outboundDetour":[{"protocol":"freedom","tag":"direct","settings":{}}],
    "routing":{"strategy":"rules","settings":{"domainStrategy":"IPOnDemand","rules":[{"type":"field","ip":["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","::1/128","fc00::/7","fe80::/10"],"outboundTag":"direct"}]}}
}
```

```
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
