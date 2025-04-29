# serde syslog capnp (sersyscap)

the overkill rust library for serializing and deserializing syslog messages using cap'n proto. i use it with a Ømq publisher and subscriber :) the more complicated, the better 

but.. its pretty fast
```
Processed 1000 messages in 1.979458ms
Average message size: 88 bytes
Average time per message: 1.979µs
Processed 1m messages in 1.796509333s
Average message size: 95 bytes
Average time per message: 1.796µs
```

## Features

- binary serialization using cap'n proto
- handling of syslog message components including timestamp, source ip, facility, severity, and message content
- support for both ipv4 and ipv6 source addresses (thats right, support for ipv6, useless)
- unicode-safe message handling (i think)
- timestamp management (i just use my own timestamp)
- big ol test suite covering edge cases (edge cases my little brain code come up with)
- efficient processing of large messages

## Use Cases

- network logging infrastructure
- log aggregation systems
- syslog message storage and retrieval
- high-throughput logging systems
- cross-service logging with binary efficiency (this is why i made this)
