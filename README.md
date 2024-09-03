## Quiche Multipath example

Example on how to create multiple paths with [quiche](https://github.com/cloudflare/quiche), with a simple echo server.
This example is vastly inspired by the [official client/server example](https://github.com/cloudflare/quiche/tree/master/apps), but with modifications specific to multipath.

## Run the server
```bash
$ cargo run --bin server

# Example:
#
# > cargo run --bin server
# Received test on stream 0
# Received test1 on stream 4
# Received test2 on stream 8
# Closing connection to 98641fb19e8a57154f18522118fe3d650af89af9
```

## Run the client
```bash
$ cargo run --bin client -- Message1 Message2 ... MessageN

# Example:
#
# > cargo run --bin client -- test test1 test2
# Received 'test' from server on stream 0
# Received 'test1' from server on stream 4
# Received 'test2' from server on stream 8
```

## How it works

The client will request for each different message the creation of a new path
using the `conn.probe_path` method. Once this path is validated by the server, we migrate the connection to use this new path using `conn.migrate`, and then we send the message on a new stream using the `conn.stream_send` method. Note that in order to work, we must also supply enough CIDs for these new paths, which can be done using the `conn.new_scid` method.
