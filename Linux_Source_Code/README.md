# Basic HTTP Service (Linux)

A minimal, single-threaded HTTP/1.1 server written in C using POSIX sockets. It is built to be easy to read and modify, and it serves as the clean, non-vulnerable baseline for a binary exploitation project.

## Description

The server listens on a TCP port, accepts one client at a time, parses the HTTP request, and sends back a response. It supports two routes:

| Method | Path    | Response                                     |
|--------|---------|----------------------------------------------|
| GET    | `/`     | A small HTML page with a form                |
| POST   | `/echo` | The request body, echoed back as `text/plain` |

Every request moves through the same pipeline of stages:

```
accept -> read_headers -> parse_request_line -> parse_headers
       -> validate_request -> read_body -> route_request -> close
```

### Error handling

C has no exceptions, so the server uses a try/catch pattern built from error codes:

- Every stage returns an `http_err_t`. `ERR_NONE` means success; any other value is the "thrown" error.
- `process_request()` is the **try** block. The `TRY()` macro runs a stage and returns immediately if it fails.
- `handle_client()` is the **catch** block. It looks up the error in `error_table[]` and sends the matching HTTP error response.

| Status | Cause                                                        |
|--------|--------------------------------------------------------------|
| 400    | Malformed request line, header, or `Content-Length`          |
| 404    | Unknown path                                                 |
| 405    | Known path, wrong method (e.g. `GET /echo`)                  |
| 408    | Client stopped sending for longer than the receive timeout   |
| 411    | `POST` without a `Content-Length` header                     |
| 413    | Body larger than `MAX_BODY_LEN`                              |
| 414    | Path longer than `MAX_PATH_LEN`                              |
| 431    | Request line plus headers larger than `MAX_HEADER_BYTES`     |
| 501    | Method other than GET or POST, or `Transfer-Encoding` used   |
| 505    | HTTP version other than 1.0 or 1.1                           |

All input is bounds-checked: every copy is checked against its destination size, `Content-Length` is validated before any body bytes are read, and a 5 second receive timeout stops idle clients from hanging the server.

## Requirements

- Linux (also builds on macOS)
- GCC or Clang
- `curl` and `nc` (netcat) for testing

Install on Debian, Ubuntu, or Kali:

```bash
sudo apt update
sudo apt install build-essential curl netcat-openbsd
```

Install on Fedora:

```bash
sudo dnf install gcc make curl nmap-ncat
```

## Compilation

Standard build:

```bash
gcc -Wall -Wextra -std=c11 -o server server.c
```

Debug build (symbols, no optimization, easier to step through in GDB):

```bash
gcc -Wall -Wextra -std=c11 -g -O0 -o server server.c
```

## Running

```bash
./server            # listens on port 8080
./server 9000       # listens on port 9000
```

Press Ctrl-C to stop. The server prints one log line per request:

```
Listening on http://0.0.0.0:8080
127.0.0.1:58864 "GET /" -> 200
127.0.0.1:58872 "POST /echo" -> 200
```

Ports below 1024 require root. The server binds to `0.0.0.0`, so other machines on your network can reach it. If you use a firewall such as `ufw`, allow the port with `sudo ufw allow 8080/tcp`, or change `INADDR_ANY` to `INADDR_LOOPBACK` in `create_listener()` to accept local connections only.

## Testing

Normal requests:

```bash
curl -v http://127.0.0.1:8080/
curl -v -d 'name=hello' http://127.0.0.1:8080/echo
```

Error paths:

```bash
curl -i http://127.0.0.1:8080/nope                     # 404
curl -i http://127.0.0.1:8080/echo                     # 405
curl -i -X PUT http://127.0.0.1:8080/                  # 501
```

Raw requests with netcat, which give you full control over every byte:

```bash
printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -q1 127.0.0.1 8080
printf 'POST /echo HTTP/1.1\r\n\r\n' | nc -q1 127.0.0.1 8080             # 411
printf 'GET / HTTP/2.0\r\n\r\n' | nc -q1 127.0.0.1 8080                  # 505
```

## Configuration

All limits are `#define` constants at the top of `server.c`:

| Constant           | Default | Meaning                                  |
|--------------------|---------|------------------------------------------|
| `DEFAULT_PORT`     | 8080    | Port used when none is given             |
| `BACKLOG`          | 16      | Pending connections queued by `listen()` |
| `RECV_TIMEOUT_SEC` | 5       | Seconds before an idle client gets 408   |
| `MAX_HEADER_BYTES` | 8192    | Size of the request buffer               |
| `MAX_METHOD_LEN`   | 15      | Longest accepted method                  |
| `MAX_PATH_LEN`     | 255     | Longest accepted path                    |
| `MAX_VERSION_LEN`  | 15      | Longest accepted version string          |
| `MAX_BODY_LEN`     | 4096    | Largest accepted POST body               |

## Modifying the server

**Add a route:** write a handler with the signature `static http_err_t handler(int fd, const http_request_t *req)`, then add a `strcmp` check for its path in `route_request()`.

**Add an error:** add a value to the `http_err_t` enum (before `ERR_COUNT`) and a matching row in `error_table[]`. Return it from any stage and the catch block handles the rest.

**Add a parsing stage:** write a function that returns `http_err_t` and call it with `TRY()` inside `process_request()`.

**Read another header:** add a `header_name_is()` check in `parse_header_line()` and store the value in a new field on `http_request_t`.

## Notes for exploitation work

This build is intentionally safe. When you add a vulnerability later, these are useful for controlling the environment:

Check which mitigations a binary was built with (from `pwntools`):

```bash
checksec --file=./server
```

Build with common protections turned off:

```bash
gcc -std=c11 -g -O0 -fno-stack-protector -z execstack -no-pie -o server server.c
```

| Flag                   | Disables                          |
|------------------------|-----------------------------------|
| `-fno-stack-protector` | Stack canaries                    |
| `-z execstack`         | NX (non-executable stack)         |
| `-no-pie`              | Position-independent executable   |

Temporarily disable ASLR system-wide (resets on reboot):

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Restore it with `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`.

The main stack buffer is `buf` in `process_request()`, and the parsed fields live in `http_request_t` on the stack in `handle_client()`.
