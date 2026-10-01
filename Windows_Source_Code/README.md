# Basic HTTP Service (Windows)

A minimal, single-threaded HTTP/1.1 server written in C using the Winsock API. It is built to be easy to read and modify, and it serves as the clean, non-vulnerable baseline for a binary exploitation project. This is the Windows port of the Linux version; the parsing logic and error model are identical, and only the socket and OS glue differ.

## Description

The server listens on a TCP port, accepts one client at a time, parses the HTTP request, and sends back a response. It supports two routes:

| Method | Path    | Response                                     |
|--------|---------|----------------------------------------------|
| GET    | `/`     | A small HTML page with a form                |
| POST   | `/echo` | The request body, echoed back as `text/plain` |

Every request moves through the same pipeline of stages:

```
WSAStartup -> socket -> bind -> listen -> accept loop:
  read_headers -> parse_request_line -> parse_headers
  -> validate_request -> read_body -> route_request -> closesocket
-> WSACleanup
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

### What differs from the Linux build

Each of these is marked with a `WINDOWS:` comment in the source.

- Includes `<winsock2.h>` and `<ws2tcpip.h>` instead of the POSIX socket headers.
- Calls `WSAStartup()` at launch and `WSACleanup()` at exit.
- Sockets are the `SOCKET` type and are closed with `closesocket()`.
- Socket errors come from `WSAGetLastError()`; the receive timeout maps from `WSAETIMEDOUT`.
- `SO_RCVTIMEO` is set as a `DWORD` of milliseconds.
- Ctrl-C is handled with `SetConsoleCtrlHandler()`, which closes the listening socket to break out of `accept()`.
- `_strnicmp()` is used in place of `strncasecmp()`.

## Requirements

You need one of the following toolchains.

**Option A: Visual Studio (MSVC).** Install "Visual Studio Community" with the "Desktop development with C++" workload, or the standalone "Build Tools for Visual Studio". This gives you the `cl` compiler and a "Developer Command Prompt for VS".

**Option B: MinGW-w64.** Install via [MSYS2](https://www.msys2.org/), then from an MSYS2 shell:

```bash
pacman -S mingw-w64-x86_64-gcc
```

`curl.exe` ships with Windows 10 and later, so it is available in both Command Prompt and PowerShell for testing.

## Compilation

**MSVC** (from a Developer Command Prompt for VS):

```bat
cl /nologo /W4 server.c /Fe:server.exe
```

Winsock is linked automatically by the `#pragma comment(lib, "Ws2_32.lib")` line in the source.

Debug build:

```bat
cl /nologo /W4 /Zi /Od server.c /Fe:server.exe
```

**MinGW-w64** (from an MSYS2 MinGW 64-bit shell). This compiler does not honor the `#pragma`, so link the library explicitly:

```bash
gcc -Wall -Wextra -std=c11 -o server.exe server.c -lws2_32
```

## Running

From Command Prompt or PowerShell:

```bat
server.exe            REM listens on port 8080
server.exe 9000       REM listens on port 9000
```

Press Ctrl-C to stop. The server prints one log line per request:

```
Listening on http://0.0.0.0:8080
127.0.0.1:58864 "GET /" -> 200
127.0.0.1:58872 "POST /echo" -> 200
```

The first time you run it, Windows Defender Firewall will likely show a prompt asking whether to allow the program to communicate on the network. Allow it (private networks is enough for local testing), or keep testing against `127.0.0.1` only. The server binds to `0.0.0.0`, so to accept local connections only, change `INADDR_ANY` to `INADDR_LOOPBACK` in `create_listener()`.

## Testing

Normal requests:

```bat
curl.exe -v http://127.0.0.1:8080/
curl.exe -v -d "name=hello" http://127.0.0.1:8080/echo
```

Use double quotes on Windows shells, not single quotes.

Error paths:

```bat
curl.exe -i http://127.0.0.1:8080/nope                 REM 404
curl.exe -i http://127.0.0.1:8080/echo                 REM 405
curl.exe -i -X PUT http://127.0.0.1:8080/              REM 501
```

In PowerShell, prefer `curl.exe` (with the `.exe`) so you get the real curl rather than the `Invoke-WebRequest` alias.

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

**Add a route:** write a handler with the signature `static http_err_t handler(SOCKET fd, const http_request_t *req)`, then add a `strcmp` check for its path in `route_request()`.

**Add an error:** add a value to the `http_err_t` enum (before `ERR_COUNT`) and a matching row in `error_table[]`. Return it from any stage and the catch block handles the rest.

**Add a parsing stage:** write a function that returns `http_err_t` and call it with `TRY()` inside `process_request()`.

**Read another header:** add a `header_name_is()` check in `parse_header_line()` and store the value in a new field on `http_request_t`.

## Notes for exploitation work

This build is intentionally safe. When you add a vulnerability later, the mitigation landscape on Windows is different from Linux and is worth knowing.

MSVC enables several protections by default. To build a softer target for class work:

```bat
cl /nologo /Zi /Od /GS- server.c /Fe:server.exe
```

| MSVC flag | Effect                                                  |
|-----------|---------------------------------------------------------|
| `/GS-`    | Disables stack buffer security checks (stack cookies)   |
| `/Od`     | Disables optimization                                   |
| `/Zi`     | Generates debug symbols                                 |

Other relevant linker mitigations you may want to control for a lab: `/DYNAMICBASE:NO` disables ASLR, `/NXCOMPAT:NO` disables DEP, and `/SAFESEH:NO` (x86 only) disables Safe Structured Exception Handling. Note that true SEH-overwrite techniques apply to 32-bit builds; x64 uses table-based exception handling instead, so compile for x86 if your coursework targets SEH.

The main stack buffer is `buf` in `process_request()`, and the parsed fields live in `http_request_t` on the stack in `handle_client()`.

Recommended debuggers on Windows: [x64dbg](https://x64dbg.com/) and WinDbg, usually paired with the [pwndbg](https://github.com/pwndbg/pwndbg) or similar workflow you already use.
