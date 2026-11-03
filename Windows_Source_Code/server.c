/*
 * server.c - minimal single-threaded HTTP/1.1 server (Windows / Winsock)
 *
 * Routes:
 *   GET  /       -> small HTML page with a form
 *   POST /echo   -> echoes the request body back as text/plain
 *
 * Build (MSVC, from a 32-bit "x86 Native Tools" Developer Command Prompt):
 *   cl /nologo /W4 /GS- server.c /Fe:server.exe /link /SAFESEH:NO /DYNAMICBASE:NO /NXCOMPAT:NO
 * Build (MinGW-w64, 32-bit toolchain i686):
 *   i686-w64-mingw32-gcc -Wall -Wextra -std=c11 -fno-stack-protector -o server.exe server.c -lws2_32 -Wl,--disable-dynamicbase,--disable-nxcompat
 *
 * NOTE: handle_post_echo() is intentionally vulnerable to a stack buffer
 * overflow (strcpy into a fixed-size buffer). It can be exploited two ways:
 *   - saved return-address overwrite, and
 *   - SEH (structured exception handler) overwrite.
 *
 * MITIGATIONS: build 32-bit (x86). SEH overwrite is an x86 technique -- on
 * x64 Windows the exception handlers live in a .pdata table, not on the
 * stack, so the overflow cannot reach them. The flags turn off stack
 * cookies (/GS-), SafeSEH (/SAFESEH:NO, so a hijacked handler isn't
 * validated), ASLR (/DYNAMICBASE:NO) and DEP (/NXCOMPAT:NO). SEHOP is an
 * OS/process setting; disable it for the exercise if it is on. For the SEH
 * path you also need a "pop pop ret" gadget in a module built WITHOUT
 * SafeSEH (this .exe qualifies, since /SAFESEH:NO is set above).
 *
 * Run:   server.exe [port]          (default 8080, Ctrl-C to stop)
 * Test:  curl.exe -v http://127.0.0.1:8080/
 *        curl.exe -v -d "name=hello" http://127.0.0.1:8080/echo
 *
 * ---------------------------------------------------------------------
 * Error handling model ("try / catch" in C)
 * ---------------------------------------------------------------------
 * C has no exceptions, so every step that touches input returns an
 * http_err_t. ERR_NONE means success; anything else is the "exception".
 *
 *   process_request()  is the TRY block. It runs each stage in order
 *                      and the TRY() macro bails out at the first error.
 *   handle_client()    is the CATCH block. It turns the error code into
 *                      the matching HTTP response using error_table[].
 *
 * To add a new error: add a value to http_err_t and a row to
 * error_table[]. To add a new stage: write a function that returns
 * http_err_t and call it with TRY() inside process_request().
 *
 * Request flow:
 *   WSAStartup -> socket -> bind -> listen -> accept loop:
 *     read_headers -> parse_request_line -> parse_headers
 *     -> validate_request -> read_body -> route_request -> closesocket
 *   -> WSACleanup
 *
 * Differences from the Linux version are marked with "WINDOWS:".
 */

/* WINDOWS: target Windows 7+ so inet_ntop() is available. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
/* MSVC refuses strcpy() without this (warning C4996). */
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WINDOWS: tell MSVC to link the Winsock library automatically.
 * (MinGW ignores this, so pass -lws2_32 on its command line.) */
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

/* =====================================================================
 * Configuration
 * ===================================================================== */

#define DEFAULT_PORT      8080
#define BACKLOG           16
#define RECV_TIMEOUT_SEC  5

#define MAX_HEADER_BYTES  8192   /* request line + all header lines   */
#define MAX_METHOD_LEN    15     /* e.g. "GET", "POST"                */
#define MAX_PATH_LEN      255    /* e.g. "/echo"                      */
#define MAX_VERSION_LEN   15     /* e.g. "HTTP/1.1"                   */
#define MAX_BODY_LEN      4096   /* largest POST body we will accept  */

/* =====================================================================
 * Error codes (the "exceptions") and how each one is reported
 * ===================================================================== */

typedef enum {
    ERR_NONE = 0,
    ERR_CLIENT_CLOSED,        /* connection gone, nothing to send back */
    ERR_BAD_REQUEST,          /* 400 */
    ERR_NOT_FOUND,            /* 404 */
    ERR_METHOD_NOT_ALLOWED,   /* 405 */
    ERR_TIMEOUT,              /* 408 */
    ERR_LENGTH_REQUIRED,      /* 411 */
    ERR_BODY_TOO_LARGE,       /* 413 */
    ERR_URI_TOO_LONG,         /* 414 */
    ERR_HEADERS_TOO_LARGE,    /* 431 */
    ERR_INTERNAL,             /* 500 */
    ERR_NOT_IMPLEMENTED,      /* 501 */
    ERR_VERSION_UNSUPPORTED,  /* 505 */
    ERR_COUNT                 /* keep last: number of error codes */
} http_err_t;

typedef struct {
    int         status;    /* HTTP status code (0 = send nothing) */
    const char *reason;    /* reason phrase on the status line     */
    const char *message;   /* plain-text body sent to the client   */
} error_info_t;

static const error_info_t error_table[ERR_COUNT] = {
    [ERR_NONE]                = {200, "OK", ""},
    [ERR_CLIENT_CLOSED]       = {0,   "",   ""},
    [ERR_BAD_REQUEST]         = {400, "Bad Request",
                                 "The request was malformed.\n"},
    [ERR_NOT_FOUND]           = {404, "Not Found",
                                 "No such resource.\n"},
    [ERR_METHOD_NOT_ALLOWED]  = {405, "Method Not Allowed",
                                 "That method is not allowed on this path.\n"},
    [ERR_TIMEOUT]             = {408, "Request Timeout",
                                 "Timed out waiting for the request.\n"},
    [ERR_LENGTH_REQUIRED]     = {411, "Length Required",
                                 "POST requests need a Content-Length header.\n"},
    [ERR_BODY_TOO_LARGE]      = {413, "Content Too Large",
                                 "The request body is too large.\n"},
    [ERR_URI_TOO_LONG]        = {414, "URI Too Long",
                                 "The request path is too long.\n"},
    [ERR_HEADERS_TOO_LARGE]   = {431, "Request Header Fields Too Large",
                                 "The request headers are too large.\n"},
    [ERR_INTERNAL]            = {500, "Internal Server Error",
                                 "Something went wrong on the server.\n"},
    [ERR_NOT_IMPLEMENTED]     = {501, "Not Implemented",
                                 "This server only supports GET and POST.\n"},
    [ERR_VERSION_UNSUPPORTED] = {505, "HTTP Version Not Supported",
                                 "Only HTTP/1.0 and HTTP/1.1 are supported.\n"},
};

/* Run a stage; if it fails, stop and pass the error up to the caller. */
#define TRY(call)                                   \
    do {                                            \
        http_err_t err_ = (call);                   \
        if (err_ != ERR_NONE) return err_;          \
    } while (0)

/* =====================================================================
 * Parsed request
 * ===================================================================== */

typedef struct {
    char   method[MAX_METHOD_LEN + 1];
    char   path[MAX_PATH_LEN + 1];
    char   version[MAX_VERSION_LEN + 1];
    long   content_length;            /* -1 if header not present */
    char   body[MAX_BODY_LEN + 1];    /* NUL-terminated for convenience */
    size_t body_len;
} http_request_t;

/* =====================================================================
 * Small helpers
 * ===================================================================== */

/* Find "\r\n" in [p, end). Returns pointer to the '\r', or NULL. */
static const char *find_crlf(const char *p, const char *end)
{
    for (; p + 1 < end; p++) {
        if (p[0] == '\r' && p[1] == '\n')
            return p;
    }
    return NULL;
}

/* Returns the length of the header block (through "\r\n\r\n"), or 0. */
static size_t find_header_end(const char *buf, size_t len)
{
    for (size_t i = 3; i < len; i++) {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
            buf[i - 1] == '\r' && buf[i]     == '\n')
            return i + 1;
    }
    return 0;
}

/* Case-insensitive compare of a header name against an expected name.
 * WINDOWS: _strnicmp instead of POSIX strncasecmp. */
static int header_name_is(const char *name, size_t len, const char *expected)
{
    return strlen(expected) == len && _strnicmp(name, expected, len) == 0;
}

/*
 * Copy the token [from, to) into dst as a C string.
 * Tokens must be non-empty, fit in dst, and contain only visible ASCII.
 */
static http_err_t copy_token(char *dst, size_t dst_size,
                             const char *from, const char *to,
                             http_err_t too_long_err)
{
    size_t len = (size_t)(to - from);

    if (len == 0)
        return ERR_BAD_REQUEST;
    if (len >= dst_size)
        return too_long_err;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)from[i];
        if (c <= 0x20 || c >= 0x7f)       /* control, space, or non-ASCII */
            return ERR_BAD_REQUEST;
    }

    memcpy(dst, from, len);
    dst[len] = '\0';
    return ERR_NONE;
}

/* =====================================================================
 * Socket I/O
 * ===================================================================== */

/* One recv() call, with errors mapped to http_err_t.
 * WINDOWS: recv() takes an int length and reports errors through
 * WSAGetLastError() instead of errno. */
static http_err_t recv_some(SOCKET fd, char *buf, size_t len, size_t *got)
{
    int n = recv(fd, buf, (int)len, 0);

    if (n > 0) {
        *got = (size_t)n;
        return ERR_NONE;
    }
    if (n == 0)
        return ERR_CLIENT_CLOSED;
    if (WSAGetLastError() == WSAETIMEDOUT)
        return ERR_TIMEOUT;
    return ERR_CLIENT_CLOSED;              /* reset, aborted, etc. */
}

/* send() until every byte is written. Returns 0 on success, -1 on error. */
static int send_all(SOCKET fd, const char *buf, size_t len)
{
    while (len > 0) {
        int n = send(fd, buf, (int)len, 0);
        if (n == SOCKET_ERROR)
            return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Build and send a full response: status line, headers, blank line, body. */
static int send_response(SOCKET fd, int status, const char *reason,
                         const char *content_type,
                         const char *body, size_t body_len)
{
    char header[512];
    int n = snprintf(header, sizeof header,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %lu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, reason, content_type, (unsigned long)body_len);

    if (n < 0 || (size_t)n >= sizeof header)
        return -1;
    if (send_all(fd, header, (size_t)n) < 0)
        return -1;
    if (body_len > 0 && send_all(fd, body, body_len) < 0)
        return -1;
    return 0;
}

static void send_error(SOCKET fd, http_err_t err)
{
    if (err <= ERR_NONE || err >= ERR_COUNT)
        err = ERR_INTERNAL;

    const error_info_t *e = &error_table[err];
    if (e->status == 0)
        return;                            /* nothing to send */

    send_response(fd, e->status, e->reason, "text/plain",
                  e->message, strlen(e->message));
}

/* =====================================================================
 * Stage 1: read the request line and headers
 * ===================================================================== */

/*
 * Keep calling recv() until we see the blank line that ends the headers.
 * On success, *total is the number of bytes in buf and *header_len is
 * the length of the header block. Bytes after header_len (if any) are
 * the start of the body.
 */
static http_err_t read_headers(SOCKET fd, char *buf, size_t cap,
                               size_t *total, size_t *header_len)
{
    *total = 0;
    *header_len = 0;

    while (*total < cap) {
        size_t got = 0;
        TRY(recv_some(fd, buf + *total, cap - *total, &got));
        *total += got;

        *header_len = find_header_end(buf, *total);
        if (*header_len > 0)
            return ERR_NONE;
    }
    return ERR_HEADERS_TOO_LARGE;
}

/* =====================================================================
 * Stage 2: parse "METHOD SP PATH SP VERSION"
 * ===================================================================== */

static http_err_t parse_request_line(const char *start, const char *end,
                                     http_request_t *req)
{
    const char *sp1 = memchr(start, ' ', (size_t)(end - start));
    if (!sp1)
        return ERR_BAD_REQUEST;

    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(end - (sp1 + 1)));
    if (!sp2)
        return ERR_BAD_REQUEST;

    TRY(copy_token(req->method,  sizeof req->method,  start,   sp1,
                   ERR_NOT_IMPLEMENTED));
    TRY(copy_token(req->path,    sizeof req->path,    sp1 + 1, sp2,
                   ERR_URI_TOO_LONG));
    TRY(copy_token(req->version, sizeof req->version, sp2 + 1, end,
                   ERR_BAD_REQUEST));

    if (req->path[0] != '/')
        return ERR_BAD_REQUEST;

    if (strcmp(req->version, "HTTP/1.1") != 0 &&
        strcmp(req->version, "HTTP/1.0") != 0) {
        return strncmp(req->version, "HTTP/", 5) == 0
               ? ERR_VERSION_UNSUPPORTED
               : ERR_BAD_REQUEST;
    }
    return ERR_NONE;
}

/* =====================================================================
 * Stage 3: parse "Name: value" header lines
 * ===================================================================== */

static http_err_t parse_content_length(const char *val, const char *end,
                                       http_request_t *req)
{
    long n = 0;

    if (val == end)
        return ERR_BAD_REQUEST;

    for (const char *p = val; p < end; p++) {
        if (*p < '0' || *p > '9')
            return ERR_BAD_REQUEST;
        n = n * 10 + (*p - '0');
        if (n > MAX_BODY_LEN)              /* stops early, so no overflow */
            return ERR_BODY_TOO_LARGE;
    }

    if (req->content_length >= 0 && req->content_length != n)
        return ERR_BAD_REQUEST;            /* conflicting duplicates */

    req->content_length = n;
    return ERR_NONE;
}

static http_err_t parse_header_line(const char *line, const char *eol,
                                    http_request_t *req)
{
    const char *colon = memchr(line, ':', (size_t)(eol - line));
    if (!colon || colon == line)
        return ERR_BAD_REQUEST;

    size_t name_len = (size_t)(colon - line);

    /* Trim spaces and tabs around the value. */
    const char *val = colon + 1;
    const char *val_end = eol;
    while (val < val_end && (*val == ' ' || *val == '\t'))
        val++;
    while (val_end > val && (val_end[-1] == ' ' || val_end[-1] == '\t'))
        val_end--;

    if (header_name_is(line, name_len, "Content-Length"))
        return parse_content_length(val, val_end, req);

    if (header_name_is(line, name_len, "Transfer-Encoding"))
        return ERR_NOT_IMPLEMENTED;        /* chunked bodies unsupported */

    return ERR_NONE;                       /* other headers are ignored */
}

static http_err_t parse_headers(const char *start, const char *end,
                                http_request_t *req)
{
    const char *line = start;

    while (line < end) {
        const char *eol = find_crlf(line, end);
        if (!eol)
            return ERR_BAD_REQUEST;
        if (eol == line)
            break;                         /* blank line: end of headers */

        TRY(parse_header_line(line, eol, req));
        line = eol + 2;
    }
    return ERR_NONE;
}

/* =====================================================================
 * Stage 4: request-level rules
 * ===================================================================== */

static http_err_t validate_request(const http_request_t *req)
{
    int is_get  = strcmp(req->method, "GET")  == 0;
    int is_post = strcmp(req->method, "POST") == 0;

    if (!is_get && !is_post)
        return ERR_NOT_IMPLEMENTED;
    if (is_post && req->content_length < 0)
        return ERR_LENGTH_REQUIRED;
    return ERR_NONE;
}

/* =====================================================================
 * Stage 5: read the body (exactly Content-Length bytes)
 * ===================================================================== */

static http_err_t read_body(SOCKET fd, const char *buf, size_t total,
                            size_t header_len, http_request_t *req)
{
    req->body_len = 0;
    req->body[0] = '\0';

    if (req->content_length <= 0)
        return ERR_NONE;

    /* content_length was already checked to be <= MAX_BODY_LEN. */
    size_t want = (size_t)req->content_length;

    /* Some of the body may have arrived with the headers. */
    size_t already = total - header_len;
    if (already > want)
        already = want;                    /* ignore any extra bytes */
    memcpy(req->body, buf + header_len, already);
    req->body_len = already;

    /* recv() the rest. */
    while (req->body_len < want) {
        size_t got = 0;
        TRY(recv_some(fd, req->body + req->body_len,
                      want - req->body_len, &got));
        req->body_len += got;
    }

    req->body[req->body_len] = '\0';
    return ERR_NONE;
}

/* =====================================================================
 * Stage 6: route to a handler
 * ===================================================================== */

static http_err_t handle_get_index(SOCKET fd, const http_request_t *req)
{
    (void)req;
    static const char page[] =
        "<!DOCTYPE html>\n"
        "<html><body>\n"
        "<h1>It works</h1>\n"
        "<form method=\"POST\" action=\"/echo\">\n"
        "  <input name=\"name\" value=\"hello\">\n"
        "  <button>Send</button>\n"
        "</form>\n"
        "</body></html>\n";

    if (send_response(fd, 200, "OK", "text/html", page, sizeof page - 1) < 0)
        return ERR_CLIENT_CLOSED;
    return ERR_NONE;
}



static http_err_t handle_post_echo(SOCKET fd, const http_request_t *req)
{
    char msg[64];

    __try {
        strcpy(msg, req->body);

        if (msg[0] == '!') {
            volatile char *crash = NULL;
            *crash = 'x';             
        }

        if (send_response(fd, 200, "OK", "text/plain",
                          msg, strlen(msg)) < 0)
            return ERR_CLIENT_CLOSED;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        send_error(fd, ERR_INTERNAL);
    }
    return ERR_NONE;
}

static http_err_t route_request(SOCKET fd, const http_request_t *req)
{
    if (strcmp(req->path, "/") == 0) {
        if (strcmp(req->method, "GET") != 0)
            return ERR_METHOD_NOT_ALLOWED;
        return handle_get_index(fd, req);
    }

    if (strcmp(req->path, "/echo") == 0) {
        if (strcmp(req->method, "POST") != 0)
            return ERR_METHOD_NOT_ALLOWED;
        return handle_post_echo(fd, req);
    }

    return ERR_NOT_FOUND;
}

/* =====================================================================
 * TRY: run every stage for one request
 * ===================================================================== */

static http_err_t process_request(SOCKET fd, http_request_t *req)
{
    char   buf[MAX_HEADER_BYTES];   /* raw bytes from the client */
    size_t total = 0;
    size_t header_len = 0;

    TRY(read_headers(fd, buf, sizeof buf, &total, &header_len));

    const char *start = buf;
    const char *end   = buf + header_len;
    const char *eol   = find_crlf(start, end);   /* end of request line */
    if (!eol)
        return ERR_BAD_REQUEST;

    TRY(parse_request_line(start, eol, req));
    TRY(parse_headers(eol + 2, end, req));
    TRY(validate_request(req));
    TRY(read_body(fd, buf, total, header_len, req));

    return route_request(fd, req);
}

/* =====================================================================
 * CATCH: one connection from start to finish
 * ===================================================================== */

static void log_request(const struct sockaddr_in *addr,
                        const http_request_t *req, http_err_t err)
{
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof ip);

    const char *method = req->method[0] ? req->method : "-";
    const char *path   = req->path[0]   ? req->path   : "-";

    if (err == ERR_CLIENT_CLOSED)
        printf("%s:%d \"%s %s\" -> connection closed\n",
               ip, ntohs(addr->sin_port), method, path);
    else
        printf("%s:%d \"%s %s\" -> %d\n",
               ip, ntohs(addr->sin_port), method, path,
               error_table[err].status);
}

static void handle_client(SOCKET fd, const struct sockaddr_in *addr)
{
    http_request_t req;
    memset(&req, 0, sizeof req);
    req.content_length = -1;

    http_err_t err = process_request(fd, &req);        /* try   */

    if (err != ERR_NONE && err != ERR_CLIENT_CLOSED)   /* catch */
        send_error(fd, err);

    log_request(addr, &req, err);
    closesocket(fd);                    /* WINDOWS: not close() */
}

/* =====================================================================
 * Server setup and main loop
 * ===================================================================== */

static volatile LONG running = 1;
static SOCKET listen_sock = INVALID_SOCKET;

/* WINDOWS: Ctrl-C runs this on a separate thread. Closing the listening
 * socket makes the blocked accept() in main() return so the loop exits. */
static BOOL WINAPI on_ctrl_c(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        InterlockedExchange(&running, 0);
        closesocket(listen_sock);
        return TRUE;
    }
    return FALSE;
}

static SOCKET create_listener(int port)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    /* WINDOWS: SO_EXCLUSIVEADDRUSE stops other programs from binding the
     * same port. (SO_REUSEADDR means something less safe on Windows.) */
    BOOL yes = TRUE;
    setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               (const char *)&yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(fd);
        return INVALID_SOCKET;
    }
    if (listen(fd, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(fd);
        return INVALID_SOCKET;
    }
    return fd;
}

/* So a client that connects and sends nothing can't hang the server.
 * WINDOWS: the timeout is a DWORD in milliseconds, not a struct timeval. */
static void set_recv_timeout(SOCKET fd, int seconds)
{
    DWORD ms = (DWORD)seconds * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "usage: %s [port]\n", argv[0]);
            return 1;
        }
    }

    /* WINDOWS: unbuffered output (line buffering isn't supported). */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* WINDOWS: Winsock must be started before any socket call. */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    listen_sock = create_listener(port);
    if (listen_sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    SetConsoleCtrlHandler(on_ctrl_c, TRUE);
    printf("Listening on http://0.0.0.0:%d\n", port);

    while (running) {
        struct sockaddr_in client;
        int len = sizeof client;

        SOCKET fd = accept(listen_sock, (struct sockaddr *)&client, &len);
        if (fd == INVALID_SOCKET) {
            if (running)
                fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
            continue;
        }

        set_recv_timeout(fd, RECV_TIMEOUT_SEC);
        handle_client(fd, &client);
    }

    printf("\nShutting down\n");
    WSACleanup();                       /* listen_sock closed by on_ctrl_c */
    return 0;
}
