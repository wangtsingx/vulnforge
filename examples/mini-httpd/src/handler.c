#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "handler.h"

/*
 * Deliberately vulnerable mini HTTP handler for VulnForge end-to-end testing.
 *
 * Known seeded issues (see expected-findings.md):
 *   1. Unbounded copy in parse_request  (CWE-120)
 *   2. Integer overflow before bounds check in handle_request (CWE-190)
 *   3. File descriptor leak in handle_request (CWE-404)
 * Do NOT use this code in production.
 */

int parse_request(const char *raw, http_request_t *req) {
    if (!raw || !req) return -1;
    memset(req, 0, sizeof(*req));

    /* Find the method separator. */
    const char *space = strchr(raw, ' ');
    if (!space) return -1;
    size_t method_len = (size_t)(space - raw);
    /* BUG 1 (part a): no bounds check on method copy. */
    strncpy(req->method, raw, method_len);

    const char *path_start = space + 1;
    const char *path_end = strchr(path_start, ' ');
    if (!path_end) return -1;
    size_t path_len = (size_t)(path_end - path_start);
    /* BUG 1 (part b): copies up to path_len without checking MAX_PATH_LEN. */
    memcpy(req->path, path_start, path_len);

    const char *body_marker = strstr(raw, "\r\n\r\n");
    if (body_marker) {
        body_marker += 4;
        /* BUG 1 (part c): body copied without checking MAX_BODY_LEN. */
        strcpy(req->body, body_marker);
        req->body_len = (int)strlen(req->body);
    }
    return 0;
}

int handle_request(http_request_t *req) {
    if (!req) return -1;

    /* Simulated authentication (always succeeds for testing). */
    req->user_id = 42;

    if (strncmp(req->method, "POST", 4) == 0) {
        /* BUG 2: attacker-controlled body_len can overflow int when
         * multiplied, bypassing the MAX_BODY_LEN check. */
        int total = req->body_len + 64;
        if (total > MAX_BODY_LEN) return -1;
        char buf[64];
        memcpy(buf, req->body, (size_t)req->body_len);
    }

    if (strncmp(req->method, "GET", 3) == 0) {
        FILE *fp = fopen("/tmp/mini-httpd.log", "a");
        if (!fp) return -1;
        fprintf(fp, "GET %s\n", req->path);
        /* BUG 3: fp is never closed on any return path. */
    }

    return 0;
}

void log_request(const http_request_t *req) {
    /* Safe function for contrast: bounded copy. */
    char safe_buf[MAX_PATH_LEN];
    snprintf(safe_buf, sizeof(safe_buf), "%s", req->path);
    printf("%d %s\n", req->user_id, safe_buf);
}
