#include <stdio.h>
#include <stdlib.h>
#include "handler.h"

/*
 * Minimal reproduction harness for mini-httpd findings.
 * Allocates the request object on the heap so AddressSanitizer can observe
 * exactly where an out-of-bounds write leaves the struct.
 */
int main(void) {
    char raw[4096];
    size_t n = fread(raw, 1, sizeof(raw) - 1, stdin);
    raw[n] = '\0';

    http_request_t *req = malloc(sizeof(*req));
    if (!req) return 2;
    if (parse_request(raw, req) != 0) {
        fprintf(stderr, "parse error\n");
        free(req);
        return 1;
    }
    printf("method=%s path=%s body_len=%d\n", req->method, req->path, req->body_len);
    free(req);
    return 0;
}
