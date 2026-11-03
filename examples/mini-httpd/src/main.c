#include <stdio.h>
#include <string.h>
#include "handler.h"

/* Minimal entry point: reads one request from stdin and dispatches it. */
int main(void) {
    char raw[4096];
    size_t n = fread(raw, 1, sizeof(raw) - 1, stdin);
    raw[n] = '\0';

    http_request_t req;
    if (parse_request(raw, &req) != 0) {
        fprintf(stderr, "parse error\n");
        return 1;
    }
    handle_request(&req);
    log_request(&req);
    return 0;
}
