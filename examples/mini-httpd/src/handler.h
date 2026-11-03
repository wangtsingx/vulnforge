#ifndef MINI_HTTPD_HANDLER_H
#define MINI_HTTPD_HANDLER_H

#define MAX_PATH_LEN 256
#define MAX_BODY_LEN 1024

/* Parsed HTTP request (simplified). */
typedef struct {
    char method[8];
    char path[MAX_PATH_LEN];
    char body[MAX_BODY_LEN];
    int  body_len;
    int  user_id;      /* set after auth */
} http_request_t;

int  parse_request(const char *raw, http_request_t *req);
int  handle_request(http_request_t *req);
void log_request(const http_request_t *req);

#endif
