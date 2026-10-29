#include "vandam_rasp.h"
#include "SAPI.h"

int connect_to_vandam(VANDAM_TSRMLS_D) {
    if (VANDAM_PHP_G(client_fd) >= 0) {
        return VANDAM_PHP_G(client_fd);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    const char *sock_path = VANDAM_PHP_G(socket_path);
    if (!sock_path || strlen(sock_path) == 0) {
        sock_path = "/run/vandam/rasp_telemetry.sock";
    }

    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    VANDAM_PHP_G(client_fd) = fd;
    return fd;
}

char *extract_json_string(const char *json, const char *key) {
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);
    const char *pos = strstr(json, search_pattern);
    if (!pos) return NULL;

    pos = strchr(pos + strlen(search_pattern), ':');
    if (!pos) return NULL;

    pos = strchr(pos, '"');
    if (!pos) return NULL;
    pos++;

    const char *end = strchr(pos, '"');
    if (!end) return NULL;

    size_t len = end - pos;
    char *val = pemalloc(len + 1, 1);
    memcpy(val, pos, len);
    val[len] = '\0';
    return val;
}

void escape_json_string(const char *input, char *output, size_t out_size) {
    if (!input || !output || out_size < 3) {
        if (output && out_size > 0) output[0] = '\0';
        return;
    }
    size_t i = 0, j = 0;
    for (i = 0; input[i] != '\0' && j < out_size - 2; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
}

int query_vandam_verdict(const char *type, const char *func_name, const char *path VANDAM_TSRMLS_DC) {
    int fd = connect_to_vandam(VANDAM_TSRMLS_C);
    if (fd < 0) {
        return 1;
    }

    int payload_size_bytes = path ? strlen(path) : 0;

    if ((strcmp(type, "eval_code") == 0 || strcmp(type, "file_compile") == 0) && payload_size_bytes > 2097152) {
        zend_error(E_ERROR, "Vandam RASP blocked execution: Payload exceeded 2MB hard cap (%d bytes).", payload_size_bytes);
        return 0;
    }

    char escaped_path[10000] = "";
    if (payload_size_bytes > 4096) {
        char truncated[4200] = "";
        strncpy(truncated, path, 2048);
        truncated[2048] = '\0';
        strcat(truncated, "\n...[TRUNCATED_MIDDLE]...\n");
        strncat(truncated, path + payload_size_bytes - 2048, 2048);
        escape_json_string(truncated, escaped_path, sizeof(escaped_path));
    } else {
        escape_json_string(path, escaped_path, sizeof(escaped_path));
    }

    const char *req_method = "";
    const char *req_uri = "";
    const char *req_query = "";
    char esc_uri[1024] = "";
    char esc_query[1024] = "";
    char client_ip[64] = "";
    char http_host[256] = "";

    if (VANDAM_PHP_G(in_request)) {
        if (SG(request_info).request_method) req_method = SG(request_info).request_method;
        if (SG(request_info).request_uri) req_uri = SG(request_info).request_uri;
        if (SG(request_info).query_string) req_query = SG(request_info).query_string;
        
        escape_json_string(req_uri, esc_uri, sizeof(esc_uri));
        escape_json_string(req_query, esc_query, sizeof(esc_query));

#if PHP_VERSION_ID >= 70000
        zend_is_auto_global_str(ZEND_STRL("_SERVER"));
        zval *server_vars = &PG(http_globals)[TRACK_VARS_SERVER];
        if (server_vars && Z_TYPE_P(server_vars) == IS_ARRAY) {
            zval *ip_zv = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1);
            if (ip_zv && Z_TYPE_P(ip_zv) == IS_STRING) {
                strncpy(client_ip, Z_STRVAL_P(ip_zv), sizeof(client_ip) - 1);
            }
            zval *host_zv = zend_hash_str_find(Z_ARRVAL_P(server_vars), "HTTP_HOST", sizeof("HTTP_HOST") - 1);
            if (host_zv && Z_TYPE_P(host_zv) == IS_STRING) {
                strncpy(http_host, Z_STRVAL_P(host_zv), sizeof(http_host) - 1);
            }
        }
#else
        zend_is_auto_global("_SERVER", sizeof("_SERVER") - 1 TSRMLS_CC);
        zval **server_vars;
        if (zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"), (void **)&server_vars) == SUCCESS && Z_TYPE_PP(server_vars) == IS_ARRAY) {
            zval **ip_zv;
            if (zend_hash_find(Z_ARRVAL_PP(server_vars), "REMOTE_ADDR", sizeof("REMOTE_ADDR"), (void **)&ip_zv) == SUCCESS && Z_TYPE_PP(ip_zv) == IS_STRING) {
                strncpy(client_ip, Z_STRVAL_PP(ip_zv), sizeof(client_ip) - 1);
            }
            zval **host_zv;
            if (zend_hash_find(Z_ARRVAL_PP(server_vars), "HTTP_HOST", sizeof("HTTP_HOST"), (void **)&host_zv) == SUCCESS && Z_TYPE_PP(host_zv) == IS_STRING) {
                strncpy(http_host, Z_STRVAL_PP(host_zv), sizeof(http_host) - 1);
            }
        }
#endif
    }

    char *json_trace = build_json_trace(VANDAM_TSRMLS_C);
    
    char *server_json = NULL;
    char *post_json = NULL;
    char *get_json = NULL;
    char *files_json = NULL;
    char *cookie_json = NULL;
    if (VANDAM_PHP_G(in_request)) {
        server_json = get_json_encoded_global("_SERVER" VANDAM_TSRMLS_CC);
        post_json = get_json_encoded_global("_POST" VANDAM_TSRMLS_CC);
        get_json = get_json_encoded_global("_GET" VANDAM_TSRMLS_CC);
        files_json = get_json_encoded_global("_FILES" VANDAM_TSRMLS_CC);
        cookie_json = get_json_encoded_global("_COOKIE" VANDAM_TSRMLS_CC);
    }

    int is_install_context = (getenv("COMPOSER") || getenv("COMPOSER_HOME") || getenv("COMPOSER_BIN_DIR")) ? 1 : 0;

    char request[20480];
    if (func_name) {
        snprintf(request, sizeof(request),
            "{\"type\":\"%s\",\"pid\":%d,\"function\":\"%s\",\"path\":\"%s\",\"payload_size_bytes\":%d,\"in_request\":%d,"
            "\"http\":{\"method\":\"%s\",\"uri\":\"%s\",\"query\":\"%s\",\"remote_addr\":\"%s\",\"http_host\":\"%s\","
            "\"_SERVER\":%s,\"_POST\":%s,\"_GET\":%s,\"_FILES\":%s,\"_COOKIE\":%s},"
            "\"trace\":%s,\"is_install_context\":%d}\n",
            type, getpid(), func_name, escaped_path, payload_size_bytes, VANDAM_PHP_G(in_request),
            req_method, esc_uri, esc_query, client_ip, http_host,
            server_json ? server_json : "{}",
            post_json ? post_json : "{}",
            get_json ? get_json : "{}",
            files_json ? files_json : "{}",
            cookie_json ? cookie_json : "{}",
            json_trace ? json_trace : "[]", is_install_context);
    } else {
        snprintf(request, sizeof(request),
            "{\"type\":\"%s\",\"pid\":%d,\"path\":\"%s\",\"payload_size_bytes\":%d,\"in_request\":%d,"
            "\"http\":{\"method\":\"%s\",\"uri\":\"%s\",\"query\":\"%s\",\"remote_addr\":\"%s\",\"http_host\":\"%s\","
            "\"_SERVER\":%s,\"_POST\":%s,\"_GET\":%s,\"_FILES\":%s,\"_COOKIE\":%s},"
            "\"trace\":%s,\"is_install_context\":%d}\n",
            type, getpid(), escaped_path, payload_size_bytes, VANDAM_PHP_G(in_request),
            req_method, esc_uri, esc_query, client_ip, http_host,
            server_json ? server_json : "{}",
            post_json ? post_json : "{}",
            get_json ? get_json : "{}",
            files_json ? files_json : "{}",
            cookie_json ? cookie_json : "{}",
            json_trace ? json_trace : "[]", is_install_context);
    }

    if (json_trace) pefree(json_trace, 0);
    if (server_json) efree(server_json);
    if (post_json) efree(post_json);
    if (get_json) efree(get_json);
    if (files_json) efree(files_json);
    if (cookie_json) efree(cookie_json);

    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        VANDAM_PHP_G(client_fd) = -1;
        return 1;
    }

    if (strcmp(type, "file_compile") == 0 || strcmp(type, "eval_code") == 0 || strcmp(type, "dynamic_load") == 0 || strcmp(type, "ffi_call") == 0) {
        return 1;
    }

    char response[1024];
    memset(response, 0, sizeof(response));
    ssize_t bytes = recv(fd, response, sizeof(response) - 1, 0);
    if (bytes <= 0) {
        close(fd);
        VANDAM_PHP_G(client_fd) = -1;
        return 1;
    }

    if (strstr(response, "\"verdict\":\"allow\"") || strstr(response, "\"verdict\": \"allow\"")) {
        return 1;
    } else if (strstr(response, "\"verdict\":\"deny\"") || strstr(response, "\"verdict\": \"deny\"")) {
        return 0;
    }

    return 1;
}

int check_exec_verdict(const char *func_name, const char *cmd VANDAM_TSRMLS_DC) {
    return query_vandam_verdict("exec_call", func_name, cmd VANDAM_TSRMLS_CC);
}

int check_file_read_verdict(const char *filename VANDAM_TSRMLS_DC) {
    char resolved_path[MAXPATHLEN];
    if (!VANDAM_PHP_G(blocking_enabled)) {
        return 1;
    }

    if (!VCWD_REALPATH(filename, resolved_path)) {
        strncpy(resolved_path, filename, sizeof(resolved_path) - 1);
        resolved_path[sizeof(resolved_path) - 1] = '\0';
    }

    if (!query_vandam_verdict("file_read", NULL, resolved_path VANDAM_TSRMLS_CC)) {
        return 0;
    }

    if (VANDAM_PHP_G(blocked_read_paths)) {
        char *paths_copy = estrdup(VANDAM_PHP_G(blocked_read_paths));
        char *token = strtok(paths_copy, ",");
        int blocked = 0;
        while (token) {
            if (strstr(resolved_path, token) != NULL) {
                blocked = 1;
                break;
            }
            token = strtok(NULL, ",");
        }
        efree(paths_copy);
        if (blocked) return 0;
    }

    if (VANDAM_PHP_G(site_root) && strlen(VANDAM_PHP_G(site_root)) > 0) {
        if (resolved_path[0] == '/') {
            if (strncmp(resolved_path, VANDAM_PHP_G(site_root), strlen(VANDAM_PHP_G(site_root))) != 0) {
                int allowed = 0;
                if (strncmp(resolved_path, "/tmp/", 5) == 0 || strncmp(resolved_path, "/var/tmp/", 9) == 0) {
                    allowed = 1;
                }
                if (!allowed && VANDAM_PHP_G(allowed_read_paths)) {
                    char *paths_copy = estrdup(VANDAM_PHP_G(allowed_read_paths));
                    char *token = strtok(paths_copy, ",");
                    while (token) {
                        if (strncmp(resolved_path, token, strlen(token)) == 0) {
                            allowed = 1;
                            break;
                        }
                        token = strtok(NULL, ",");
                    }
                    efree(paths_copy);
                }
                if (!allowed) return 0;
            }
        }
    }
    return 1;
}

int check_file_write_verdict(const char *filename VANDAM_TSRMLS_DC) {
    char resolved_path[MAXPATHLEN];
    if (!VANDAM_PHP_G(blocking_enabled)) {
        return 1;
    }

    if (!VCWD_REALPATH(filename, resolved_path)) {
        strncpy(resolved_path, filename, sizeof(resolved_path) - 1);
        resolved_path[sizeof(resolved_path) - 1] = '\0';
    }

    if (!query_vandam_verdict("file_write", NULL, resolved_path VANDAM_TSRMLS_CC)) {
        return 0;
    }

    if (VANDAM_PHP_G(blocked_write_paths)) {
        char *paths_copy = estrdup(VANDAM_PHP_G(blocked_write_paths));
        char *token = strtok(paths_copy, ",");
        int blocked = 0;
        while (token) {
            if (strstr(resolved_path, token) != NULL) {
                blocked = 1;
                break;
            }
            token = strtok(NULL, ",");
        }
        efree(paths_copy);
        if (blocked) return 0;
    }

    if (VANDAM_PHP_G(site_root) && strlen(VANDAM_PHP_G(site_root)) > 0) {
        if (resolved_path[0] == '/') {
            if (strncmp(resolved_path, VANDAM_PHP_G(site_root), strlen(VANDAM_PHP_G(site_root))) != 0) {
                int allowed = 0;
                if (strncmp(resolved_path, "/tmp/", 5) == 0 || strncmp(resolved_path, "/var/tmp/", 9) == 0) {
                    allowed = 1;
                }
                if (!allowed && VANDAM_PHP_G(allowed_write_paths)) {
                    char *paths_copy = estrdup(VANDAM_PHP_G(allowed_write_paths));
                    char *token = strtok(paths_copy, ",");
                    while (token) {
                        if (strncmp(resolved_path, token, strlen(token)) == 0) {
                            allowed = 1;
                            break;
                        }
                        token = strtok(NULL, ",");
                    }
                    efree(paths_copy);
                }
                if (!allowed) return 0;
            }
        }
    }
    return 1;
}
