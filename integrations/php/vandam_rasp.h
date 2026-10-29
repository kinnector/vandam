#ifndef VANDAM_RASP_H
#define VANDAM_RASP_H

#include "vandam_php.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Cross-version Helper Functions */
int connect_to_vandam(VANDAM_TSRMLS_D);
void escape_json_string(const char *input, char *output, size_t out_size);
char *extract_json_string(const char *json, const char *key);

/* Core verdicts */
int query_vandam_verdict(const char *type, const char *func_name, const char *path VANDAM_TSRMLS_DC);
int check_exec_verdict(const char *func_name, const char *cmd VANDAM_TSRMLS_DC);
int check_file_read_verdict(const char *filename VANDAM_TSRMLS_DC);
int check_file_write_verdict(const char *filename VANDAM_TSRMLS_DC);

/* Version specific implementations required by hooks_phpX.c */
void vandam_install_hooks(VANDAM_TSRMLS_D);
void vandam_restore_hooks(VANDAM_TSRMLS_D);
char *build_json_trace(VANDAM_TSRMLS_D);
void send_startup_telemetry(VANDAM_TSRMLS_D);
char *get_json_encoded_global(const char *global_name VANDAM_TSRMLS_DC);

#endif /* VANDAM_RASP_H */
