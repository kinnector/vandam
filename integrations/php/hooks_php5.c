#include "vandam_rasp.h"
#include "SAPI.h"

#if PHP_VERSION_ID < 70000

/* Original function handlers */
static vandam_func_handler orig_exec = NULL;
static vandam_func_handler orig_shell_exec = NULL;
static vandam_func_handler orig_system = NULL;
static vandam_func_handler orig_passthru = NULL;
static vandam_func_handler orig_proc_open = NULL;
static vandam_func_handler orig_popen = NULL;
static vandam_func_handler orig_pcntl_exec = NULL;

static vandam_func_handler orig_fopen = NULL;
static vandam_func_handler orig_file_get_contents = NULL;
static vandam_func_handler orig_file_put_contents = NULL;
static vandam_func_handler orig_readfile = NULL;
static vandam_func_handler orig_chmod = NULL;

static zend_op_array *(*orig_compile_file)(zend_file_handle *file_handle, int type VANDAM_TSRMLS_DC) = NULL;
static zend_op_array *(*orig_compile_string)(zval *source_string, char *filename VANDAM_TSRMLS_DC) = NULL;
static vandam_func_handler orig_dl = NULL;
static vandam_func_handler orig_preg_replace = NULL;
static vandam_func_handler orig_assert = NULL;

char *get_json_encoded_global(const char *global_name VANDAM_TSRMLS_DC) {
    return NULL; /* Too complex to safely port json_encode invocation to PHP 5, skip gracefully */
}

char *build_json_trace(VANDAM_TSRMLS_D) {
    size_t alloc_size = 8192;
    char *trace = pemalloc(alloc_size, 0);
    if (!trace) return NULL;
    
    strcpy(trace, "[");
    size_t current_len = 1;

    strcpy(trace + current_len, "{\"file\":\"[Trace unsupported in PHP 5.x]\",\"line\":0,\"function\":\"\",\"class\":\"\",\"args\":[]}");
    current_len += strlen(trace + current_len);

    strcpy(trace + current_len, "]");
    return trace;
}

void send_startup_telemetry(VANDAM_TSRMLS_D) {
    if (VANDAM_PHP_G(startup_telemetry_sent)) {
        return;
    }

    int fd = connect_to_vandam(VANDAM_TSRMLS_C);
    if (fd < 0) return;

    char ext_list[512] = "";
    if (zend_hash_exists(&module_registry, "opcache", 8)) strcat(ext_list, "\"opcache\",");
    if (zend_hash_exists(&module_registry, "imagick", 8)) strcat(ext_list, "\"imagick\",");
    if (zend_hash_exists(&module_registry, "redis", 6)) strcat(ext_list, "\"redis\",");
    if (zend_hash_exists(&module_registry, "curl", 5)) strcat(ext_list, "\"curl\",");
    if (zend_hash_exists(&module_registry, "gd", 3)) strcat(ext_list, "\"gd\",");
    if (zend_hash_exists(&module_registry, "zip", 4)) strcat(ext_list, "\"zip\",");

    size_t ext_len = strlen(ext_list);
    if (ext_len > 0 && ext_list[ext_len - 1] == ',') {
        ext_list[ext_len - 1] = '\0';
    }

    int opcache_enabled = 0;
    if (zend_hash_exists(&module_registry, "opcache", 8)) opcache_enabled = 1;

    char *manifest = pemalloc(8192, 0);
    manifest[0] = '\0';
    size_t manifest_len = 0;
    size_t manifest_max = 8192;
    int first = 1;

    HashPosition pos;
    char *file_path;
    uint file_path_len;
    ulong num_key;
    zend_hash_internal_pointer_reset_ex(&EG(included_files), &pos);
    while (zend_hash_get_current_key_ex(&EG(included_files), &file_path, &file_path_len, &num_key, 0, &pos) == HASH_KEY_IS_STRING) {
        size_t path_len = strlen(file_path);
        if (manifest_len + path_len + 16 < manifest_max) {
            if (!first) {
                strcat(manifest + manifest_len, ",");
                manifest_len++;
            }
            strcat(manifest + manifest_len, "\"");
            manifest_len++;

            for (size_t i = 0; i < path_len; i++) {
                if (file_path[i] == '\\' || file_path[i] == '"') {
                    manifest[manifest_len++] = '\\';
                }
                manifest[manifest_len++] = file_path[i];
            }

            manifest[manifest_len++] = '"';
            manifest[manifest_len] = '\0';
            first = 0;
        }
        zend_hash_move_forward_ex(&EG(included_files), &pos);
    }

    const char *open_basedir = INI_STR("open_basedir") ? INI_STR("open_basedir") : "";
    const char *disable_functions = INI_STR("disable_functions") ? INI_STR("disable_functions") : "";
    const char *memory_limit = INI_STR("memory_limit") ? INI_STR("memory_limit") : "";
    long max_execution_time = INI_INT("max_execution_time");

    char esc_basedir[256] = "";
    char esc_disabled[1024] = "";

    size_t bd_len = strlen(open_basedir);
    size_t bd_idx = 0;
    for (size_t i = 0; i < bd_len && bd_idx < sizeof(esc_basedir) - 2; i++) {
        if (open_basedir[i] == '\\' || open_basedir[i] == '"') {
            esc_basedir[bd_idx++] = '\\';
        }
        esc_basedir[bd_idx++] = open_basedir[i];
    }
    esc_basedir[bd_idx] = '\0';

    size_t df_len = strlen(disable_functions);
    size_t df_idx = 0;
    for (size_t i = 0; i < df_len && df_idx < sizeof(esc_disabled) - 2; i++) {
        if (disable_functions[i] == '\\' || disable_functions[i] == '"') {
            esc_disabled[df_idx++] = '\\';
        }
        esc_disabled[df_idx++] = disable_functions[i];
    }
    esc_disabled[df_idx] = '\0';

    char *payload = pemalloc(16384, 0);
    snprintf(payload, 16384,
        "{\"type\":\"startup\",\"pid\":%d,\"php_version\":\"%s\",\"sapi\":\"%s\",\"autoload_manifest\":[%s],\"loaded_extensions\":[%s],\"opcache\":{\"enabled\":%s,\"jit_enabled\":false},\"ini\":{\"open_basedir\":\"%s\",\"disable_functions\":\"%s\",\"memory_limit\":\"%s\",\"max_execution_time\":%ld}}\n",
        getpid(), PHP_VERSION, sapi_module.name, manifest, ext_list,
        opcache_enabled ? "true" : "false",
        esc_basedir, esc_disabled, memory_limit, max_execution_time);

    send(fd, payload, strlen(payload), 0);
    pefree(manifest, 0);
    pefree(payload, 0);

    char response[2048];
    memset(response, 0, sizeof(response));
    ssize_t bytes = recv(fd, response, sizeof(response) - 1, 0);
    if (bytes > 0) {
        char *new_site_root = extract_json_string(response, "site_root");
        if (new_site_root) {
            if (VANDAM_PHP_G(site_root)) pefree(VANDAM_PHP_G(site_root), 1);
            VANDAM_PHP_G(site_root) = new_site_root;
        }

        char *new_allowed_read = extract_json_string(response, "allowed_read_paths");
        if (new_allowed_read) {
            if (VANDAM_PHP_G(allowed_read_paths)) pefree(VANDAM_PHP_G(allowed_read_paths), 1);
            VANDAM_PHP_G(allowed_read_paths) = new_allowed_read;
        }

        char *new_allowed_write = extract_json_string(response, "allowed_write_paths");
        if (new_allowed_write) {
            if (VANDAM_PHP_G(allowed_write_paths)) pefree(VANDAM_PHP_G(allowed_write_paths), 1);
            VANDAM_PHP_G(allowed_write_paths) = new_allowed_write;
        }

        char *new_blocked_read = extract_json_string(response, "blocked_read_paths");
        if (new_blocked_read) {
            if (VANDAM_PHP_G(blocked_read_paths)) pefree(VANDAM_PHP_G(blocked_read_paths), 1);
            VANDAM_PHP_G(blocked_read_paths) = new_blocked_read;
        }

        char *new_blocked_write = extract_json_string(response, "blocked_write_paths");
        if (new_blocked_write) {
            if (VANDAM_PHP_G(blocked_write_paths)) pefree(VANDAM_PHP_G(blocked_write_paths), 1);
            VANDAM_PHP_G(blocked_write_paths) = new_blocked_write;
        }
    }

    VANDAM_PHP_G(startup_telemetry_sent) = 1;
}

static zend_op_array *vandam_compile_file(zend_file_handle *file_handle, int type VANDAM_TSRMLS_DC) {
    const char *filename = NULL;
    if (file_handle) {
        filename = file_handle->filename;
    }

    if (filename) {
        char resolved_path[MAXPATHLEN];
        if (!VCWD_REALPATH(filename, resolved_path)) {
            strncpy(resolved_path, filename, sizeof(resolved_path) - 1);
            resolved_path[sizeof(resolved_path) - 1] = '\0';
        }

        if (!query_vandam_verdict("file_compile", NULL, resolved_path VANDAM_TSRMLS_CC)) {
            zend_error(E_COMPILE_ERROR, "[Vandam RASP] Blocked loading unauthorized PHP file: %s", filename);
            return NULL;
        }
    }
    return orig_compile_file(file_handle, type VANDAM_TSRMLS_CC);
}

static zend_op_array *vandam_compile_string(zval *source_string, char *filename VANDAM_TSRMLS_DC) {
    if (source_string && Z_TYPE_P(source_string) == IS_STRING) {
        char *code = Z_STRVAL_P(source_string);
        char preview[1024];
        snprintf(preview, sizeof(preview), "%.1000s", code);
        query_vandam_verdict("eval_code", "eval", preview VANDAM_TSRMLS_CC);
    }
    if (orig_compile_string) {
        return orig_compile_string(source_string, filename VANDAM_TSRMLS_CC);
    }
    return NULL;
}

PHP_FUNCTION(vandam_exec) {
    char *cmd = NULL;
    int cmd_len = 0;
    zval *args = NULL;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|z/z/", &cmd, &cmd_len, &args, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("exec", cmd VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_shell_exec) {
    char *cmd = NULL;
    int cmd_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s", &cmd, &cmd_len) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("shell_exec", cmd VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_shell_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_shell_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_system) {
    char *cmd = NULL;
    int cmd_len = 0;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|z/", &cmd, &cmd_len, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("system", cmd VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_system) VANDAM_FUNC_HANDLER_PASSTHRU(orig_system); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_passthru) {
    char *cmd = NULL;
    int cmd_len = 0;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|z/", &cmd, &cmd_len, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("passthru", cmd VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_passthru) VANDAM_FUNC_HANDLER_PASSTHRU(orig_passthru); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_proc_open) {
    zval *cmd_zval = NULL, *descriptors = NULL, *pipes = NULL, *env = NULL, *other_options = NULL;
    char *cwd = NULL;
    int cwd_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "zaz|s!a!a!", &cmd_zval, &descriptors, &pipes, &cwd, &cwd_len, &env, &other_options) == FAILURE) RETURN_FALSE;
    if (cmd_zval && Z_TYPE_P(cmd_zval) == IS_STRING) {
        char *cmd = Z_STRVAL_P(cmd_zval);
        if (cmd && strlen(cmd) > 0 && !check_exec_verdict("proc_open", cmd VANDAM_TSRMLS_CC)) {
            zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
            RETURN_FALSE;
        }
    }
    if (orig_proc_open) VANDAM_FUNC_HANDLER_PASSTHRU(orig_proc_open); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_popen) {
    char *cmd = NULL, *mode = NULL;
    int cmd_len = 0, mode_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "ss", &cmd, &cmd_len, &mode, &mode_len) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("popen", cmd VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_popen) VANDAM_FUNC_HANDLER_PASSTHRU(orig_popen); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_pcntl_exec) {
    char *path = NULL;
    int path_len = 0;
    zval *args = NULL, *envs = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|a!a!", &path, &path_len, &args, &envs) == FAILURE) RETURN_FALSE;
    if (path && path_len > 0 && !check_exec_verdict("pcntl_exec", path VANDAM_TSRMLS_CC)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", path);
        RETURN_FALSE;
    }
    if (orig_pcntl_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_pcntl_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_fopen) {
    char *filename = NULL, *mode = NULL;
    int filename_len = 0, mode_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "ss|bz", &filename, &filename_len, &mode, &mode_len, &use_include_path, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) {
        int is_write = 0;
        if (mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, 'x') || strchr(mode, 'c') || strchr(mode, '+'))) is_write = 1;
        if (is_write) {
            if (!check_file_write_verdict(filename VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] File write blocked: %s", filename); RETURN_FALSE; }
        } else {
            if (!check_file_read_verdict(filename VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
        }
    }
    if (orig_fopen) VANDAM_FUNC_HANDLER_PASSTHRU(orig_fopen); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_file_get_contents) {
    char *filename = NULL;
    int filename_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    long offset = 0, maxlen = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|bzl!l!", &filename, &filename_len, &use_include_path, &context, &offset, &maxlen) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_read_verdict(filename VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
    if (orig_file_get_contents) VANDAM_FUNC_HANDLER_PASSTHRU(orig_file_get_contents); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_file_put_contents) {
    char *filename = NULL;
    int filename_len = 0;
    zval *data = NULL, *context = NULL;
    long flags = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "sz|llz", &filename, &filename_len, &data, &flags, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_write_verdict(filename VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] File write blocked: %s", filename); RETURN_FALSE; }
    if (orig_file_put_contents) VANDAM_FUNC_HANDLER_PASSTHRU(orig_file_put_contents); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_readfile) {
    char *filename = NULL;
    int filename_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s|bz", &filename, &filename_len, &use_include_path, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_read_verdict(filename VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
    if (orig_readfile) VANDAM_FUNC_HANDLER_PASSTHRU(orig_readfile); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_chmod) {
    char *filename = NULL;
    int filename_len = 0;
    long mode = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "sl", &filename, &filename_len, &mode) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) {
        char path_mode[2048];
        snprintf(path_mode, sizeof(path_mode), "%s (Perms: 0%lo)", filename, (unsigned long)mode);
        if (!check_exec_verdict("chmod", path_mode VANDAM_TSRMLS_CC)) { zend_error(E_WARNING, "[Vandam RASP] chmod blocked: %s", filename); RETURN_FALSE; }
    }
    if (orig_chmod) VANDAM_FUNC_HANDLER_PASSTHRU(orig_chmod); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_dl) {
    char *filename = NULL;
    int filename_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "s", &filename, &filename_len) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) query_vandam_verdict("dynamic_load", "dl", filename VANDAM_TSRMLS_CC);
    if (orig_dl) VANDAM_FUNC_HANDLER_PASSTHRU(orig_dl); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_preg_replace) {
    zval *regex = NULL;
    zval *replace = NULL;
    zval *subject = NULL;
    long limit = -1;
    zval *count = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "zzz|lz/", &regex, &replace, &subject, &limit, &count) != FAILURE) {
        if (regex) {
            if (Z_TYPE_P(regex) == IS_STRING) {
                char *pattern = Z_STRVAL_P(regex);
                if (pattern && strchr(pattern, 'e')) {
                    char *last_slash = strrchr(pattern, '/');
                    if (last_slash && strchr(last_slash, 'e')) {
                        query_vandam_verdict("eval_code", "preg_replace", pattern VANDAM_TSRMLS_CC);
                    }
                }
            } else if (Z_TYPE_P(regex) == IS_ARRAY) {
                HashTable *arr = Z_ARRVAL_P(regex);
                HashPosition pos;
                zval **val;
                zend_hash_internal_pointer_reset_ex(arr, &pos);
                while (zend_hash_get_current_data_ex(arr, (void **)&val, &pos) == SUCCESS) {
                    if (val && Z_TYPE_PP(val) == IS_STRING) {
                        char *pattern = Z_STRVAL_PP(val);
                        if (pattern) {
                            char *last_slash = strrchr(pattern, '/');
                            if (last_slash && strchr(last_slash, 'e')) {
                                query_vandam_verdict("eval_code", "preg_replace", pattern VANDAM_TSRMLS_CC);
                            }
                        }
                    }
                    zend_hash_move_forward_ex(arr, &pos);
                }
            }
        }
    }
    if (orig_preg_replace) VANDAM_FUNC_HANDLER_PASSTHRU(orig_preg_replace); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_assert) {
    zval *assertion = NULL;
    zval *description = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() VANDAM_TSRMLS_CC, "z|z", &assertion, &description) != FAILURE) {
        if (assertion && Z_TYPE_P(assertion) == IS_STRING) {
            query_vandam_verdict("eval_code", "assert", Z_STRVAL_P(assertion) VANDAM_TSRMLS_CC);
        }
    }
    if (orig_assert) VANDAM_FUNC_HANDLER_PASSTHRU(orig_assert); else RETURN_FALSE;
}

static void install_hook(const char *name, vandam_func_handler wrapper, vandam_func_handler *orig VANDAM_TSRMLS_DC) {
    zend_function *func;
    if (zend_hash_find(CG(function_table), name, strlen(name) + 1, (void **)&func) == SUCCESS) {
        *orig = func->internal_function.handler;
        func->internal_function.handler = wrapper;
    }
}

static void restore_hook(const char *name, vandam_func_handler orig VANDAM_TSRMLS_DC) {
    if (!orig) return;
    zend_function *func;
    if (zend_hash_find(CG(function_table), name, strlen(name) + 1, (void **)&func) == SUCCESS) {
        func->internal_function.handler = orig;
    }
}

void vandam_install_hooks(VANDAM_TSRMLS_D) {
    install_hook("exec", PHP_FN(vandam_exec), &orig_exec VANDAM_TSRMLS_CC);
    install_hook("shell_exec", PHP_FN(vandam_shell_exec), &orig_shell_exec VANDAM_TSRMLS_CC);
    install_hook("system", PHP_FN(vandam_system), &orig_system VANDAM_TSRMLS_CC);
    install_hook("passthru", PHP_FN(vandam_passthru), &orig_passthru VANDAM_TSRMLS_CC);
    install_hook("proc_open", PHP_FN(vandam_proc_open), &orig_proc_open VANDAM_TSRMLS_CC);
    install_hook("popen", PHP_FN(vandam_popen), &orig_popen VANDAM_TSRMLS_CC);
    install_hook("pcntl_exec", PHP_FN(vandam_pcntl_exec), &orig_pcntl_exec VANDAM_TSRMLS_CC);

    install_hook("fopen", PHP_FN(vandam_fopen), &orig_fopen VANDAM_TSRMLS_CC);
    install_hook("file_get_contents", PHP_FN(vandam_file_get_contents), &orig_file_get_contents VANDAM_TSRMLS_CC);
    install_hook("file_put_contents", PHP_FN(vandam_file_put_contents), &orig_file_put_contents VANDAM_TSRMLS_CC);
    install_hook("readfile", PHP_FN(vandam_readfile), &orig_readfile VANDAM_TSRMLS_CC);
    install_hook("chmod", PHP_FN(vandam_chmod), &orig_chmod VANDAM_TSRMLS_CC);
    install_hook("dl", PHP_FN(vandam_dl), &orig_dl VANDAM_TSRMLS_CC);
    install_hook("preg_replace", PHP_FN(vandam_preg_replace), &orig_preg_replace VANDAM_TSRMLS_CC);
    install_hook("assert", PHP_FN(vandam_assert), &orig_assert VANDAM_TSRMLS_CC);

    orig_compile_file = zend_compile_file;
    zend_compile_file = vandam_compile_file;
    orig_compile_string = zend_compile_string;
    zend_compile_string = vandam_compile_string;
}

void vandam_restore_hooks(VANDAM_TSRMLS_D) {
    restore_hook("exec", orig_exec VANDAM_TSRMLS_CC);
    restore_hook("shell_exec", orig_shell_exec VANDAM_TSRMLS_CC);
    restore_hook("system", orig_system VANDAM_TSRMLS_CC);
    restore_hook("passthru", orig_passthru VANDAM_TSRMLS_CC);
    restore_hook("proc_open", orig_proc_open VANDAM_TSRMLS_CC);
    restore_hook("popen", orig_popen VANDAM_TSRMLS_CC);
    restore_hook("pcntl_exec", orig_pcntl_exec VANDAM_TSRMLS_CC);

    restore_hook("fopen", orig_fopen VANDAM_TSRMLS_CC);
    restore_hook("file_get_contents", orig_file_get_contents VANDAM_TSRMLS_CC);
    restore_hook("file_put_contents", orig_file_put_contents VANDAM_TSRMLS_CC);
    restore_hook("readfile", orig_readfile VANDAM_TSRMLS_CC);
    restore_hook("chmod", orig_chmod VANDAM_TSRMLS_CC);
    restore_hook("dl", orig_dl VANDAM_TSRMLS_CC);
    restore_hook("preg_replace", orig_preg_replace VANDAM_TSRMLS_CC);
    restore_hook("assert", orig_assert VANDAM_TSRMLS_CC);

    if (zend_compile_file == vandam_compile_file) zend_compile_file = orig_compile_file;
    if (zend_compile_string == vandam_compile_string) zend_compile_string = orig_compile_string;
}

#endif /* PHP_VERSION_ID < 70000 */
