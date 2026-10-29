#include "vandam_rasp.h"
#include "SAPI.h"

#if PHP_VERSION_ID >= 70000

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

static zend_op_array *(*orig_compile_file)(zend_file_handle *file_handle, int type) = NULL;
#if PHP_VERSION_ID >= 80200
static zend_op_array *(*orig_compile_string)(zend_string *source_string, const char *filename, zend_compile_position position) = NULL;
#elif PHP_VERSION_ID >= 80000
static zend_op_array *(*orig_compile_string)(zend_string *source_string, const char *filename) = NULL;
#else
static zend_op_array *(*orig_compile_string)(zval *source_string, char *filename) = NULL;
#endif
static vandam_func_handler orig_dl = NULL;
static vandam_func_handler orig_preg_replace = NULL;
static vandam_func_handler orig_assert = NULL;

char *get_json_encoded_global(const char *global_name VANDAM_TSRMLS_DC) {
    zend_is_auto_global_str((char*)global_name, strlen(global_name));
    zval *global_arr = zend_hash_str_find(&EG(symbol_table), global_name, strlen(global_name));
    if (!global_arr || Z_TYPE_P(global_arr) != IS_ARRAY) return NULL;

    zval func_name, retval;
    ZVAL_STRING(&func_name, "json_encode");

    zval params[2];
    ZVAL_COPY_VALUE(&params[0], global_arr);
    ZVAL_LONG(&params[1], 512);

    char *result = NULL;
    if (call_user_function(CG(function_table), NULL, &func_name, &retval, 2, params) == SUCCESS) {
        if (Z_TYPE(retval) == IS_STRING) {
            result = estrdup(Z_STRVAL(retval));
        }
        zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&func_name);
    return result;
}

char *build_json_trace(VANDAM_TSRMLS_D) {
    size_t alloc_size = 8192;
    char *trace = pemalloc(alloc_size, 0);
    if (!trace) return NULL;
    
    strcpy(trace, "[");
    size_t current_len = 1;

    zend_execute_data *ptr = EG(current_execute_data);
    int first = 1;
    int limit = 15;
    while (ptr && limit > 0) {
        if (ptr->func) {
            const char *file_name = "";
            const char *func_name = "";
            const char *class_name = "";
            uint32_t line_num = 0;

            if (ptr->func->type == ZEND_USER_FUNCTION) {
                if (ptr->func->op_array.filename) {
                    file_name = ZSTR_VAL(ptr->func->op_array.filename);
                }
                if (ptr->opline) {
                    line_num = ptr->opline->lineno;
                }
            } else if (ptr->func->type == ZEND_INTERNAL_FUNCTION) {
                file_name = "[internal function]";
            }

            if (ptr->func->common.function_name) {
                func_name = ZSTR_VAL(ptr->func->common.function_name);
            }
            if (ptr->func->common.scope && ptr->func->common.scope->name) {
                class_name = ZSTR_VAL(ptr->func->common.scope->name);
            }

            char args_buf[1024] = "[";
            uint32_t num_args = ZEND_CALL_NUM_ARGS(ptr);
            for (uint32_t i = 1; i <= num_args && i <= 5; i++) {
                zval *arg = ZEND_CALL_ARG(ptr, i);
                if (!arg) continue;
                
                char arg_str[256] = "";
                if (Z_TYPE_P(arg) == IS_STRING) {
                    char esc_arg[128] = "";
                    escape_json_string(Z_STRVAL_P(arg), esc_arg, sizeof(esc_arg));
                    snprintf(arg_str, sizeof(arg_str), "\"%s\"", esc_arg);
                } else if (Z_TYPE_P(arg) == IS_LONG) {
                    snprintf(arg_str, sizeof(arg_str), "%ld", Z_LVAL_P(arg));
                } else if (Z_TYPE_P(arg) == IS_DOUBLE) {
                    snprintf(arg_str, sizeof(arg_str), "%f", Z_DVAL_P(arg));
                } else if (Z_TYPE_P(arg) == IS_TRUE) {
                    strcpy(arg_str, "true");
                } else if (Z_TYPE_P(arg) == IS_FALSE) {
                    strcpy(arg_str, "false");
                } else if (Z_TYPE_P(arg) == IS_NULL) {
                    strcpy(arg_str, "null");
                } else if (Z_TYPE_P(arg) == IS_ARRAY) {
                    strcpy(arg_str, "\"[array]\"");
                } else if (Z_TYPE_P(arg) == IS_OBJECT) {
                    strcpy(arg_str, "\"[object]\"");
                } else {
                    strcpy(arg_str, "\"[unknown]\"");
                }

                if (i > 1) strcat(args_buf, ",");
                if (strlen(args_buf) + strlen(arg_str) + 2 < sizeof(args_buf)) {
                    strcat(args_buf, arg_str);
                }
            }
            if (num_args > 5) strcat(args_buf, ",\"...\"");
            strcat(args_buf, "]");

            char frame[2048];
            char esc_file[512] = "";
            char esc_func[128] = "";
            char esc_class[128] = "";
            
            escape_json_string(file_name, esc_file, sizeof(esc_file));
            escape_json_string(func_name, esc_func, sizeof(esc_func));
            escape_json_string(class_name, esc_class, sizeof(esc_class));

            int written = snprintf(frame, sizeof(frame), "%s{\"file\":\"%s\",\"line\":%u,\"function\":\"%s\",\"class\":\"%s\",\"args\":%s}",
                     first ? "" : ",", esc_file, line_num, esc_func, esc_class, args_buf);
                     
            if (written > 0 && current_len + written + 4 < alloc_size) {
                strcpy(trace + current_len, frame);
                current_len += written;
            } else {
                break;
            }
            first = 0;
        }
        ptr = ptr->prev_execute_data;
        limit--;
    }

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
    if (zend_hash_str_exists(&module_registry, "opcache", 7)) strcat(ext_list, "\"opcache\",");
    if (zend_hash_str_exists(&module_registry, "imagick", 7)) strcat(ext_list, "\"imagick\",");
    if (zend_hash_str_exists(&module_registry, "redis", 5)) strcat(ext_list, "\"redis\",");
    if (zend_hash_str_exists(&module_registry, "curl", 4)) strcat(ext_list, "\"curl\",");
    if (zend_hash_str_exists(&module_registry, "gd", 2)) strcat(ext_list, "\"gd\",");
    if (zend_hash_str_exists(&module_registry, "zip", 3)) strcat(ext_list, "\"zip\",");

    size_t ext_len = strlen(ext_list);
    if (ext_len > 0 && ext_list[ext_len - 1] == ',') {
        ext_list[ext_len - 1] = '\0';
    }

    int opcache_enabled = 0;
    int jit_enabled = 0;
    if (zend_hash_str_exists(&module_registry, "opcache", 7)) {
        opcache_enabled = 1;
        zval *jit = cfg_get_entry("opcache.jit", sizeof("opcache.jit") - 1);
        if (jit && Z_TYPE_P(jit) == IS_STRING && Z_STRLEN_P(jit) > 0) {
            char *jit_str = Z_STRVAL_P(jit);
            if (strcmp(jit_str, "off") != 0 && strcmp(jit_str, "0") != 0) {
                jit_enabled = 1;
            }
        }
    }

    char *manifest = pemalloc(8192, 0);
    manifest[0] = '\0';
    size_t manifest_len = 0;
    size_t manifest_max = 8192;
    int first = 1;

    zval *zv;
    ZEND_HASH_FOREACH_VAL(&EG(included_files), zv) {
        if (Z_TYPE_P(zv) == IS_STRING) {
            char *path = Z_STRVAL_P(zv);
            size_t path_len = strlen(path);
            if (manifest_len + path_len + 16 < manifest_max) {
                if (!first) {
                    strcat(manifest + manifest_len, ",");
                    manifest_len++;
                }
                strcat(manifest + manifest_len, "\"");
                manifest_len++;

                for (size_t i = 0; i < path_len; i++) {
                    if (path[i] == '\\' || path[i] == '"') {
                        manifest[manifest_len++] = '\\';
                    }
                    manifest[manifest_len++] = path[i];
                }

                manifest[manifest_len++] = '"';
                manifest[manifest_len] = '\0';
                first = 0;
            }
        }
    } ZEND_HASH_FOREACH_END();

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
        "{\"type\":\"startup\",\"pid\":%d,\"php_version\":\"%s\",\"sapi\":\"%s\",\"autoload_manifest\":[%s],\"loaded_extensions\":[%s],\"opcache\":{\"enabled\":%s,\"jit_enabled\":%s},\"ini\":{\"open_basedir\":\"%s\",\"disable_functions\":\"%s\",\"memory_limit\":\"%s\",\"max_execution_time\":%ld}}\n",
        getpid(), PHP_VERSION, sapi_module.name, manifest, ext_list,
        opcache_enabled ? "true" : "false",
        jit_enabled ? "true" : "false",
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

static zend_op_array *vandam_compile_file(zend_file_handle *file_handle, int type) {
    const char *filename = NULL;
    if (file_handle && file_handle->filename) {
#if PHP_VERSION_ID >= 80100
        filename = ZSTR_VAL(file_handle->filename);
#else
        filename = file_handle->filename;
#endif
    }

    if (filename) {
        char resolved_path[MAXPATHLEN];
        if (!VCWD_REALPATH(filename, resolved_path)) {
            strncpy(resolved_path, filename, sizeof(resolved_path) - 1);
            resolved_path[sizeof(resolved_path) - 1] = '\0';
        }

        if (!query_vandam_verdict("file_compile", NULL, resolved_path)) {
            zend_error(E_COMPILE_ERROR, "[Vandam RASP] Blocked loading unauthorized PHP file: %s", filename);
            return NULL;
        }
    }
    return orig_compile_file(file_handle, type);
}

#if PHP_VERSION_ID >= 80200
static zend_op_array *vandam_compile_string(zend_string *source_string, const char *filename, zend_compile_position position) {
    if (source_string) {
        char *code = ZSTR_VAL(source_string);
        char preview[1024];
        snprintf(preview, sizeof(preview), "%.1000s", code);
        query_vandam_verdict("eval_code", "eval", preview);
    }
    if (orig_compile_string) {
        return orig_compile_string(source_string, filename, position);
    }
    return NULL;
}
#elif PHP_VERSION_ID >= 80000
static zend_op_array *vandam_compile_string(zend_string *source_string, const char *filename) {
    if (source_string) {
        char *code = ZSTR_VAL(source_string);
        char preview[1024];
        snprintf(preview, sizeof(preview), "%.1000s", code);
        query_vandam_verdict("eval_code", "eval", preview);
    }
    if (orig_compile_string) {
        return orig_compile_string(source_string, filename);
    }
    return NULL;
}
#else
static zend_op_array *vandam_compile_string(zval *source_string, char *filename) {
    if (source_string && Z_TYPE_P(source_string) == IS_STRING) {
        char *code = Z_STRVAL_P(source_string);
        char preview[1024];
        snprintf(preview, sizeof(preview), "%.1000s", code);
        query_vandam_verdict("eval_code", "eval", preview);
    }
    if (orig_compile_string) {
        return orig_compile_string(source_string, filename);
    }
    return NULL;
}
#endif

PHP_FUNCTION(vandam_exec) {
    char *cmd = NULL;
    size_t cmd_len = 0;
    zval *args = NULL;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|z/z/", &cmd, &cmd_len, &args, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("exec", cmd)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_shell_exec) {
    char *cmd = NULL;
    size_t cmd_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &cmd, &cmd_len) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("shell_exec", cmd)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_shell_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_shell_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_system) {
    char *cmd = NULL;
    size_t cmd_len = 0;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|z/", &cmd, &cmd_len, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("system", cmd)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_system) VANDAM_FUNC_HANDLER_PASSTHRU(orig_system); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_passthru) {
    char *cmd = NULL;
    size_t cmd_len = 0;
    zval *retval = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|z/", &cmd, &cmd_len, &retval) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("passthru", cmd)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_passthru) VANDAM_FUNC_HANDLER_PASSTHRU(orig_passthru); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_proc_open) {
    zval *cmd_zval = NULL, *descriptors = NULL, *pipes = NULL, *env = NULL, *other_options = NULL;
    char *cwd = NULL;
    size_t cwd_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zaz|s!a!a!", &cmd_zval, &descriptors, &pipes, &cwd, &cwd_len, &env, &other_options) == FAILURE) RETURN_FALSE;
    if (cmd_zval && Z_TYPE_P(cmd_zval) == IS_STRING) {
        char *cmd = Z_STRVAL_P(cmd_zval);
        if (cmd && strlen(cmd) > 0 && !check_exec_verdict("proc_open", cmd)) {
            zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
            RETURN_FALSE;
        }
    }
    if (orig_proc_open) VANDAM_FUNC_HANDLER_PASSTHRU(orig_proc_open); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_popen) {
    char *cmd = NULL, *mode = NULL;
    size_t cmd_len = 0, mode_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &cmd, &cmd_len, &mode, &mode_len) == FAILURE) RETURN_FALSE;
    if (cmd && cmd_len > 0 && !check_exec_verdict("popen", cmd)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", cmd);
        RETURN_FALSE;
    }
    if (orig_popen) VANDAM_FUNC_HANDLER_PASSTHRU(orig_popen); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_pcntl_exec) {
    char *path = NULL;
    size_t path_len = 0;
    zval *args = NULL, *envs = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|a!a!", &path, &path_len, &args, &envs) == FAILURE) RETURN_FALSE;
    if (path && path_len > 0 && !check_exec_verdict("pcntl_exec", path)) {
        zend_error(E_WARNING, "[Vandam RASP] Exec blocked by security policy: %s", path);
        RETURN_FALSE;
    }
    if (orig_pcntl_exec) VANDAM_FUNC_HANDLER_PASSTHRU(orig_pcntl_exec); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_fopen) {
    char *filename = NULL, *mode = NULL;
    size_t filename_len = 0, mode_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|bz", &filename, &filename_len, &mode, &mode_len, &use_include_path, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) {
        int is_write = 0;
        if (mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, 'x') || strchr(mode, 'c') || strchr(mode, '+'))) is_write = 1;
        if (is_write) {
            if (!check_file_write_verdict(filename)) { zend_error(E_WARNING, "[Vandam RASP] File write blocked: %s", filename); RETURN_FALSE; }
        } else {
            if (!check_file_read_verdict(filename)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
        }
    }
    if (orig_fopen) VANDAM_FUNC_HANDLER_PASSTHRU(orig_fopen); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_file_get_contents) {
    char *filename = NULL;
    size_t filename_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    zend_long offset = 0, maxlen = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|bzl!l!", &filename, &filename_len, &use_include_path, &context, &offset, &maxlen) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_read_verdict(filename)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
    if (orig_file_get_contents) VANDAM_FUNC_HANDLER_PASSTHRU(orig_file_get_contents); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_file_put_contents) {
    char *filename = NULL;
    size_t filename_len = 0;
    zval *data = NULL, *context = NULL;
    zend_long flags = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz|llz", &filename, &filename_len, &data, &flags, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_write_verdict(filename)) { zend_error(E_WARNING, "[Vandam RASP] File write blocked: %s", filename); RETURN_FALSE; }
    if (orig_file_put_contents) VANDAM_FUNC_HANDLER_PASSTHRU(orig_file_put_contents); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_readfile) {
    char *filename = NULL;
    size_t filename_len = 0;
    zend_bool use_include_path = 0;
    zval *context = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|bz", &filename, &filename_len, &use_include_path, &context) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0 && !check_file_read_verdict(filename)) { zend_error(E_WARNING, "[Vandam RASP] File read blocked: %s", filename); RETURN_FALSE; }
    if (orig_readfile) VANDAM_FUNC_HANDLER_PASSTHRU(orig_readfile); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_chmod) {
    char *filename = NULL;
    size_t filename_len = 0;
    zend_long mode = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &filename, &filename_len, &mode) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) {
        char path_mode[2048];
        snprintf(path_mode, sizeof(path_mode), "%s (Perms: 0%lo)", filename, (unsigned long)mode);
        if (!check_exec_verdict("chmod", path_mode)) { zend_error(E_WARNING, "[Vandam RASP] chmod blocked: %s", filename); RETURN_FALSE; }
    }
    if (orig_chmod) VANDAM_FUNC_HANDLER_PASSTHRU(orig_chmod); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_dl) {
    char *filename = NULL;
    size_t filename_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &filename, &filename_len) == FAILURE) RETURN_FALSE;
    if (filename && filename_len > 0) query_vandam_verdict("dynamic_load", "dl", filename);
    if (orig_dl) VANDAM_FUNC_HANDLER_PASSTHRU(orig_dl); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_preg_replace) {
    zval *regex = NULL;
    zval *replace = NULL;
    zval *subject = NULL;
    zend_long limit = -1;
    zval *count = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz|lz/", &regex, &replace, &subject, &limit, &count) != FAILURE) {
        if (regex) {
            if (Z_TYPE_P(regex) == IS_STRING) {
                char *pattern = Z_STRVAL_P(regex);
                if (pattern && strchr(pattern, 'e')) {
                    char *last_slash = strrchr(pattern, '/');
                    if (last_slash && strchr(last_slash, 'e')) {
                        query_vandam_verdict("eval_code", "preg_replace", pattern);
                    }
                }
            } else if (Z_TYPE_P(regex) == IS_ARRAY) {
                zval *val;
                ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(regex), val) {
                    if (Z_TYPE_P(val) == IS_STRING) {
                        char *pattern = Z_STRVAL_P(val);
                        if (pattern) {
                            char *last_slash = strrchr(pattern, '/');
                            if (last_slash && strchr(last_slash, 'e')) {
                                query_vandam_verdict("eval_code", "preg_replace", pattern);
                            }
                        }
                    }
                } ZEND_HASH_FOREACH_END();
            }
        }
    }
    if (orig_preg_replace) VANDAM_FUNC_HANDLER_PASSTHRU(orig_preg_replace); else RETURN_FALSE;
}

PHP_FUNCTION(vandam_assert) {
    zval *assertion = NULL;
    zval *description = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|z", &assertion, &description) != FAILURE) {
        if (assertion && Z_TYPE_P(assertion) == IS_STRING) {
            query_vandam_verdict("eval_code", "assert", Z_STRVAL_P(assertion));
        }
    }
    if (orig_assert) VANDAM_FUNC_HANDLER_PASSTHRU(orig_assert); else RETURN_FALSE;
}

static void install_hook(const char *name, vandam_func_handler wrapper, vandam_func_handler *orig) {
    zend_function *func = zend_hash_str_find_ptr(CG(function_table), name, strlen(name));
    if (func) { *orig = func->internal_function.handler; func->internal_function.handler = wrapper; }
}

static void restore_hook(const char *name, vandam_func_handler orig) {
    if (!orig) return;
    zend_function *func = zend_hash_str_find_ptr(CG(function_table), name, strlen(name));
    if (func) { func->internal_function.handler = orig; }
}

void vandam_install_hooks(VANDAM_TSRMLS_D) {
    install_hook("exec", PHP_FN(vandam_exec), &orig_exec);
    install_hook("shell_exec", PHP_FN(vandam_shell_exec), &orig_shell_exec);
    install_hook("system", PHP_FN(vandam_system), &orig_system);
    install_hook("passthru", PHP_FN(vandam_passthru), &orig_passthru);
    install_hook("proc_open", PHP_FN(vandam_proc_open), &orig_proc_open);
    install_hook("popen", PHP_FN(vandam_popen), &orig_popen);
    install_hook("pcntl_exec", PHP_FN(vandam_pcntl_exec), &orig_pcntl_exec);

    install_hook("fopen", PHP_FN(vandam_fopen), &orig_fopen);
    install_hook("file_get_contents", PHP_FN(vandam_file_get_contents), &orig_file_get_contents);
    install_hook("file_put_contents", PHP_FN(vandam_file_put_contents), &orig_file_put_contents);
    install_hook("readfile", PHP_FN(vandam_readfile), &orig_readfile);
    install_hook("chmod", PHP_FN(vandam_chmod), &orig_chmod);
    install_hook("dl", PHP_FN(vandam_dl), &orig_dl);
    install_hook("preg_replace", PHP_FN(vandam_preg_replace), &orig_preg_replace);
    install_hook("assert", PHP_FN(vandam_assert), &orig_assert);

    orig_compile_file = zend_compile_file;
    zend_compile_file = vandam_compile_file;
    orig_compile_string = zend_compile_string;
    zend_compile_string = vandam_compile_string;
}

void vandam_restore_hooks(VANDAM_TSRMLS_D) {
    restore_hook("exec", orig_exec);
    restore_hook("shell_exec", orig_shell_exec);
    restore_hook("system", orig_system);
    restore_hook("passthru", orig_passthru);
    restore_hook("proc_open", orig_proc_open);
    restore_hook("popen", orig_popen);
    restore_hook("pcntl_exec", orig_pcntl_exec);

    restore_hook("fopen", orig_fopen);
    restore_hook("file_get_contents", orig_file_get_contents);
    restore_hook("file_put_contents", orig_file_put_contents);
    restore_hook("readfile", orig_readfile);
    restore_hook("chmod", orig_chmod);
    restore_hook("dl", orig_dl);
    restore_hook("preg_replace", orig_preg_replace);
    restore_hook("assert", orig_assert);

    if (zend_compile_file == vandam_compile_file) zend_compile_file = orig_compile_file;
    if (zend_compile_string == vandam_compile_string) zend_compile_string = orig_compile_string;
}

#endif /* PHP_VERSION_ID >= 70000 */
