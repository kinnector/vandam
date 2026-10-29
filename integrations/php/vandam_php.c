#include "vandam_php.h"
#include "vandam_rasp.h"
#include "SAPI.h"

/* Define globals */
ZEND_DECLARE_MODULE_GLOBALS(vandam_php)

static void php_vandam_init_globals(zend_vandam_php_globals *vandam_php_globals);

/* INI settings definition */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("vandam_php.blocking_enabled", "1", PHP_INI_ALL, OnUpdateBool, blocking_enabled, zend_vandam_php_globals, vandam_php_globals)
    STD_PHP_INI_ENTRY("vandam_php.socket_path", "/run/vandam/rasp_telemetry.sock", PHP_INI_ALL, OnUpdateString, socket_path, zend_vandam_php_globals, vandam_php_globals)
PHP_INI_END()

/* Module initialization */
PHP_MINIT_FUNCTION(vandam_php) {
#ifdef ZTS
    ts_allocate_id(&vandam_php_globals_id, sizeof(zend_vandam_php_globals), (ts_allocate_ctor) php_vandam_init_globals, NULL);
#else
    php_vandam_init_globals(&vandam_php_globals);
#endif

    REGISTER_INI_ENTRIES();

    vandam_install_hooks(VANDAM_TSRMLS_C);

    return SUCCESS;
}

/* Module cleanup */
PHP_MSHUTDOWN_FUNCTION(vandam_php) {
    UNREGISTER_INI_ENTRIES();

    vandam_restore_hooks(VANDAM_TSRMLS_C);

    /* Free dynamically loaded paths */
    if (VANDAM_PHP_G(site_root)) {
        pefree(VANDAM_PHP_G(site_root), 1);
        VANDAM_PHP_G(site_root) = NULL;
    }
    if (VANDAM_PHP_G(allowed_read_paths)) {
        pefree(VANDAM_PHP_G(allowed_read_paths), 1);
        VANDAM_PHP_G(allowed_read_paths) = NULL;
    }
    if (VANDAM_PHP_G(allowed_write_paths)) {
        pefree(VANDAM_PHP_G(allowed_write_paths), 1);
        VANDAM_PHP_G(allowed_write_paths) = NULL;
    }
    if (VANDAM_PHP_G(blocked_read_paths)) {
        pefree(VANDAM_PHP_G(blocked_read_paths), 1);
        VANDAM_PHP_G(blocked_read_paths) = NULL;
    }
    if (VANDAM_PHP_G(blocked_write_paths)) {
        pefree(VANDAM_PHP_G(blocked_write_paths), 1);
        VANDAM_PHP_G(blocked_write_paths) = NULL;
    }

    if (VANDAM_PHP_G(client_fd) >= 0) {
        close(VANDAM_PHP_G(client_fd));
        VANDAM_PHP_G(client_fd) = -1;
    }

    return SUCCESS;
}

/* Request initialization */
PHP_RINIT_FUNCTION(vandam_php) {
    VANDAM_PHP_G(in_request) = 1;

    /* Send telemetry only once per process lifecycle */
    if (!VANDAM_PHP_G(startup_telemetry_sent)) {
        send_startup_telemetry(VANDAM_TSRMLS_C);
    }

    return SUCCESS;
}

/* Request cleanup */
PHP_RSHUTDOWN_FUNCTION(vandam_php) {
    VANDAM_PHP_G(in_request) = 0;
    return SUCCESS;
}

/* Module info (phpinfo()) */
PHP_MINFO_FUNCTION(vandam_php) {
    php_info_print_table_start();
    php_info_print_table_header(2, "vandam-php security RASP extension", "enabled");
    php_info_print_table_row(2, "version", VANDAM_PHP_VERSION);
    php_info_print_table_row(2, "author", "Kinnector Team");
    php_info_print_table_row(2, "description", "Zend RASP engine providing dynamic call & file sandboxing");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

/* Initialize Globals */
static void php_vandam_init_globals(zend_vandam_php_globals *vandam_php_globals) {
    if (sapi_module.name && strcmp(sapi_module.name, "cli") == 0) {
        vandam_php_globals->in_request = 1;
    } else {
        vandam_php_globals->in_request = 0;
    }
    vandam_php_globals->site_root = NULL;
    vandam_php_globals->allowed_read_paths = NULL;
    vandam_php_globals->allowed_write_paths = NULL;
    vandam_php_globals->blocked_read_paths = pestrdup(".env,/etc/passwd,/etc/shadow,/etc/hosts,.ssh/,.aws/credentials,.gnupg/,/proc/,/sys/", 1);
    vandam_php_globals->blocked_write_paths = pestrdup(".php,/etc/,/bin/,/usr/bin/,/sbin/,/usr/sbin/,/lib/,/usr/lib/", 1);
    vandam_php_globals->blocking_enabled = 1;
    vandam_php_globals->socket_path = NULL;
    vandam_php_globals->client_fd = -1;
    vandam_php_globals->startup_telemetry_sent = 0;
}

/* Expose functions to PHP userspace (as wrappers) */
ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(1, args)
    ZEND_ARG_INFO(1, retval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_shell_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, cmd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_system, 0, 0, 1)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(1, retval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_passthru, 0, 0, 1)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(1, retval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_proc_open, 0, 0, 3)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(0, descriptors)
    ZEND_ARG_INFO(1, pipes)
    ZEND_ARG_INFO(0, cwd)
    ZEND_ARG_INFO(0, env)
    ZEND_ARG_INFO(0, other_options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_popen, 0, 0, 2)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_pcntl_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, args)
    ZEND_ARG_INFO(0, envs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_fopen, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, use_include_path)
    ZEND_ARG_INFO(0, context)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_file_get_contents, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, use_include_path)
    ZEND_ARG_INFO(0, context)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, maxlen)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_file_put_contents, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flags)
    ZEND_ARG_INFO(0, context)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_readfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, use_include_path)
    ZEND_ARG_INFO(0, context)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_chmod, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_dl, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_preg_replace, 0, 0, 3)
    ZEND_ARG_INFO(0, regex)
    ZEND_ARG_INFO(0, replace)
    ZEND_ARG_INFO(0, subject)
    ZEND_ARG_INFO(0, limit)
    ZEND_ARG_INFO(1, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_vandam_assert, 0, 0, 1)
    ZEND_ARG_INFO(0, assertion)
    ZEND_ARG_INFO(0, description)
ZEND_END_ARG_INFO()

static const zend_function_entry vandam_php_functions[] = {
    PHP_FE(vandam_exec, arginfo_vandam_exec)
    PHP_FE(vandam_shell_exec, arginfo_vandam_shell_exec)
    PHP_FE(vandam_system, arginfo_vandam_system)
    PHP_FE(vandam_passthru, arginfo_vandam_passthru)
    PHP_FE(vandam_proc_open, arginfo_vandam_proc_open)
    PHP_FE(vandam_popen, arginfo_vandam_popen)
    PHP_FE(vandam_pcntl_exec, arginfo_vandam_pcntl_exec)
    PHP_FE(vandam_fopen, arginfo_vandam_fopen)
    PHP_FE(vandam_file_get_contents, arginfo_vandam_file_get_contents)
    PHP_FE(vandam_file_put_contents, arginfo_vandam_file_put_contents)
    PHP_FE(vandam_readfile, arginfo_vandam_readfile)
    PHP_FE(vandam_chmod, arginfo_vandam_chmod)
    PHP_FE(vandam_dl, arginfo_vandam_dl)
    PHP_FE(vandam_preg_replace, arginfo_vandam_preg_replace)
    PHP_FE(vandam_assert, arginfo_vandam_assert)
    PHP_FE_END
};

/* Module entry declaration */
zend_module_entry vandam_php_module_entry = {
    STANDARD_MODULE_HEADER,
    VANDAM_PHP_EXTNAME,
    vandam_php_functions,
    PHP_MINIT(vandam_php),
    PHP_MSHUTDOWN(vandam_php),
    PHP_RINIT(vandam_php),
    PHP_RSHUTDOWN(vandam_php),
    PHP_MINFO(vandam_php),
    VANDAM_PHP_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_VANDAM_PHP
ZEND_GET_MODULE(vandam_php)
#endif

/* Zend Extension declaration */
#ifndef ZEND_EXT_API
#define ZEND_EXT_API ZEND_API
#endif

ZEND_DLEXPORT const zend_extension_version_info extension_version_info = {
    ZEND_EXTENSION_API_NO,
    ZEND_EXTENSION_BUILD_ID
};

static int vandam_php_zend_startup(zend_extension *extension) {
    return zend_startup_module(&vandam_php_module_entry);
}

ZEND_DLEXPORT zend_extension zend_extension_entry = {
    VANDAM_PHP_EXTNAME,
    VANDAM_PHP_VERSION,
    "Kinnector Team",
    "https://github.com/kinnector/vandam-php",
    "Copyright (c) 2026",
    vandam_php_zend_startup, /* startup */
    NULL, /* shutdown */
    NULL, /* activate */
    NULL, /* deactivate */
    NULL, /* message_handler */
    NULL, /* op_array_handler */
    NULL, /* statement_handler */
    NULL, /* fcall_begin_handler */
    NULL, /* fcall_end_handler */
    NULL, /* op_array_ctor */
    NULL, /* op_array_dtor */
    STANDARD_ZEND_EXTENSION_PROPERTIES
};
