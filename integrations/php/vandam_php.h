#ifndef VANDAM_PHP_H
#define VANDAM_PHP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_extensions.h"

#define VANDAM_PHP_EXTNAME "vandam_php"
#define VANDAM_PHP_VERSION "1.0.0"

extern zend_module_entry vandam_php_module_entry;
#define phpext_vandam_php_ptr &vandam_php_module_entry

/* Global variables for the extension */
ZEND_BEGIN_MODULE_GLOBALS(vandam_php)
    int in_request;
    char *site_root;
    char *allowed_read_paths;
    char *allowed_write_paths;
    char *blocked_read_paths;
    char *blocked_write_paths;
    int blocking_enabled;
    char *socket_path;
    int client_fd;
    int startup_telemetry_sent;
ZEND_END_MODULE_GLOBALS(vandam_php)
ZEND_EXTERN_MODULE_GLOBALS(vandam_php)

/* Macro to access globals in a thread-safe/non-thread-safe way */
#ifdef ZTS
#define VANDAM_PHP_G(v) TSRMG(vandam_php_globals_id, zend_vandam_php_globals *, v)
#else
#define VANDAM_PHP_G(v) (vandam_php_globals.v)
#endif

/* Compatibility macros for PHP 5, 7, 8 */
#if PHP_VERSION_ID < 70000
    /* PHP 5.6 */
    #define zend_size_t int
    #define VANDAM_TSRMLS_CC TSRMLS_CC
    #define VANDAM_TSRMLS_DC TSRMLS_DC
    #define VANDAM_TSRMLS_C TSRMLS_C
    #define VANDAM_TSRMLS_D TSRMLS_D
    #define VANDAM_FUNC_HANDLER_PASSTHRU(name) name(INTERNAL_FUNCTION_PARAM_PASSTHRU)
    
    #define ZEND_HASH_FIND_PTR(ht, key, key_len, val_ptr) \
        (zend_hash_find(ht, key, key_len, (void **)&val_ptr) == SUCCESS)
#else
    /* PHP 7 and 8 */
    #define zend_size_t size_t
    #define VANDAM_TSRMLS_CC
    #define VANDAM_TSRMLS_DC
    #define VANDAM_TSRMLS_C
    #define VANDAM_TSRMLS_D void
    #define VANDAM_FUNC_HANDLER_PASSTHRU(name) name(INTERNAL_FUNCTION_PARAM_PASSTHRU)
    
    #define ZEND_HASH_FIND_PTR(ht, key, key_len, val_ptr) \
        ((val_ptr = zend_hash_str_find_ptr(ht, key, key_len)) != NULL)
#endif

#if PHP_VERSION_ID >= 80000
    /* PHP 8 */
    #define VANDAM_ARG_INFO_RETVAL_OBJ(name, classname, allow_null) \
        ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(name, 0, 0, classname, allow_null)
#else
    /* PHP 5 and 7 */
    #define VANDAM_ARG_INFO_RETVAL_OBJ(name, classname, allow_null) \
        ZEND_BEGIN_ARG_INFO_EX(name, 0, 0, 0)
#endif

typedef void (*vandam_func_handler)(INTERNAL_FUNCTION_PARAMETERS);

/* Function hook declarations */
PHP_FUNCTION(vandam_exec);
PHP_FUNCTION(vandam_shell_exec);
PHP_FUNCTION(vandam_system);
PHP_FUNCTION(vandam_passthru);
PHP_FUNCTION(vandam_proc_open);
PHP_FUNCTION(vandam_popen);
PHP_FUNCTION(vandam_pcntl_exec);

PHP_FUNCTION(vandam_fopen);
PHP_FUNCTION(vandam_file_get_contents);
PHP_FUNCTION(vandam_file_put_contents);
PHP_FUNCTION(vandam_readfile);
PHP_FUNCTION(vandam_chmod);
PHP_FUNCTION(vandam_dl);
PHP_FUNCTION(vandam_preg_replace);
PHP_FUNCTION(vandam_assert);

#endif /* VANDAM_PHP_H */
