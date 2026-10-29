#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define VANDAM_SOCKET "/run/vandam/rasp_telemetry.sock"

/* Simple Native C Socket Telemetry (Identical logic to PHP) */
static int query_vandam_verdict(const char *type, const char *func, const char *path) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return 1;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; /* 0.5s timeout */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, VANDAM_SOCKET, sizeof(sun.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        close(sock);
        return 1; /* Fail-open */
    }

    /* Extract trace via userland Perl */
    char trace_buffer[8192];
    strcpy(trace_buffer, "[]");
    
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    int count = call_pv("Vandam::get_traceback_json", G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count == 1 && !SvTRUE(ERRSV)) {
        SV *ret = POPs;
        if (SvPOK(ret)) {
            snprintf(trace_buffer, sizeof(trace_buffer), "%s", SvPV_nolen(ret));
        }
    }
    PUTBACK;
    FREETMPS;
    LEAVE;

    char payload[16384];
    snprintf(payload, sizeof(payload), 
        "{\"type\":\"%s\",\"pid\":%d,\"function\":\"%s\",\"path\":\"%s\",\"in_request\":0,\"http\":{},\"trace\":%s}\n",
        type, getpid(), func, path ? path : "", trace_buffer);

    if (send(sock, payload, strlen(payload), 0) < 0) {
        close(sock);
        return 1;
    }

    /* Fire-And-Forget Fast Path */
    if (strcmp(type, "eval_code") == 0 || strcmp(type, "file_compile") == 0) {
        close(sock);
        return 1;
    }

    char response[1024];
    memset(response, 0, sizeof(response));
    if (recv(sock, response, sizeof(response)-1, 0) > 0) {
        if (strstr(response, "\"verdict\":\"deny\"") || strstr(response, "\"verdict\": \"deny\"")) {
            close(sock);
            return 0; /* Deny */
        }
    }
    close(sock);
    return 1; /* Allow */
}

/* ==========================================
 * NATIVE OPCODE HOOKS (Like PHP Zend Engine)
 * ========================================== */

/* 1. OP_SYSTEM Hook */
static OP* (*orig_pp_system)(pTHX);
static OP* vandam_pp_system(pTHX) {
    if (!query_vandam_verdict("exec_call", "system", "[Intercepted via Opcode]")) {
        croak("Vandam RASP blocked execution of 'system'");
    }
    return orig_pp_system(aTHX);
}

static Perl_check_t orig_check_system;
static OP* vandam_check_system(pTHX_ OP *op) {
    op = orig_check_system(aTHX_ op);
    if (op->op_ppaddr != vandam_pp_system) {
        orig_pp_system = op->op_ppaddr;
        op->op_ppaddr = vandam_pp_system;
    }
    return op;
}

/* 2. OP_EXEC Hook */
static OP* (*orig_pp_exec)(pTHX);
static OP* vandam_pp_exec(pTHX) {
    if (!query_vandam_verdict("exec_call", "exec", "[Intercepted via Opcode]")) {
        croak("Vandam RASP blocked execution of 'exec'");
    }
    return orig_pp_exec(aTHX);
}

static Perl_check_t orig_check_exec;
static OP* vandam_check_exec(pTHX_ OP *op) {
    op = orig_check_exec(aTHX_ op);
    if (op->op_ppaddr != vandam_pp_exec) {
        orig_pp_exec = op->op_ppaddr;
        op->op_ppaddr = vandam_pp_exec;
    }
    return op;
}

/* 3. OP_ENTEREVAL Hook (String Eval execution) */
static OP* (*orig_pp_entereval)(pTHX);
static OP* vandam_pp_entereval(pTHX) {
    dSP;
    SV *sv = TOPs;
    if (sv && SvPOK(sv)) {
        char *code = SvPV_nolen(sv);
        char preview[1024];
        snprintf(preview, sizeof(preview), "%.1000s", code);
        query_vandam_verdict("eval_code", "eval", preview);
    }
    return orig_pp_entereval(aTHX);
}

static Perl_check_t orig_check_entereval;
static OP* vandam_check_entereval(pTHX_ OP *op) {
    op = orig_check_entereval(aTHX_ op);
    if (op->op_ppaddr != vandam_pp_entereval) {
        orig_pp_entereval = op->op_ppaddr;
        op->op_ppaddr = vandam_pp_entereval;
    }
    return op;
}


MODULE = Vandam		PACKAGE = Vandam		

BOOT:
    /* Replace Native Perl Opcode Compilation Checkers */
    orig_check_system = PL_check[OP_SYSTEM];
    PL_check[OP_SYSTEM] = vandam_check_system;

    orig_check_exec = PL_check[OP_EXEC];
    PL_check[OP_EXEC] = vandam_check_exec;

    orig_check_entereval = PL_check[OP_ENTEREVAL];
    PL_check[OP_ENTEREVAL] = vandam_check_entereval;
