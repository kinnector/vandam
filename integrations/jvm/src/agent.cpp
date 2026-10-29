#include <jvmti.h>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <chrono>
#include <sys/syscall.h>
#include <sys/types.h>

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

// Binary layout of EDR Vandam TLS Forensic record headers
struct VandamTlsHeader {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    uint8_t container_id[12];
    uint8_t direction; // 0 = INBOUND (read), 1 = OUTBOUND (write)
    uint8_t tls_layer; // 2 = JVMTI
    uint16_t payload_len;
} __attribute__((packed));

// Extract 12-char container ID from cgroups path
void get_container_id(uint8_t* out_id) {
    memset(out_id, 0, 12);
    FILE* f = fopen("/proc/self/cgroup", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* p = strstr(line, "/docker/");
        if (!p) p = strstr(line, "/actions_job/");
        if (!p) {
            p = strrchr(line, '/');
        }
        if (p) {
            p++;
            int len = 0;
            while (p[len] && p[len] != '\n' && p[len] != '\r' && len < 12) {
                out_id[len] = p[len];
                len++;
            }
            if (len == 12) {
                break;
            }
        }
    }
    fclose(f);
}

// Send decrypted/plaintext TLS data directly to Vandam Forensic Ring Buffer socket
void send_tls_telemetry(uint8_t direction, const unsigned char* data, int len) {
    if (len <= 0) return;
    if (len > 16384) len = 16384; // cap at 16 KB

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/var/run/kinnector/tls_telemetry.sock", sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        VandamTlsHeader header;
        memset(&header, 0, sizeof(header));
        
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        header.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        
        header.pid = getpid();
        header.tid = gettid();
        
        get_container_id(header.container_id);
        
        header.direction = direction;
        header.tls_layer = 2; // Layer 2 (JVMTI)
        header.payload_len = (uint16_t)len;

        send(sock, &header, sizeof(header), 0);
        send(sock, data, len, 0);
    }
    close(sock);
}

// Unix Socket helper to send general Java-layer security alerts to vandamd API
void send_to_vandam(const char* threat_type, const char* class_name) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/var/run/kinnector/vandam.sock", sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char request[1024];
        snprintf(request, sizeof(request),
            "POST /api/v1/test-alert HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n\r\n"
            "{"
              "\"threat_type\": \"%s\","
              "\"severity\": \"HIGH\","
              "\"remediation\": {"
                "\"action\": \"LOG_ALERT\","
                "\"status\": \"JVMTI Agent detected compromised class loading: %s\""
              "}"
            "}", threat_type, class_name);

        send(sock, request, strlen(request), 0);
    }
    close(sock);
}

// JVMTI Class File Load Hook callback (Auditing & Exploits detection)
void JNICALL ClassFileLoadHook(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data
) {
    if (name != nullptr) {
        if (strstr(name, "ProcessBuilder") != nullptr || strstr(name, "Runtime") != nullptr) {
            std::cout << "[Kinnector JVMTI] Info: Process creation class loaded: " << name << std::endl;
            send_to_vandam("Threat.Java.ProcessCreationLoaded", name);
        }

        if (strstr(name, "ysoserial") != nullptr || strstr(name, "memshell") != nullptr || strstr(name, "Behinder") != nullptr || strstr(name, "Reconfigure") != nullptr) {
            std::cerr << "[Kinnector JVMTI] CRITICAL: Exploit kit or Java webshell loading detected: " << name << std::endl;
            send_to_vandam("Threat.Java.ExploitDetected", name);
        }
    }
}

// ClassPrepare Callback: Tag JSSE input/output classes for fast Method Entry/Exit lookup
void JNICALL ClassPrepare(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jthread thread,
    jclass klass
) {
    char* signature = nullptr;
    if (jvmti_env->GetClassSignature(klass, &signature, nullptr) == JVMTI_ERROR_NONE) {
        if (strcmp(signature, "Lsun/security/ssl/AppInputStream;") == 0) {
            jvmti_env->SetTag(klass, 101);
            std::cout << "[Kinnector JVMTI] Tagged AppInputStream (Tag 101) for JSSE plaintext read capture." << std::endl;
        } else if (strcmp(signature, "Lsun/security/ssl/AppOutputStream;") == 0) {
            jvmti_env->SetTag(klass, 102);
            std::cout << "[Kinnector JVMTI] Tagged AppOutputStream (Tag 102) for JSSE plaintext write capture." << std::endl;
        }
        jvmti_env->Deallocate((unsigned char*)signature);
    }
}

// MethodEntry Callback: Intercept JSSE outbound plaintext buffers before encryption
void JNICALL MethodEntry(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jthread thread,
    jmethodID method
) {
    jclass klass;
    if (jvmti_env->GetMethodDeclaringClass(method, &klass) != JVMTI_ERROR_NONE) return;

    jlong tag = 0;
    if (jvmti_env->GetTag(klass, &tag) != JVMTI_ERROR_NONE || tag != 102) return;

    char* name = nullptr;
    if (jvmti_env->GetMethodName(method, &name, nullptr, nullptr) == JVMTI_ERROR_NONE) {
        if (strcmp(name, "write") == 0) {
            jobject array_obj = nullptr;
            jint off = 0;
            jint len = 0;

            if (jvmti_env->GetLocalObject(thread, 0, 1, &array_obj) == JVMTI_ERROR_NONE &&
                jvmti_env->GetLocalInt(thread, 0, 2, &off) == JVMTI_ERROR_NONE &&
                jvmti_env->GetLocalInt(thread, 0, 3, &len) == JVMTI_ERROR_NONE) {
                
                if (array_obj != nullptr) {
                    jbyteArray byte_array = (jbyteArray)array_obj;
                    jsize array_len = jni_env->GetArrayLength(byte_array);
                    if (off >= 0 && len > 0 && (off + len) <= array_len) {
                        jbyte* bytes = jni_env->GetByteArrayElements(byte_array, nullptr);
                        if (bytes != nullptr) {
                            send_tls_telemetry(1, (const unsigned char*)(bytes + off), len);
                            jni_env->ReleaseByteArrayElements(byte_array, bytes, JNI_ABORT);
                        }
                    }
                }
            }
        }
        jvmti_env->Deallocate((unsigned char*)name);
    }
}

// MethodExit Callback: Intercept JSSE inbound plaintext buffers after decryption
void JNICALL MethodExit(
    jvmtiEnv *jvmti_env,
    JNIEnv* jni_env,
    jthread thread,
    jmethodID method,
    jboolean was_popped_by_exception,
    jvalue return_value
) {
    jclass klass;
    if (jvmti_env->GetMethodDeclaringClass(method, &klass) != JVMTI_ERROR_NONE) return;

    jlong tag = 0;
    if (jvmti_env->GetTag(klass, &tag) != JVMTI_ERROR_NONE || tag != 101) return;

    char* name = nullptr;
    if (jvmti_env->GetMethodName(method, &name, nullptr, nullptr) == JVMTI_ERROR_NONE) {
        if (strcmp(name, "read") == 0) {
            jobject array_obj = nullptr;
            jint off = 0;

            if (jvmti_env->GetLocalObject(thread, 0, 1, &array_obj) == JVMTI_ERROR_NONE &&
                jvmti_env->GetLocalInt(thread, 0, 2, &off) == JVMTI_ERROR_NONE) {

                if (array_obj != nullptr) {
                    jbyteArray byte_array = (jbyteArray)array_obj;
                    jsize array_len = jni_env->GetArrayLength(byte_array);
                    jint bytes_read = return_value.i; // read() returns count of bytes read
                    if (bytes_read > 0 && off >= 0 && (off + bytes_read) <= array_len) {
                        jbyte* bytes = jni_env->GetByteArrayElements(byte_array, nullptr);
                        if (bytes != nullptr) {
                            send_tls_telemetry(0, (const unsigned char*)(bytes + off), bytes_read);
                            jni_env->ReleaseByteArrayElements(byte_array, bytes, JNI_ABORT);
                        }
                    }
                }
            }
        }
        jvmti_env->Deallocate((unsigned char*)name);
    }
}

// Agent initialization
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    std::cout << "[Kinnector JVMTI] Native agent loaded. Registering JSSE plaintext BCI telemetry..." << std::endl;

    jvmtiEnv *jvmti = nullptr;
    jint res = vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_2);
    if (res != JNI_OK || jvmti == nullptr) {
        std::cerr << "[Kinnector JVMTI] ERROR: Unable to access JVMTI environment!" << std::endl;
        return JNI_ERR;
    }

    jvmtiCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_tag_objects = 1;
    capabilities.can_access_local_variables = 1;
    capabilities.can_generate_method_entry_events = 1;
    capabilities.can_generate_method_exit_events = 1;
    
    if (jvmti->AddCapabilities(&capabilities) != JVMTI_ERROR_NONE) {
        std::cerr << "[Kinnector JVMTI] ERROR: Failed to add necessary JVMTI capabilities!" << std::endl;
        return JNI_ERR;
    }

    jvmtiEventCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = &ClassFileLoadHook;
    callbacks.ClassPrepare = &ClassPrepare;
    callbacks.MethodEntry = &MethodEntry;
    callbacks.MethodExit = &MethodExit;

    if (jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE) {
        std::cerr << "[Kinnector JVMTI] ERROR: Failed to set event callbacks!" << std::endl;
        return JNI_ERR;
    }

    // Enable callbacks
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, nullptr);

    std::cout << "[Kinnector JVMTI] Native EDR agent successfully loaded and listening." << std::endl;
    return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    std::cout << "[Kinnector JVMTI] Native agent unloaded." << std::endl;
}
