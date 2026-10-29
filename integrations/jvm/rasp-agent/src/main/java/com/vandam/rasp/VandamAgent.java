package com.vandam.rasp;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.implementation.MethodDelegation;
import net.bytebuddy.implementation.bind.annotation.*;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.lang.reflect.Method;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;

public class VandamAgent {

    private static final String VANDAM_SOCKET_PATH = "/run/vandam/rasp.sock";
    private static final String VANDAM_TELEMETRY_SOCKET_PATH = "/run/vandam/rasp_telemetry.sock";
    private static final int VANDAM_TCP_PORT = 45300;
    private static final int VANDAM_TELEMETRY_TCP_PORT = 45301;
    
    private static final Map<String, String> VERDICT_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Boolean> TELEMETRY_CACHE = new ConcurrentHashMap<>();
    private static final ThreadLocal<Boolean> inVandam = new ThreadLocal<Boolean>() {
        @Override protected Boolean initialValue() { return false; }
    };
    private static int IS_INSTALL_CONTEXT = 0;
    private static boolean supportsUnixSockets = false;

    private static long getPid() {
        try {
            String name = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            return Long.parseLong(name.split("@")[0]);
        } catch (Exception e) {
            return 0;
        }
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[Vandam RASP] Initializing Java Bytecode Interceptor (Java 8+)...");
        try {
            System.setProperty("vandam.pid", String.valueOf(getPid()));
            String cmd = System.getProperty("sun.java.command", "").toLowerCase();
            if (cmd.contains("maven") || cmd.contains("gradle") || cmd.contains("mvn")) {
                System.setProperty("vandam.install.context", "1");
                IS_INSTALL_CONTEXT = 1;
            } else {
                System.setProperty("vandam.install.context", "0");
                IS_INSTALL_CONTEXT = 0;
            }
        } catch (Exception e) {}

        try {
            Class.forName("java.net.UnixDomainSocketAddress");
            supportsUnixSockets = true;
        } catch (ClassNotFoundException e) {
            supportsUnixSockets = false;
        }

        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            .with(AgentBuilder.InjectionStrategy.UsingUnsafe.INSTANCE)
            .ignore(ElementMatchers.none())
            .ignore(ElementMatchers.nameStartsWith("net.bytebuddy.")
                    .or(ElementMatchers.nameStartsWith("com.vandam.rasp.")))
            // 1. COMMAND EXECUTION
            .type(ElementMatchers.named("java.lang.ProcessBuilder"))
            .transform(new AgentBuilder.Transformer.ForAdvice().include(VandamAgent.class.getClassLoader())
                .advice(ElementMatchers.named("start"), ProcessBuilderAdvice.class.getName()))
                       
            // 2. FILE READS
            .type(ElementMatchers.named("java.io.FileInputStream"))
            .transform(new AgentBuilder.Transformer.ForAdvice().include(VandamAgent.class.getClassLoader())
                .advice(ElementMatchers.isConstructor().and(ElementMatchers.takesArguments(1)), FileReadAdvice.class.getName()))

            // 3. DYNAMIC CLASS LOADING / JNI
            .type(ElementMatchers.named("java.lang.Runtime"))
            .transform(new AgentBuilder.Transformer.ForAdvice().include(VandamAgent.class.getClassLoader())
                .advice(ElementMatchers.named("loadLibrary0"), JniAdvice.class.getName()))
            
            // 4. JNDI INJECTION (Log4Shell)
            .type(ElementMatchers.named("javax.naming.InitialContext"))
            .transform(new AgentBuilder.Transformer.ForAdvice().include(VandamAgent.class.getClassLoader())
                .advice(ElementMatchers.named("lookup"), JndiAdvice.class.getName()))

            // 5. DESERIALIZATION (Ysoserial)
            .type(ElementMatchers.named("java.io.ObjectInputStream"))
            .transform(new AgentBuilder.Transformer.ForAdvice().include(VandamAgent.class.getClassLoader())
                .advice(ElementMatchers.named("resolveClass"), DeserializationAdvice.class.getName()))

            .installOn(inst);
    }

    public static void sendPayload(String payload, boolean isTelemetry) throws Exception {
        if (supportsUnixSockets) {
            try {
                Class<?> protocolFamilyClass = Class.forName("java.net.StandardProtocolFamily");
                Object unixFamily = null;
                for (Object enumConstant : protocolFamilyClass.getEnumConstants()) {
                    if ("UNIX".equals(enumConstant.toString())) {
                        unixFamily = enumConstant;
                        break;
                    }
                }
                
                Method openMethod = SocketChannel.class.getMethod("open", java.net.ProtocolFamily.class);
                SocketChannel channel = (SocketChannel) openMethod.invoke(null, unixFamily);
                
                Class<?> unixAddrClass = Class.forName("java.net.UnixDomainSocketAddress");
                Method ofMethod = unixAddrClass.getMethod("of", String.class);
                Object address = ofMethod.invoke(null, isTelemetry ? VANDAM_TELEMETRY_SOCKET_PATH : VANDAM_SOCKET_PATH);
                
                channel.connect((java.net.SocketAddress) address);
                channel.write(ByteBuffer.wrap(payload.getBytes("UTF-8")));
                channel.close();
                return;
            } catch (Exception e) {}
        }
        
        // TCP Fallback for Java 8-15
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", isTelemetry ? VANDAM_TELEMETRY_TCP_PORT : VANDAM_TCP_PORT), 100);
            OutputStream os = socket.getOutputStream();
            os.write(payload.getBytes("UTF-8"));
            os.flush();
        }
    }

    public static String sendAndReceivePayload(String payload) throws Exception {
        if (supportsUnixSockets) {
            try {
                Class<?> protocolFamilyClass = Class.forName("java.net.StandardProtocolFamily");
                Object unixFamily = null;
                for (Object enumConstant : protocolFamilyClass.getEnumConstants()) {
                    if ("UNIX".equals(enumConstant.toString())) {
                        unixFamily = enumConstant;
                        break;
                    }
                }
                
                Method openMethod = SocketChannel.class.getMethod("open", java.net.ProtocolFamily.class);
                SocketChannel channel = (SocketChannel) openMethod.invoke(null, unixFamily);
                
                Class<?> unixAddrClass = Class.forName("java.net.UnixDomainSocketAddress");
                Method ofMethod = unixAddrClass.getMethod("of", String.class);
                Object address = ofMethod.invoke(null, VANDAM_SOCKET_PATH);
                
                channel.connect((java.net.SocketAddress) address);
                channel.write(ByteBuffer.wrap(payload.getBytes("UTF-8")));
                
                ByteBuffer buffer = ByteBuffer.allocate(1024);
                int read = channel.read(buffer);
                channel.close();
                if (read > 0) {
                    return new String(buffer.array(), 0, read);
                }
                return null;
            } catch (Exception e) {}
        }
        
        // TCP Fallback for Java 8-15
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", VANDAM_TCP_PORT), 100);
            OutputStream os = socket.getOutputStream();
            os.write(payload.getBytes("UTF-8"));
            os.flush();
            
            InputStream is = socket.getInputStream();
            byte[] buf = new byte[1024];
            int read = is.read(buf);
            if (read > 0) {
                return new String(buf, 0, read);
            }
        }
        return null;
    }

    public static void askVandam(String type, String func, String path, boolean fireAndForget) {
        if (inVandam.get()) return;
        inVandam.set(true);
        try {
            String pathStr = path != null ? path : "";
            int payloadSizeBytes = pathStr.length();
            long pid = 0;
            try {
                pid = Long.parseLong(System.getProperty("vandam.pid"));
            } catch (Exception e) {}

            if (("eval_code".equals(type) || "file_compile".equals(type)) && payloadSizeBytes > 2097152) {
                throw new SecurityException("Vandam RASP blocked execution: Payload exceeded 2MB hard cap (" + payloadSizeBytes + " bytes).");
            }

            if (payloadSizeBytes > 4096) {
                pathStr = pathStr.substring(0, 2048) + "\n...[TRUNCATED_MIDDLE]...\n" + pathStr.substring(payloadSizeBytes - 2048);
            }

            String cacheKey = func + ":" + pathStr;
            String traceCacheKey = "";

            if (fireAndForget) {
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                String topFrame = stack.length > 3 ? stack[3].getFileName() + ":" + stack[3].getLineNumber() : "unknown:0";
                traceCacheKey = "trace:" + func + ":" + topFrame;
            } else {
                if ("deny".equals(VERDICT_CACHE.get(cacheKey))) {
                    throw new SecurityException("Vandam RASP blocked execution of '" + func + "' (Cached)");
                }
                if ("allow".equals(VERDICT_CACHE.get(cacheKey))) return;
            }

            String payload = String.format("{\"type\":\"%s\",\"pid\":%d,\"function\":\"%s\",\"path\":\"%s\",\"payload_size_bytes\":%d,\"in_request\":0,\"http\":{},\"trace\":[],\"is_install_context\":%d}\n",
                type, pid, func, pathStr, payloadSizeBytes, IS_INSTALL_CONTEXT);
                
            if (fireAndForget) {
                if (!TELEMETRY_CACHE.containsKey(traceCacheKey)) {
                    StringBuilder traceBuilder = new StringBuilder("[");
                    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                    for (int i = 3; i < stack.length; i++) {
                        traceBuilder.append(String.format("{\"file\":\"%s\",\"line\":%d,\"function\":\"%s\",\"class\":\"%s\",\"args\":[]}",
                            stack[i].getFileName() != null ? stack[i].getFileName() : "",
                            stack[i].getLineNumber(),
                            stack[i].getMethodName(),
                            stack[i].getClassName()));
                        if (i < stack.length - 1) traceBuilder.append(",");
                    }
                    traceBuilder.append("]");
                    payload = String.format("{\"type\":\"%s\",\"pid\":%d,\"function\":\"%s\",\"path\":\"%s\",\"payload_size_bytes\":%d,\"in_request\":0,\"http\":{},\"trace\":%s,\"is_install_context\":%d}\n",
                        type, pid, func, pathStr, payloadSizeBytes, traceBuilder.toString(), IS_INSTALL_CONTEXT);
                        
                    if (TELEMETRY_CACHE.size() > 1000) TELEMETRY_CACHE.clear();
                    TELEMETRY_CACHE.put(traceCacheKey, Boolean.TRUE);
                }
                try {
                    sendPayload(payload, true);
                } catch (Exception e) {}
                return;
            }

            try {
                String response = sendAndReceivePayload(payload);
                if (response != null) {
                    String verdict = "allow";
                    String incidentId = null;
                    if (response.contains("\"verdict\":\"deny\"")) {
                        verdict = "deny";
                    }
                    
                    int incidentIdx = response.indexOf("\"incident_id\":\"");
                    if (incidentIdx != -1) {
                        int endIdx = response.indexOf("\"", incidentIdx + 15);
                        if (endIdx != -1) {
                            incidentId = response.substring(incidentIdx + 15, endIdx);
                        }
                    }

                    if (VERDICT_CACHE.size() > 1000) VERDICT_CACHE.clear();
                    VERDICT_CACHE.put(cacheKey, verdict);

                    if ("deny".equals(verdict)) {
                        if (incidentId != null) {
                            try {
                                StackTraceElement[] traceStack = Thread.currentThread().getStackTrace();
                                StringBuilder tb = new StringBuilder("[");
                                for (int i = 3; i < traceStack.length; i++) {
                                    tb.append(String.format("{\"file\":\"%s\",\"line\":%d,\"function\":\"%s\",\"class\":\"%s\",\"args\":[]}",
                                        traceStack[i].getFileName() != null ? traceStack[i].getFileName() : "",
                                        traceStack[i].getLineNumber(),
                                        traceStack[i].getMethodName(),
                                        traceStack[i].getClassName()));
                                    if (i < traceStack.length - 1) tb.append(",");
                                }
                                tb.append("]");
                                String tracePayload = String.format("{\"incident_id\":\"%s\",\"trace\":%s}\n", incidentId, tb.toString());
                                sendPayload(tracePayload, true);
                            } catch (Exception e) {}
                        }
                        throw new SecurityException("Vandam RASP blocked execution of '" + func + "'");
                    }
                } else {
                    if (VERDICT_CACHE.size() > 1000) VERDICT_CACHE.clear();
                    VERDICT_CACHE.put(cacheKey, "allow");
                }
            } catch (SecurityException e) {
                throw e;
            } catch (Exception e) {
                VERDICT_CACHE.put(cacheKey, "allow");
                if (VERDICT_CACHE.size() > 1000) VERDICT_CACHE.clear();
            }
        } finally {
            inVandam.set(false);
        }
    }

    // --- ADVICE INTERCEPTORS ---
    public static class ProcessBuilderAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object processBuilder) {
            try {
                java.lang.ProcessBuilder pb = (java.lang.ProcessBuilder) processBuilder;
                String cmd = String.join(" ", pb.command());
                com.vandam.rasp.VandamAgent.askVandam("exec_call", "ProcessBuilder.start", cmd, true);
            } catch (Exception e) {}
        }
    }

    public static class FileReadAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object arg) {
            try {
                if (arg != null) {
                    com.vandam.rasp.VandamAgent.askVandam("file_read", "FileInputStream", arg.toString(), true);
                }
            } catch (Exception e) {}
        }
    }

    public static class JniAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(1) Object arg) {
            try {
                if (arg != null) {
                    com.vandam.rasp.VandamAgent.askVandam("dynamic_load", "Runtime.loadLibrary", arg.toString(), true);
                }
            } catch (Exception e) {}
        }
    }

    public static class JndiAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object arg) {
            try {
                if (arg != null) {
                    com.vandam.rasp.VandamAgent.askVandam("jndi_lookup", "Context.lookup", arg.toString(), true);
                }
            } catch (Exception e) {}
        }
    }

    public static class DeserializationAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object arg) {
            try {
                if (arg != null) {
                    com.vandam.rasp.VandamAgent.askVandam("deserialize", "ObjectInputStream.resolveClass", arg.toString(), true);
                }
            } catch (Exception e) {}
        }
    }
}
