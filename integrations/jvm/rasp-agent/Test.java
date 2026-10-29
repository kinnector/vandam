import java.io.*;
import javax.naming.InitialContext;
import java.util.Properties;

public class Test {
    public static void main(String[] args) {
        System.out.println("----------------------------------------");
        System.out.println("Running test on Java version: " + System.getProperty("java.version"));
        System.out.println("----------------------------------------");
        
        // 1. File Read
        try {
            System.out.println("[Test] Triggering file_read...");
            FileInputStream fis = new FileInputStream("/etc/passwd");
            fis.close();
        } catch (Exception e) {}

        // 2. Process Execution
        try {
            System.out.println("[Test] Triggering exec_call...");
            ProcessBuilder pb = new ProcessBuilder("echo", "hello");
            pb.start();
        } catch (Exception e) {}

        // 3. JNI Dynamic Load
        try {
            System.out.println("[Test] Triggering dynamic_load...");
            Runtime.getRuntime().loadLibrary("non_existent_vandam_test_lib");
        } catch (Error e) {
            // expected UnsatisfiedLinkError
        }

        // 4. JNDI Lookup
        try {
            System.out.println("[Test] Triggering jndi_lookup...");
            Properties props = new Properties();
            props.put("java.naming.factory.initial", "com.sun.jndi.rmi.registry.RegistryContextFactory");
            props.put("java.naming.provider.url", "rmi://localhost:1099");
            InitialContext ctx = new InitialContext(props);
            ctx.lookup("ldap://test.vandam.local/Exploit");
        } catch (Exception e) {}

        // 5. Deserialization
        try {
            System.out.println("[Test] Triggering deserialize...");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(new java.util.ArrayList<String>());
            oos.close();

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream ois = new ObjectInputStream(bais);
            ois.readObject();
            ois.close();
        } catch (Exception e) {}

        System.out.println("[Test] Finished test successfully.");
    }
}
