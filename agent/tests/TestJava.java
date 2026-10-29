import java.io.FileInputStream;

public class TestJava {
    public static void main(String[] args) throws Exception {
        System.out.println("Loading Java RASP Agent (via -javaagent)...");
        Thread.sleep(1000); // wait for daemon
        
        System.out.println("\n--- Triggering RASP Events ---");
        System.out.println("1. Testing exec_call (Runtime.exec)...");
        try {
            Runtime.getRuntime().exec("echo 'Hello from Java'");
        } catch (Exception e) { e.printStackTrace(); }

        System.out.println("2. Testing file_read (FileInputStream)...");
        try {
            FileInputStream fis = new FileInputStream("/etc/passwd");
            fis.close();
        } catch (Exception e) { e.printStackTrace(); }

        System.out.println("3. Testing JNDI (InitialContext)...");
        try {
            new javax.naming.InitialContext().lookup("ldap://localhost/test");
        } catch (Exception e) { e.printStackTrace(); }
        
        System.out.println("Java test complete.");
        Thread.sleep(1000);
    }
}
