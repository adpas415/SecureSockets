package adp.io.sockets.tests;

import adp.io.sockets.server.SecureServer;

public class Test_Server {
    public static void main(String[] args) {

        int portNum = 7777;

        System.out.println("Starting Server on port " + portNum);

        SecureServer testSRVR = new SecureServer();

        try {

            testSRVR.addMessageListener(msg -> System.out.println("Message From Client: " + msg));

            testSRVR.start(portNum);

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }
    }
}
