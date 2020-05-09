package adp.io.sockets.tests;


import adp.io.sockets.client.SecureClient;
import adp.io.sockets.server.SecureServer;

public class Test_Handshake {

    public static void main(String[] args) {

        final int port = 8888;

        System.out.println("Starting Server...");
        new Thread("Server Thread") {
            @Override
            public void run() {

                try {

                    new SecureServer().start(port);

                    Thread.sleep(9999999);

                } catch (Exception e) {
                    e.printStackTrace();
                }

                System.out.println("Server Shutting Down...");
                System.exit(0);

            }
        }.start();

        System.out.println("Starting Client...");
        new Thread("Client Thread") {
            @Override
            public void run() {

                new SecureClient("127.0.0.1", port);

                try {

                    Thread.sleep(9999999);

                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                System.out.println("Client Shutting Down...");

            }
        }.start();

    }

}
