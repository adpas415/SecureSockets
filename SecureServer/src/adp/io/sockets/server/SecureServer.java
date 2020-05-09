package adp.io.sockets.server;

import adp.io.security.crypters.aes_crypter;
import adp.io.security.crypters.rsa_crypter;
import adp.io.sockets.common.*;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SecureServer implements ISendMessages, ISendObjects, Closeable {

    public boolean
        debugMode   =  true,
        killSwitch  =  false,
        objectMode  =  false;

    DataOutputStream raw_output;
    DataInputStream raw_input;

    rsa_crypter rsa_modem;
    aes_crypter aes_modem;

    Queue<IMessageListener>     msgListeners     =  new ConcurrentLinkedQueue<>();
    Queue<IObjectListener>      objListeners     =  new ConcurrentLinkedQueue<>();
    Queue<IDisconnectListener>  disconListeners  =  new ConcurrentLinkedQueue<>();

    int incomingObjectSize;
    Socket socket;
    String remoteIP;
    Object syncLock = new Object();

    public void start(int port) throws Exception {

        this.socket = new ServerSocket(port).accept();

        try {

            new Thread("Server Thread") {

                @Override
                public void run() {

                    try {

                        remoteIP = socket.getRemoteSocketAddress().toString();

                        System.out.println("S > Connection Received from " + remoteIP);

                        raw_output  =  new DataOutputStream(socket.getOutputStream());
                        raw_input   =  new DataInputStream(socket.getInputStream());

                        System.out.println("S > Securing...");

                        //FIRST HANDSHAKE
                        if(!handshake_txt())
                            return;

                        //SECOND HANDSHAKE
                        if(!handshake_rsa())
                            return;

                        //THIRD HANDSHAKE
                        if(!handshake_aes())
                            return;

                        System.out.println("S > Ready.");

                        //LISTENING LOOP
                        while(!killSwitch) {

                            if(objectMode) {

                                byte[] decryptedBytes = aes_modem.decryptBytes(raw_input.readNBytes(incomingObjectSize));

                                objListeners.parallelStream().forEach(  objLst  ->  {
                                    try {
                                        objLst.objectReceived(Serializer.deserialize(decryptedBytes));
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                });

                                objectMode = false;
                                continue;

                            } else {

                                String latestMessage = aes_modem.decryptString(raw_input.readUTF());

                                if (latestMessage.equals("Connection Terminated")) {
                                    //respond so that both loops can break
                                    sendMessage("Connection Terminated");
                                    break;
                                }

                                if(latestMessage.contains(Protocols.SEND_OBJECT)) {
                                    //prepare to receive an object
                                    objectMode = true;
                                    incomingObjectSize = Integer.valueOf(latestMessage.substring(latestMessage.indexOf(":")+1));
                                    continue;
                                }

                                msgListeners.parallelStream().forEach(msgLst -> msgLst.messageReceived(latestMessage));

                            }

                        }

                        socket.close();

                        System.out.println("Server Loop Broken Gracefully. Thread Closing.");

                    } catch (Exception ex) {

                        String msg = ex.getMessage();

                        if(msg != null && msg.contains("Connection reset"))
                            System.out.println(">>" + remoteIP + ":  Connection Severed!"); //todo: handle this
                        else
                            ex.printStackTrace(System.out);

                    } finally {

                        disconListeners.forEach(IDisconnectListener::connectionTerminated);

                    }

                }

            }.start();

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    //-

    public void addMessageListener(IMessageListener toAdd) {
        msgListeners.add(toAdd);
    }

    public void removeMessageListener(IMessageListener toRemove) {
        msgListeners.remove(toRemove);
    }

    public void addObjectListener(IObjectListener toAdd) {
        objListeners.add(toAdd);
    }

    public void addDisconnectListener(IDisconnectListener toAdd) {
        disconListeners.add(toAdd);
    }

    //-

    public void killSocket() {
        try {

            //kill the loop
            killSwitch = true;

            //If we killed the connection, be polite and inform our partner that we're doing it.
            sendMessage("Connection Terminated");

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    public String getClientIP() {
        return remoteIP;
    }

    //-

    @Override
    public void sendObject(Object toSend) {
        try {
            synchronized (syncLock) {

                byte[] encryptedBytes = aes_modem.encryptBytes(Serializer.serialize(toSend));
                //
                raw_output.writeUTF(aes_modem.encryptString(Protocols.SEND_OBJECT + ":" + encryptedBytes.length));
                raw_output.flush();
                //
                raw_output.write(encryptedBytes);
                raw_output.flush();

            }
        } catch (Exception e) {
            e.printStackTrace(); //todo: catch comm errors
        }
    }

    @Override
    public void sendMessage(String s) {
        try {
            synchronized (syncLock) {

                raw_output.writeUTF(aes_modem.encryptString(s));
                raw_output.flush();

            }
        } catch (Exception e) {
            e.printStackTrace(); //todo: catch comm errors
        }
    }

    //-

    boolean handshake_txt() throws Exception {

        String greetingFromClient = raw_input.readUTF();

        if(debugMode)
            System.out.println("S > Message From Client >> " + greetingFromClient);

        if(greetingFromClient.equals(HandShakes.txt_greet)) {

            raw_output.writeUTF(HandShakes.txt_reply);
            raw_output.flush();

        } else {

            if(debugMode)
                System.out.println("S > Unrecognized First Challenge! Sending Response...");

            raw_output.writeUTF("Fuck off!");
            raw_output.flush();

            return false;

        }

        return true;

    }

    boolean handshake_rsa() throws Exception {

        String publicKey = raw_input.readUTF();

        rsa_modem = new rsa_crypter();

        rsa_modem.setPartnersPublicKey(publicKey);

        String publicKeyString = rsa_modem.getPublicKey();

        if(debugMode)
            System.out.println("S > Sharing RSA Public Key... ");

        raw_output.writeUTF(publicKeyString);
        raw_output.flush();

        if(debugMode)
            System.out.println("S > ...Switching to RSA Encryption. ");

        String second_challenge = rsa_modem.decryptString(raw_input.readUTF());

        if(second_challenge.equals(HandShakes.rsa_greet)) {

            if(debugMode)
                System.out.println("S > RSA Encrypted Message From Client >> " + second_challenge);

            raw_output.writeUTF(rsa_modem.encryptString(HandShakes.rsa_reply));
            raw_output.flush();

        } else {

            if(debugMode)
                System.out.println("S > Unrecognized Second Challenge! Sending Response...");

            raw_output.writeUTF("Fuck off!");
            raw_output.flush();

            return false;

        }

        return true;

    }

    boolean handshake_aes() throws Exception {

        aes_modem = new aes_crypter(rsa_modem.decryptString(raw_input.readUTF()));

        if(debugMode)
            System.out.println("S > ...Switching to AES Encryption. ");

        raw_output.writeUTF(aes_modem.encryptString(HandShakes.aes_greet));
        raw_output.flush();

        String responseToGreeting = aes_modem.decryptString(raw_input.readUTF());

        if(!responseToGreeting.equals(HandShakes.aes_reply))
            return false;

        if(debugMode)
            System.out.println("S > AES Encrypted Message From Client >> " + responseToGreeting);

        return true;

    }

    @Override
    public void close() throws IOException {
        killSocket();
    }
}
