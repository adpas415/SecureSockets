package adp.io.sockets.client;

import adp.io.security.crypters.aes_crypter;
import adp.io.security.crypters.rsa_crypter;
import adp.io.sockets.common.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SecureClient implements ISendMessages, ISendObjects {

    public boolean
        debugMode   =  true,
        killSwitch  =  false,
        objectMode  =  false;

    Socket socket = null;

    DataOutputStream raw_output;
    DataInputStream raw_input;

    rsa_crypter rsa_modem;
    aes_crypter aes_modem;

    Queue<IMessageListener> msgListeners = new ConcurrentLinkedQueue<>();
    Queue<IObjectListener> objListeners = new ConcurrentLinkedQueue<>();

    int incomingObjectSize;

    Object syncLock = new Object();

    public SecureClient(String ipAddress, int port) {

        try {

            socket = new Socket(ipAddress, port);

            System.out.println("C > Connected to " + ipAddress + " / " + port);

            raw_output  =  new DataOutputStream(socket.getOutputStream());
            raw_input   =  new DataInputStream(socket.getInputStream());

            //PAUSE FOR SERVER'S BENEFIT.
            Thread.sleep(250);

            System.out.println("C > Securing ... ");

            //FIRST HANDSHAKE
            if(!handshake_txt())
                return;

            //SECOND HANDSHAKE
            if(!handshake_rsa())
                return;

            //THIRD HANDSHAKE
            if(!handshake_aes())
                return;

            //STRIKE A POSE!
            Thread.sleep(1000);

            //READY TO ROCK
            System.out.println("C > Ready.");

            new Thread("Client Thread") {
                @Override
                public void run() {

                    try {

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

                        System.out.println("Client Loop Broken. Thread Closing.");

                        //cleanup
                        raw_output.close();
                        raw_input.close();
                        socket.close();

                    } catch(Exception ex) {
                        ex.printStackTrace(System.out);
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

    //-

    @Override
    public void sendObject(Object toSend) {
        try {
            synchronized (syncLock) {

                byte[] encryptedBytes = aes_modem.encryptBytes(Serializer.serialize(toSend));
                //sendMessage function copied here for thread-safety reasons
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

    public String getServerIP() {
        return socket.getRemoteSocketAddress().toString();
    }

    //-

    public void killSwitch() {
        try {

            //kill the loop
            killSwitch = true;

            //If we killed the connection, be polite and inform our partner that we're doing it.
            sendMessage("Connection Terminated");

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    public void disconnect() {
        try {
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //-

    boolean handshake_txt() throws Exception {

        raw_output.writeUTF(HandShakes.txt_greet);
        raw_output.flush();

        String response = raw_input.readUTF();

        if(HandShakes.txt_reply.length() == response.length() && !response.equals(HandShakes.txt_reply)) {
            System.out.println("C > Cleartext Handshake Failed via Unrecognized Response! >> " + response);
            return false;
        }

        if(debugMode) {
            System.out.println("C > Message From Server >> " + response);
            System.out.println("C > First Handshake Successful! ");
        }

        return true;

    }

    boolean handshake_rsa() throws Exception {

        if(debugMode)
            System.out.println("C > Sharing RSA Public Key... ");

        rsa_modem = new rsa_crypter();

        //send our key
        raw_output.writeUTF(rsa_modem.key_public.toString());
        raw_output.flush();

        //receive partner's key
        rsa_modem.setPartnersPublicKey(raw_input.readUTF());

        if(debugMode)
            System.out.println("C > ...Switching to RSA Encryption. ");

        raw_output.writeUTF(rsa_modem.encryptString(HandShakes.rsa_greet));
        raw_output.flush();

        String second_challenge_response = rsa_modem.decryptString(raw_input.readUTF());

        if(!second_challenge_response.equals(HandShakes.rsa_reply)) {
            System.out.println("C > RSA Handshake Failed via Unrecognized Response! >> " + second_challenge_response);
            return false;
        }

        if(debugMode) {
            System.out.println("C > RSA Encrypted Message From Server >> " + second_challenge_response);
            System.out.println("C > Second Handshake Successful! ");
        }

        return true;

    }

    boolean handshake_aes() throws Exception {

        if(debugMode)
            System.out.println("C > Establishing Shared AES Key... ");

        aes_modem = new aes_crypter();

        raw_output.writeUTF(rsa_modem.encryptString(aes_modem.getPublicKey()));
        raw_output.flush();

        if(debugMode)
            System.out.println("C > ...Switching to AES Encryption. ");

        String third_challenge = aes_modem.decryptString(raw_input.readUTF());

        if(!third_challenge.equals(HandShakes.aes_greet)) {
            System.out.println("C > AES Handshake Failed via Unrecognized Response! >> " + third_challenge);
            return false;
        }

        if(debugMode)
            System.out.println("C > AES Encrypted Message From Server >> " + third_challenge);

        raw_output.writeUTF(aes_modem.encryptString(HandShakes.aes_reply));
        raw_output.flush();

        return true;

    }

}
