package adp.io.sockets.server;

import adp.io.sockets.common.IDisconnectListener;
import adp.io.sockets.common.IMessageListener;
import adp.io.sockets.common.IObjectListener;

public abstract class AServerProtocol implements IMessageListener, IObjectListener, IDisconnectListener {

    final public String clientName;
    final public SecureServer ss;

    public AServerProtocol(SecureServer ss) {
        this.clientName = "<not set>";
        this.ss = ss;
    }

    public AServerProtocol(SecureServer ss, String clientName) {
        this.clientName = clientName;
        this.ss = ss;
    }

    @Override
    public void messageReceived(String msg) {

    }

    @Override
    public void objectReceived(Object obj) {

    }

    @Override
    public void connectionTerminated() {

    }

}
