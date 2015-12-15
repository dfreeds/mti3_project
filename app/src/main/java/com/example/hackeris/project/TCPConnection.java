/*
 * Developed by David Fritz 2015.
 */

package com.example.hackeris.project;

import java.net.Socket;

/**
 * Created by dfritz on 15/12/15.
 */
public class TCPConnection {
    private Socket socket = null;
    private long sequenceNumber = -1;

    public TCPConnection (Socket socket)
    {
        this.socket = socket;
        sequenceNumber = (long)(Math.random() * 100000);
    }

    public long getNextSequenceNumber () {
        return ++sequenceNumber;
    }

    public Socket getSocket() {
        return socket;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
}
