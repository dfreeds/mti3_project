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
    private long ackNumber = -1;
    private int id = -1;
    private int lastDataSize = 0;

    private TCPReceiver tcpReceiver = null;

    public TCPConnection (Socket socket)
    {
        this.socket = socket;
        sequenceNumber = (long)(Math.random() * 30000);
        id = (int)(Math.random() * 30000);
    }

    public long getNextSequenceNumber () {
        sequenceNumber = sequenceNumber + lastDataSize;
        lastDataSize = 0;
        return sequenceNumber;
    }

    public int getNextIdNumber () {
        return ++id;
    }

    public void saveNextAckNumber (long lastSequenceNumber, long lastDataSize){
        ackNumber = lastSequenceNumber + lastDataSize;
    }

    public Socket getSocket() {
        return socket;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public long getAckNumber() {
        return ackNumber;
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public TCPReceiver getTcpReceiver() {
        return tcpReceiver;
    }

    public void setTcpReceiver(TCPReceiver tcpReceiver) {
        this.tcpReceiver = tcpReceiver;
    }

    public void setLastDataSize(int lastDataSize) {
        this.lastDataSize = lastDataSize;
    }
}
