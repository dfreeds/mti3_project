/*
 * Developed by David Fritz 2016.
 */

package com.example.hackeris.project;

/**
 * Created by dfritz on 08/07/16.
 */
public class TCPIdentifier {
    private int sourcePort;
    private String destinationAddress;
    private int destinationPort;
    private int hashCode;

    public TCPIdentifier (int sourcePort, String destinationAddress, int destinationPort)
    {
        this.sourcePort = sourcePort;
        this.destinationAddress = destinationAddress;
        this.destinationPort = destinationPort;

        hashCode = sourcePort * destinationAddress.hashCode() * destinationPort;
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public boolean equals(Object o) {
        if (o != null)
        {
            if (TCPIdentifier.class.isInstance(o))
            {
                TCPIdentifier tcpIdentifier = (TCPIdentifier)o;
                if (tcpIdentifier.getSourcePort() == this.getSourcePort() && tcpIdentifier.getDestinationPort() == this.getDestinationPort() && tcpIdentifier.getDestinationAddress().equals(this.getDestinationAddress()))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public void setDestinationAddress(String destinationAddress) {
        this.destinationAddress = destinationAddress;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }
}
