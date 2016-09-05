/*
 * Developed by David Fritz 2016.
 */

package at.fhtw.mti.project;

/**
 * Created by dfritz on 08/07/16.
 */
public class IPIdentifier {
    private int sourcePort;
    private String destinationAddress;
    private int destinationPort;
    private int hashCode;

    public IPIdentifier(int sourcePort, String destinationAddress, int destinationPort)
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
            if (IPIdentifier.class.isInstance(o))
            {
                IPIdentifier ipIdentifier = (IPIdentifier)o;
                if (ipIdentifier.getSourcePort() == this.getSourcePort() && ipIdentifier.getDestinationPort() == this.getDestinationPort() && ipIdentifier.getDestinationAddress().equals(this.getDestinationAddress()))
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

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder ();

        builder.append("Source Port: [" + sourcePort + "], ");
        builder.append("Destination Address: [" + destinationAddress + "], ");
        builder.append("Destination Port: [" + destinationPort + "]");

        return builder.toString ();
    }
}
