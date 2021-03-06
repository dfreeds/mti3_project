/*
 * Developed by David Fritz 2015.
 */

package at.fhtw.mti.project;

import android.content.Intent;
import android.net.VpnService;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import net.sourceforge.jpcap.net.IPPacket;
import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.net.UDPPacket;
import net.sourceforge.jpcap.util.HexHelper;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.HashMap;

import at.fhtw.mti.project.project.R;
import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;


public class TracingVPNService extends VpnService implements Handler.Callback, Runnable {

    private static final String TAG = "TracingVPNService";

    private Handler mHandler;
    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    private FileInputStream mInputStream;
    private FileOutputStream mOutputStream;

    private HashMap<IPIdentifier, TCPConnection> tcpConnections = new HashMap<> ();

    private static final int PACK_SIZE = 32767 * 2;

    private String vpnIP = "10.0.0.42";
    private MainActivity mainActivity;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        if (mThread != null) {
            mThread.interrupt();
        }

        if (mInterface != null) {
            try {
                mInterface.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        mThread = new Thread(this);
        mThread.start();

        return START_STICKY;
    }

    @Override
    public void onDestroy() {

        stopVPNService();
    }

    public void stopVPNService() {

        if (mThread != null) {
            mThread.interrupt();
        }
        try {
            if (mInterface != null) {
                mInterface.close();
            }
            if (mInputStream != null) {
                mInputStream.close();
            }
            if (mOutputStream != null) {
                mOutputStream.close();
            }
        } catch (IOException ie) {
            ie.printStackTrace();
        }
        mThread = null;
        mInterface = null;
        mInputStream = null;
        mOutputStream = null;
    }

    private void configure() throws IOException {

        VpnService.Builder builder = new VpnService.Builder();
        //TODO compare to local address - has to be different!
        builder.addAddress(vpnIP, 32).addRoute("0.0.0.0", 0).addDnsServer("8.8.8.8").setSession("TracingVPN").setMtu(1500);

        mInterface = builder.establish();

        mInputStream = new FileInputStream(mInterface.getFileDescriptor());
        mOutputStream = new FileOutputStream(mInterface.getFileDescriptor());
    }


    @SuppressWarnings("InfiniteLoopStatement")
    private void dataTransferLoop() throws IOException {

        // Allocate the buffer for a single packet.
        ByteBuffer packet = ByteBuffer.allocate(PACK_SIZE);
        //HashMap<Integer, TCPConnection> tcpConnections = new HashMap<> ();
        TCPConnection tcpConnection;
        byte[] bytes;

        while (true) {

            packet = ByteBuffer.allocate(PACK_SIZE);

            int length = mInputStream.read(packet.array());
            if (length > 0) {

                bytes = Arrays.copyOf(packet.array (), length);


                Log.d(TAG, "--- new incoming packet ---");
                //Log.d(TAG, "->| " + HexHelper.toString(bytes));
                System.out.println ("00000000   " + HexHelper.toString(bytes));
                IPPacket ipPacket = new IPPacket(0, bytes);
                Log.i(TAG, "->| " + ipPacket.toColoredVerboseString(false));

                if (ipPacket.getProtocol() == 6)
                {
                    //TCP
                    TCPPacket tcpPacket = new TCPPacket(0, bytes);
                    Log.i(TAG, "->| " + tcpPacket.toColoredVerboseString(false));
                    IPIdentifier ipIdentifier = new IPIdentifier(tcpPacket.getSourcePort(), tcpPacket.getDestinationAddress(), tcpPacket.getDestinationPort());

                    tcpConnection = tcpConnections.get(ipIdentifier);

                    if (tcpConnection != null || tcpPacket.isSyn())
                    {
                        if (tcpConnection != null) {
                            tcpConnection.saveNextAckNumber(tcpPacket.getSequenceNumber(), tcpPacket.isFin() ? tcpPacket.getData().length == 0 ? 1 : tcpPacket.getData().length : tcpPacket.getData().length);
                        }

                        if (tcpPacket.isSyn())
                        {
                            if (tcpConnection == null) {
                                tcpConnection = new TCPConnection(createSocketConnection(tcpPacket));
                                tcpConnections.put(ipIdentifier, tcpConnection);
                                tcpConnection.saveNextAckNumber(tcpPacket.getSequenceNumber(), 1);
                            }

                            Log.d (TAG, "SYN ACK Handshake");
                            //opening handshake towards VPN
                            try {
                                sendTCPPacketToVPN(buildHandshakePacket(tcpPacket, true, tcpConnection));
                            } catch (NetUtilsException e) {
                                e.printStackTrace();
                            }

                            //outgoing data
                            if (tcpPacket.getData().length > 0) {
                                sendTCPData(tcpConnection, tcpPacket, false);
                            }
                        }
                        else if (tcpPacket.isFin())
                        {
                            Log.d (TAG, "FIN ACK Handshake");
                            //closing handshake towards VPN
                            try {
                                sendTCPPacketToVPN(buildHandshakePacket(tcpPacket, false, tcpConnection));
                            } catch (NetUtilsException e) {
                                e.printStackTrace();
                            }

                            tcpConnection.setToClose(true);
                        }
                        else if (tcpPacket.isRst())
                        {
                            //just close connection outwards
                            closeTCPConnection (tcpConnection, ipIdentifier);
                        }
                        else
                        {
                            if (tcpPacket.getData().length > 0) {
                                //send ACK
                                try {
                                    sendTCPPacketToVPN(buildAckPacket(tcpPacket, tcpConnection));
                                } catch (NetUtilsException e) {
                                    e.printStackTrace();
                                }

                                //outgoing packet
                                sendTCPData(tcpConnection, tcpPacket, true);
                            }
                            else if (tcpConnection.isToClose ())
                            {
                                //close connection outwards
                                closeTCPConnection (tcpConnection, ipIdentifier);
                            }

                        }
                    }
                    else
                    {
                        Log.d (TAG, "// none of us, sending RST");
                        try {
                            sendTCPPacketToVPN(buildRstPacket(tcpPacket));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                else if (ipPacket.getProtocol() == 17)
                {
                    //UDP
                    UDPPacket udpPacket = new UDPPacket(0, packet.array());
                    Log.i(TAG, "->| " + udpPacket.toColoredString(false));
                    boolean doProcess = true;

                    if (udpPacket.getDestinationPort() == 53) {
                        if (!isCleanDomainName(NetworkUtils.getDomainName(packet.array()))) {
                            doProcess = false;
                        }
                    }

                    if (doProcess) {
                        new Thread (new UDPReceiver(TracingVPNService.this, udpPacket)).start ();
                    }
                }
                else if (ipPacket.getProtocol() == 1)
                {
                    //ICMP
                    InetAddress host = InetAddress.getByName(ipPacket.getDestinationAddress());
                    //Log.d(TAG, "sent ping, answer is: " + host.isReachable(1000));
                }
                else
                {
                    Log.e (TAG, "unhandled protocol! " + ipPacket.toColoredVerboseString(false));
                }

                packet.clear();
            }

            try {
                Thread.sleep(0, 1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void closeTCPConnection(TCPConnection tcpConnection, IPIdentifier ipIdentifier) throws IOException {
        if (tcpConnection.getTcpReceiver() != null) {
            tcpConnection.getTcpReceiver().stop();
        }
        if (tcpConnection.getSocket() != null) {
            tcpConnection.getSocket().close();
        }
        tcpConnections.remove(ipIdentifier);
    }

    private boolean isCleanDomainName(String domainName) {
        boolean retVal = true;

        mainActivity.addDomainNameAccessListEntry(domainName);

        for (DomainNameAccessListModel entry : mainActivity.getDomainNameAccessList()) {
            if (entry.isBlacklisted() && domainName.contains(entry.getDomainName())) {
                Log.e (TAG, "Blocking DNS request with domain name: " + domainName);
                retVal = false;
            }
        }

        return retVal;
    }

    private TCPPacketIpv4 buildRstPacket(TCPPacket tcpPacket) throws NetUtilsException {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setRSTFlag(true);
        tcpPacketBuilder.setSeqNum(0);
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setWindowSize(0);

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(0);
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4) tcpPacketBuilder.createTCPPacket();
    }

    private TCPPacketIpv4 buildAckPacket(TCPPacket tcpPacket, TCPConnection tcpConnection) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(true);
        tcpPacketBuilder.setSeqNum(tcpConnection.getNextSequenceNumber());
        tcpPacketBuilder.setAckNum(tcpConnection.getAckNumber());
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setWindowSize(tcpPacket.getWindowSize());

        tcpConnection.setLastDataSize(0);

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(tcpConnection.getNextIdNumber());
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4) tcpPacketBuilder.createTCPPacket();
    }

    private TCPPacketIpv4 buildHandshakePacket(TCPPacket tcpPacket, boolean isSyn, TCPConnection tcpConnection) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(true);
        if (isSyn)
        {
            tcpPacketBuilder.setSYNFlag(true);
        }
        else
        {
            tcpPacketBuilder.setFINFlag(true);
        }
        tcpPacketBuilder.setSeqNum(tcpConnection.getNextSequenceNumber());
        tcpPacketBuilder.setAckNum(tcpConnection.getAckNumber());
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setWindowSize(tcpPacket.getWindowSize());

        tcpConnection.setLastDataSize(isSyn ? 1 : 0);

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(tcpConnection.getNextIdNumber());
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4) tcpPacketBuilder.createTCPPacket();
    }

    private void sendTCPData(TCPConnection tcpConnection, TCPPacket tcpPacket, boolean read) throws IOException
    {
        if (tcpConnection.getSocket().isConnected()) {
            DataOutputStream outToServer = new DataOutputStream(tcpConnection.getSocket().getOutputStream());

            Log.d(TAG, "|-> TCP Packet (addr: " + tcpPacket.getDestinationAddress() + " port: " + tcpPacket.getDestinationPort() + " saddr: " + tcpConnection.getSocket().getLocalAddress() + " sport: " + tcpConnection.getSocket().getLocalPort() + ")");

            Log.d(TAG, "..writing tcppacket.data: ");
            Log.d(TAG, "[" + new String (tcpPacket.getData()) + "]");
            Log.d(TAG, "..data end");

            try {
                outToServer.write(tcpPacket.getData());

                if (read) {
                    if (tcpConnection.getTcpReceiver() == null) {
                        TCPReceiver tcpReceiver = new TCPReceiver();
                        tcpReceiver.setInFromServer(tcpConnection.getSocket().getInputStream());
                        tcpReceiver.setTcpPacket(tcpPacket);
                        tcpReceiver.setTcpConnection(tcpConnection);
                        tcpReceiver.setService(this);
                        tcpConnection.setTcpReceiver(tcpReceiver);
                        new Thread(tcpReceiver).start();
                    } else {
                        tcpConnection.getTcpReceiver().setTcpPacket(tcpPacket);
                    }
                }
            } catch (SocketException e) {
                //FIN
                try {
                    sendTCPPacketToVPN(buildHandshakePacket(tcpPacket, false, tcpConnection));
                } catch (NetUtilsException e1) {
                    closeTCPConnection(tcpConnection, new IPIdentifier(tcpPacket.getSourcePort(), tcpPacket.getDestinationAddress(), tcpPacket.getDestinationPort()));
                }
            }
        }
        else {
            //FIN
            try {
                sendTCPPacketToVPN(buildHandshakePacket(tcpPacket, false, tcpConnection));
            } catch (NetUtilsException e) {
                closeTCPConnection(tcpConnection, new IPIdentifier(tcpPacket.getSourcePort(), tcpPacket.getDestinationAddress(), tcpPacket.getDestinationPort()));
            }
        }
    }

    public void sendTCPPacketToVPN(TCPPacketIpv4 tcpPacketToSend) throws IOException, NetUtilsException {

        IPPacket ipPacket = new IPPacket(14, tcpPacketToSend.getRawBytes());
        Log.d(TAG, "<-| " + ipPacket.toColoredVerboseString(false));
        Log.d(TAG, "<-| " + new TCPPacket(14, tcpPacketToSend.getRawBytes()).toColoredVerboseString(false));
        //Log.d(TAG, "<-| TCP.data: " + HexHelper.toString(new UDPPacket(14, tcpPacketToSend.getRawBytes()).getData()));
        //Log.d(TAG, "<-| ip packet: " + HexHelper.toString(ipPacket.getEthernetData()));

        //Log.d(TAG, "<-| " + HexHelper.toString (Arrays.copyOfRange(tcpPacketToSend.getRawBytes(), 14, tcpPacketToSend.getRawBytes().length)));
        System.out.println("00000000   " + HexHelper.toString(Arrays.copyOfRange(tcpPacketToSend.getRawBytes(), 14, tcpPacketToSend.getRawBytes().length)));
        //System.out.println("-> 00000000   " + HexHelper.toString(ipPacket.getEthernetData()));

        Log.d(TAG, "// writing tcp packet to vpn");
        mOutputStream.write(Arrays.copyOfRange(tcpPacketToSend.getRawBytes(), 14, tcpPacketToSend.getRawBytes().length));
    }

    public void sendUDPPacketToVPN(UDPPacketIpv4 udpPacketToSend) throws IOException, NetUtilsException {
        //ipPacket = new IPPacket(14, udpPacketToSend.getRawBytes());
        //Log.d(TAG, "<-| UDP.data: " + HexHelper.toString(new UDPPacket(14, udpPacketToSend.getRawBytes()).getData()));
        //Log.d(TAG, "<-| ip packet: " + HexHelper.toString(ipPacket.getEthernetData()));
        System.out.println("00000000   " + HexHelper.toString(Arrays.copyOfRange(udpPacketToSend.getRawBytes(), 14, udpPacketToSend.getRawBytes().length)));

        //Log.d(TAG, "// writing received udp packet back to vpn");
        mOutputStream.write(Arrays.copyOfRange(udpPacketToSend.getRawBytes(), 14, udpPacketToSend.getRawBytes().length));
    }

    private Socket createSocketConnection(TCPPacket tcpPacket) throws IOException {
        Socket socket = SocketChannel.open().socket();
        protect(socket);
        InetSocketAddress address = new InetSocketAddress(tcpPacket.getDestinationAddress(),tcpPacket.getDestinationPort());
        socket.connect(address);
        return socket;
    }

    private void debugIncomingPacket(DatagramPacket datagramPacket)
    {
        Log.d (TAG, "|<- --- incoming Datagram Packet ---");
        Log.d(TAG, "|<- length: " + datagramPacket.getLength());
        Log.d(TAG, "|<- address: " + datagramPacket.getAddress());
        Log.d(TAG, "|<- data in hex: " + HexHelper.toString(datagramPacket.getData()));
        Log.d(TAG, "|<- data length: " + datagramPacket.getData().length);
        Log.d(TAG, "|<- port: " + datagramPacket.getPort());
        Log.d(TAG, "|<- socketaddress: " + datagramPacket.getSocketAddress().toString());
        Log.d(TAG, "|<- --- incoming Datagram Packet ---");
    }

    @Override
    public void run()
    {
        mHandler.sendEmptyMessage(R.string.connecting);

        try {
            configure();

            mHandler.sendEmptyMessage(R.string.connected);

            dataTransferLoop();

        } catch (IOException ie) {
            ie.printStackTrace();
            Log.e(TAG, ie.toString());
        } finally {
            try {
                mInterface.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            mHandler.sendEmptyMessage(R.string.disconnected);
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return false;
    }

    @Override
    public IBinder onBind(Intent intent) {

        return new VPNServiceBinder();
    }

    public void setMainActivity(MainActivity mainActivity) {
        this.mainActivity = mainActivity;
    }

    public void removeTCPConnection(IPIdentifier ipIdentifier) {
        //Log.d (TAG, "removeTCPConnection : " + ipIdentifier);
        /*for (IPIdentifier ident : tcpConnections.keySet())
        {
            Log.d (TAG, "removeTCPConnection - " + ident);
        }*/

        tcpConnections.remove(ipIdentifier);
    }

    public class VPNServiceBinder extends Binder {

        public TracingVPNService getService() {

            return TracingVPNService.this;
        }
    }
}