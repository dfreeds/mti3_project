/*
 * Developed by David Fritz 2015.
 */

package com.example.hackeris.project;

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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Arrays;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.build.UDPPacketBuilder;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;


public class DemoVPNService extends VpnService implements Handler.Callback, Runnable {

    private static final String TAG = "DemoVPNService";

    private Handler mHandler;

    private Thread mThread;

    private ParcelFileDescriptor mInterface;

    private FileInputStream mInputStream;

    private FileOutputStream mOutputStream;

    private static final int PACK_SIZE = 32767 * 2;

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
        builder.addAddress("10.0.0.42", 32).addRoute("0.0.0.0", 0).setSession("DemoVPN").addDnsServer("8.8.8.8").setMtu(1500);

        mInterface = builder.establish();

        mInputStream = new FileInputStream(mInterface.getFileDescriptor());
        mOutputStream = new FileOutputStream(mInterface.getFileDescriptor());
    }


    @SuppressWarnings("InfiniteLoopStatement")
    private void dataTransferLoop() throws IOException {

        // Allocate the buffer for a single packet.
        ByteBuffer packet = ByteBuffer.allocate(PACK_SIZE);

        while (true) {

            int length = mInputStream.read(packet.array());
            if (length > 0) {

                packet.limit(length);

                Log.d (TAG, "--- new incoming packet ---");
                Log.d(TAG, "->| " + HexHelper.toString(packet.array()));
                IPPacket ipPacket = new IPPacket(0, packet.array ());
                Log.i(TAG, "->| " + ipPacket.toColoredVerboseString(false));

                if (ipPacket.getProtocol() == 6)
                {
                    //TCP
                    TCPPacket tcpPacket = new TCPPacket(0, packet.array());
                    Log.i(TAG, "->| " + tcpPacket.toColoredVerboseString(false));

                    if (tcpPacket.isSyn())
                    {
                        //handshake towards VPN
                        try {
                            sendTCPPacketToVPN(buildSynAckPacket(tcpPacket));
                        } catch (NetUtilsException e) {
                            e.printStackTrace();
                        }

                        sendTCPData(tcpPacket, false);
                    }
                    else
                    {
                        sendTCPData(tcpPacket, true);
                    }
                }
                else if (ipPacket.getProtocol() == 17)
                {
                    //UDP
                    DatagramSocket socket = sendDatagramPacket (packet.array());
                    DatagramPacket datagramPacket = receiveDatagramPacket(socket);
                    socket.close();

                    try {
                        sendUDPPacketToVPN (ipPacket, datagramPacket.getData());
                    } catch (NetUtilsException e) {
                        e.printStackTrace();
                    }
                }
                else
                {
                    Log.e (TAG, "unhandled protocol! " + ipPacket.toColoredVerboseString(false));
                }

                packet.clear();
            }

            try {
                Thread.sleep(100, 0);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void sendTCPData(TCPPacket tcpPacket, boolean read) throws IOException
    {
        Socket socket = createSocketConnection (tcpPacket);

        DataOutputStream outToServer = new DataOutputStream(socket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        Log.d(TAG, "|-> TCP Packet (addr: " + tcpPacket.getDestinationAddress() + " port: " + tcpPacket.getDestinationPort() + " saddr: " + socket.getLocalAddress() + " sport: " + socket.getLocalPort() + ")");

        outToServer.write(tcpPacket.getData());

        if (read) {
            char[] buffer = new char[PACK_SIZE * 2];
            int val = -1;

            while ((val = inFromServer.read(buffer, 0, PACK_SIZE * 2)) != -1) {
                //TODO maybe have to split into more packets
                try {
                    sendTCPPacketToVPN(buildTCPPacket(tcpPacket, buffer));
                } catch (NetUtilsException e) {
                    e.printStackTrace();
                }
            }

            /*String line = null;
            while ((line = inFromServer.readLine()) != null)
            {
                Log.d (TAG, "|<- tcp answer: " + line);
            }*/
        }

        socket.close();
    }

    private TCPPacketIpv4 buildTCPPacket(TCPPacket tcpPacket, char[] buffer) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(tcpPacket.isAck());
        tcpPacketBuilder.setFINFlag(tcpPacket.isFin());
        tcpPacketBuilder.setPSHFlag(tcpPacket.isPsh());
        tcpPacketBuilder.setRSTFlag(tcpPacket.isRst());
        tcpPacketBuilder.setSYNFlag(tcpPacket.isSyn());
        tcpPacketBuilder.setURGFlag(tcpPacket.isUrg());
        tcpPacketBuilder.setSeqNum((long) (Math.random() * 100000));
        tcpPacketBuilder.setAckNum(tcpPacket.getSequenceNumber() + 1); //TODO remember old value, store and use it
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setPayload(new String(buffer).getBytes());

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(tcpPacket.getId() + 1);
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4) tcpPacketBuilder.createTCPPacket();
    }

    private TCPPacketIpv4 buildSynAckPacket(TCPPacket tcpPacket) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(true);
        tcpPacketBuilder.setSYNFlag(true);
        tcpPacketBuilder.setSeqNum((long) (Math.random() * 100000));
        tcpPacketBuilder.setAckNum(tcpPacket.getSequenceNumber() + 1);
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(tcpPacket.getId() + 1);
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4) tcpPacketBuilder.createTCPPacket();
    }

    private void sendTCPPacketToVPN(TCPPacketIpv4 tcpPacketToSend) throws IOException, NetUtilsException {
        //Log.d (TAG, HexHelper.toString(tcpPacketToSend.getRawBytes()));

        IPPacket ipPacket = new IPPacket(14, tcpPacketToSend.getRawBytes());
        Log.d(TAG, "<-| " + ipPacket.toColoredVerboseString(false));
        Log.d(TAG, "<-| " + new TCPPacket(14, tcpPacketToSend.getRawBytes()).toColoredVerboseString(false));
        //Log.d(TAG, "<-| TCP.data: " + HexHelper.toString(new UDPPacket(14, tcpPacketToSend.getRawBytes()).getData()));
        //Log.d(TAG, "<-| ip packet: " + HexHelper.toString(ipPacket.getEthernetData()));

        Log.d(TAG, "// writing received tcp packet back to vpn");
        mOutputStream.write(ipPacket.getEthernetData());
    }

    private void sendUDPPacketToVPN(IPPacket ipPacket, byte[] data) throws IOException, NetUtilsException {
        UDPPacketIpv4 udpPacketToSend = buildUDPPacket (ipPacket, data);

        //Log.e (TAG, HexHelper.toString(udpPacketToSend.getRawBytes()));

        ipPacket = new IPPacket(14, udpPacketToSend.getRawBytes());
        Log.i(TAG, "<-| " + ipPacket.toColoredVerboseString(false));
        //Log.d(TAG, "<-| UDP.data: " + HexHelper.toString(new UDPPacket(14, udpPacketToSend.getRawBytes()).getData()));
        //Log.d(TAG, "<-| ip packet: " + HexHelper.toString(ipPacket.getEthernetData()));

        //Log.d(TAG, "// writing received udp packet back to vpn");
        mOutputStream.write(ipPacket.getEthernetData());
    }

    private UDPPacketIpv4 buildUDPPacket(IPPacket ipPacket, byte[] data) throws NetUtilsException {
        UDPPacket udpPacket = new UDPPacket(0, ipPacket.getEthernetData());
        UDPPacketBuilder udpPacketBuilder = new UDPPacketBuilder();
        udpPacketBuilder.setSrcPort(udpPacket.getDestinationPort());
        udpPacketBuilder.setDstPort(udpPacket.getSourcePort());
        udpPacketBuilder.setPayload(trimTrailingZeros(data));
        //TODO check if trailing zeros is okay - or better replace it with a new byte array with correct length

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(ipPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(ipPacket.getSourceAddress()));
        ipv4.setId(ipPacket.getId() + 1);
        ipv4.setTos(ipPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(16);
        ipv4.addL4Buider(udpPacketBuilder);

        return (UDPPacketIpv4) udpPacketBuilder.createUDPPacket();
    }

    private DatagramPacket receiveDatagramPacket(DatagramSocket socket) throws IOException
    {
        byte[] answer = new byte[PACK_SIZE];
        DatagramPacket datagramPacket = new DatagramPacket(answer, answer.length);
        socket.receive(datagramPacket);
        //debugIncomingPacket(datagramPacket);

        return datagramPacket;
    }

    private DatagramSocket sendDatagramPacket(byte[] bytes) throws IOException
    {
        UDPPacket udpPacket = new UDPPacket(0, bytes);
        Log.d(TAG, "->| " + udpPacket.toColoredString(false));

        DatagramSocket socket = new DatagramSocket();
        protect(socket);
        //Log.d(TAG, "|-> sending UDP data: " + HexHelper.toString(udpPacket.getData()));
        DatagramPacket datagramPacket = new DatagramPacket(udpPacket.getData(), udpPacket.getLength (), InetAddress.getByName(udpPacket.getDestinationAddress()), udpPacket.getDestinationPort());

        //Log.d (TAG, "|-> " + HexHelper.toString (datagramPacket.getData()));

        socket.send(datagramPacket);

        return socket;
    }

    private Socket createSocketConnection(TCPPacket tcpPacket) throws IOException {
        Socket socket = SocketChannel.open().socket();
        protect(socket);
        InetSocketAddress address = new InetSocketAddress(tcpPacket.getDestinationAddress(),tcpPacket.getDestinationPort());
        socket.connect(address);
        return socket;
    }

    private byte[] trimTrailingZeros(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }

    private void debugIncomingPacket(DatagramPacket datagramPacket)
    {
        Log.d (TAG, "|<- --- incoming Datagram Packet ---");
        Log.d(TAG, "|<- length: " + datagramPacket.getLength());
        Log.d(TAG, "|<- address: " + datagramPacket.getAddress());
        Log.d(TAG, "|<- data: " + datagramPacket.getData());
        Log.d(TAG, "|<- data length: " + datagramPacket.getData().length);
        Log.d(TAG, "|<- port: " + datagramPacket.getPort());
        Log.d(TAG, "|<- socketaddress: " + datagramPacket.getSocketAddress().toString());
        Log.d(TAG, "|<- data in hex: " + HexHelper.toString(datagramPacket.getData()));
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

    public class VPNServiceBinder extends Binder {

        public DemoVPNService getService() {

            return DemoVPNService.this;
        }
    }
}