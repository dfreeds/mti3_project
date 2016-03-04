/*
 * Developed by David Fritz 2016.
 */

package com.example.hackeris.project;

import net.sourceforge.jpcap.net.TCPPacket;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;

/**
 * Created by dfritz on 15/01/16.
 */
public class TCPReceiver implements Runnable{

    private static final String TAG = "DemoVPNService";
    private static final int DATA_LENGTH = 1200;

    private DemoVPNService service;
    private TCPConnection tcpConnection;
    private TCPPacket tcpPacket;
    private InputStream inFromServer;

    @Override
    public void run() {
        try {
            while (true) {
                byte[] buffer = new byte[DATA_LENGTH];
                int bytesRead = 0;

                while ((bytesRead = inFromServer.read(buffer, 0, DATA_LENGTH)) != -1) {
                    byte[] actualReadBytes = Arrays.copyOf(buffer, bytesRead);
                    //Log.d(TAG, "### bytes read:");
                    //Log.d(TAG, HexHelper.toString(actualReadBytes));
                    //Log.d(TAG, "###");

                    try {
                        service.sendTCPPacketToVPN(buildTCPPacket(tcpConnection, tcpPacket, actualReadBytes));
                    } catch (NetUtilsException e) {
                        e.printStackTrace();
                    }

                    buffer = new byte[DATA_LENGTH];
                }

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private TCPPacketIpv4 buildTCPPacket(TCPConnection tcpConnection, TCPPacket tcpPacket, byte[] bytes) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(true);
        tcpPacketBuilder.setFINFlag(false);
        tcpPacketBuilder.setSeqNum(tcpConnection.getNextSequenceNumber());
        tcpPacketBuilder.setAckNum(tcpConnection.getAckNumber());
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setWindowSize(tcpPacket.getWindowSize());
        tcpPacketBuilder.setPayload(bytes);
        tcpConnection.setLastDataSize(bytes.length);
        //Log.d(TAG, "@@@ bytes.length: " + bytes.length);

        IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
        ipv4.setSrcAddr(new IPv4Address(tcpPacket.getDestinationAddress()));
        ipv4.setDstAddr(new IPv4Address(tcpPacket.getSourceAddress()));
        ipv4.setId(tcpConnection.getNextIdNumber());
        ipv4.setTos(tcpPacket.getTypeOfService());
        ipv4.setFragFlags(2);
        ipv4.setTTL(64);
        ipv4.addL4Buider(tcpPacketBuilder);

        return (TCPPacketIpv4)tcpPacketBuilder.createTCPPacket();
    }

    public void setService(DemoVPNService service) {
        this.service = service;
    }
    public void setTcpConnection(TCPConnection tcpConnection) {
        this.tcpConnection = tcpConnection;
    }
    public void setInFromServer(InputStream inFromServer) {
        this.inFromServer = inFromServer;
    }
    public void setTcpPacket(TCPPacket tcpPacket) {
        this.tcpPacket = tcpPacket;
    }
}