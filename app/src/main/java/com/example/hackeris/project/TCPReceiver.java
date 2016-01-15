/*
 * Developed by David Fritz 2016.
 */

package com.example.hackeris.project;

import android.util.Log;

import net.sourceforge.jpcap.net.TCPPacket;

import java.io.BufferedReader;
import java.io.IOException;
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

    public void setService(DemoVPNService service) {
        this.service = service;
    }

    DemoVPNService service;

    public void setTcpConnection(TCPConnection tcpConnection) {
        this.tcpConnection = tcpConnection;
    }

    private TCPConnection tcpConnection;

    public void setTcpPacket(TCPPacket tcpPacket) {
        this.tcpPacket = tcpPacket;
    }

    private TCPPacket tcpPacket;

    public void setInFromServer(BufferedReader inFromServer) {
        this.inFromServer = inFromServer;
    }

    private BufferedReader inFromServer;

    @Override
    public void run() {
        while (true) {
            char[] buffer = new char[1388];

            try {
                while ((inFromServer.read(buffer, 0, 1388)) != -1) {
                    Log.d(TAG, "### ");
                    Log.d(TAG, new String(buffer));
                    Log.d(TAG, "###");

                    try {
                        service.sendTCPPacketToVPN(buildTCPPacket(tcpConnection, tcpPacket, buffer));
                    } catch (NetUtilsException e) {
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private TCPPacketIpv4 buildTCPPacket(TCPConnection tcpConnection, TCPPacket tcpPacket, char[] buffer) throws NetUtilsException
    {
        TCPPacketBuilder tcpPacketBuilder = new TCPPacketBuilder();
        tcpPacketBuilder.setACKFlag(true);
        tcpPacketBuilder.setFINFlag(tcpPacket.isFin());
        tcpPacketBuilder.setSeqNum(tcpConnection.getNextSequenceNumber());
        tcpPacketBuilder.setAckNum(tcpPacket.getSequenceNumber() + 1);
        tcpPacketBuilder.setSrcPort(tcpPacket.getDestinationPort());
        tcpPacketBuilder.setDstPort(tcpPacket.getSourcePort());
        tcpPacketBuilder.setWindowSize(tcpPacket.getWindowSize());
        tcpPacketBuilder.setPayload(trimTrailingZeros(new String(buffer).getBytes()));

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

    private byte[] trimTrailingZeros(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }
}
