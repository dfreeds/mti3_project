/*
 * Developed by David Fritz 2016.
 */

/*
 * Developed by David Fritz 2016.
 */

package com.example.hackeris.project;

import android.util.Log;

import net.sourceforge.jpcap.net.IPPacket;
import net.sourceforge.jpcap.net.UDPPacket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.UDPPacketBuilder;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;

/**
 * Created by dfritz on 19/04/16.
 */
public class UDPReceiver implements Runnable{

    private static final String TAG = "TracingVPNService";
    private static final int DATA_LENGTH = 1400;

    private DemoVPNService service;

    private UDPPacket udpPacket;

    public UDPReceiver(DemoVPNService service, UDPPacket udpPacket) {
        this.service = service;
        this.udpPacket = udpPacket;
    }

    @Override
    public void run() {
        try {
            DatagramSocket socket = sendDatagramPacket(udpPacket);
            DatagramPacket datagramPacket = receiveDatagramPacket(socket);
            socket.close();

            try {
                service.sendUDPPacketToVPN(udpPacket, datagramPacket.getData());
            } catch (NetUtilsException e) {
                e.printStackTrace();

            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private DatagramSocket sendDatagramPacket(UDPPacket udpPacket) throws IOException
    {
        Log.d(TAG, "->| " + udpPacket.toColoredString(false));

        DatagramSocket socket = new DatagramSocket();
        service.protect(socket);
        //Log.d(TAG, "|-> sending UDP data: " + HexHelper.toString(udpPacket.getData()));
        DatagramPacket datagramPacket = new DatagramPacket(udpPacket.getData(), udpPacket.getLength (), InetAddress.getByName(udpPacket.getDestinationAddress()), udpPacket.getDestinationPort());
        //Log.d (TAG, "|-> " + HexHelper.toString (datagramPacket.getData()));

        socket.send(datagramPacket);

        return socket;
    }

    private UDPPacketIpv4 buildUDPPacket(IPPacket ipPacket, byte[] data) throws NetUtilsException {
        UDPPacket udpPacket = new UDPPacket(0, ipPacket.getEthernetData());
        UDPPacketBuilder udpPacketBuilder = new UDPPacketBuilder();
        udpPacketBuilder.setSrcPort(udpPacket.getDestinationPort());
        udpPacketBuilder.setDstPort(udpPacket.getSourcePort());
        udpPacketBuilder.setPayload(trimTrailingZeros(data));

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
        byte[] answer = new byte[DATA_LENGTH];
        DatagramPacket datagramPacket = new DatagramPacket(answer, answer.length);
        socket.receive(datagramPacket);
        //debugIncomingPacket(datagramPacket);

        return datagramPacket;
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

    public void setService(DemoVPNService service) {
        this.service = service;
    }

    public void setUdpPacket(UDPPacket udpPacket) {
        this.udpPacket = udpPacket;
    }
}
