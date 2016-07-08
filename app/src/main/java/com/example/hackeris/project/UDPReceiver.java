/*
 * Developed by David Fritz 2016.
 */

/*
 * Developed by David Fritz 2016.
 */

package com.example.hackeris.project;

import android.util.Log;

import net.sourceforge.jpcap.net.UDPPacket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import edu.huji.cs.netutils.NetUtilsException;

/**
 * Created by dfritz on 19/04/16.
 */
public class UDPReceiver implements Runnable{

    private static final String TAG = "TracingVPNService";
    private static final int DATA_LENGTH = 1311;

    private TracingVPNService service;

    private UDPPacket udpPacket;

    public UDPReceiver(TracingVPNService service, UDPPacket udpPacket) {
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
        Log.d(TAG, "|-> " + udpPacket.toColoredString(false));

        DatagramSocket socket = new DatagramSocket();
        service.protect(socket);
        //Log.d(TAG, "|-> sending UDP data: " + HexHelper.toString(udpPacket.getData()));
        DatagramPacket datagramPacket = new DatagramPacket(udpPacket.getData(), udpPacket.getLength (), InetAddress.getByName(udpPacket.getDestinationAddress()), udpPacket.getDestinationPort());
        //Log.d (TAG, "|-> " + HexHelper.toString (datagramPacket.getData()));

        socket.send(datagramPacket);

        return socket;
    }

    private DatagramPacket receiveDatagramPacket(DatagramSocket socket) throws IOException
    {
        byte[] answer = new byte[DATA_LENGTH];
        DatagramPacket datagramPacket = new DatagramPacket(answer, answer.length);
        socket.receive(datagramPacket);
        //debugIncomingPacket(datagramPacket);

        return datagramPacket;
    }
}
