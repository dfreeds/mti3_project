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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * Created by hackeris on 15/9/6.
 */
public class DemoVPNService extends VpnService implements Handler.Callback, Runnable {

    private static final String TAG = "DemoVPNService";

    private Handler mHandler;

    private Thread mThread;

    private ParcelFileDescriptor mInterface;

    private FileInputStream mInputStream;

    private FileOutputStream mOutputStream;

    private SocketChannel mTunnel;

    private Encryptor mEncrypter;

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

        if (mEncrypter == null) {
            mEncrypter = new Encryptor();
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
            if (mTunnel != null) {
                mTunnel.close();
            }
        } catch (IOException ie) {
            ie.printStackTrace();
        }
        mThread = null;
        mInterface = null;
        mInputStream = null;
        mOutputStream = null;
        mTunnel = null;
    }

    private void configure() throws IOException {

        VpnService.Builder builder = new VpnService.Builder();
        //TODO get local address?
        builder.addAddress("10.0.0.42", 32).addRoute("0.0.0.0", 0).setSession("DemoVPN").addDnsServer("8.8.8.8")
                .setMtu(1500);

        mInterface = builder.establish();

        mInputStream = new FileInputStream(mInterface.getFileDescriptor());
        mOutputStream = new FileOutputStream(mInterface.getFileDescriptor());

        /*//  建立一个到代理服务器的网络链接，用于数据传送
        mTunnel = SocketChannel.open();
        // Protect the mTunnel before connecting to avoid loopback.
        if (!protect(mTunnel.socket())) {
            throw new IllegalStateException("Cannot protect the mTunnel");
        }
        mTunnel.connect(new InetSocketAddress("127.0.0.1", Integer.parseInt(mServerPort)));
        mTunnel.configureBlocking(false);*/
    }


    @SuppressWarnings("InfiniteLoopStatement")
    private void dataTransferLoop() throws IOException {

        // Allocate the buffer for a single packet.
        ByteBuffer packet = ByteBuffer.allocate(PACK_SIZE);

        /*//  一个线程用于接收代理传回的数据，一个线程用于发送手机发出的数据到代理服务器
        Thread recvThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Allocate the buffer for a single packet.
                    ByteBuffer packet = ByteBuffer.allocate(PACK_SIZE);
                    while (true) {
                        int length = mTunnel.read(packet);
                        mEncrypter.decrypt(packet.array(), length);
                        if (length > 0) {
                            if (packet.get(0) != 0) {
                                packet.limit(length);
                                try {
                                    mOutputStream.write(packet.array());
                                } catch (IOException ie) {
                                    ie.printStackTrace();
                                    NetworkUtils.logIPPack(TAG, packet, length);
                                }
                                packet.clear();
                            }
                        }
                    }
                } catch (IOException ie) {
                    ie.printStackTrace();
                }
            }
        });
        recvThread.start();*/

        while (true) {

            int length = mInputStream.read(packet.array());
            if (length > 0) {

                //NetworkUtils.logIPPack(TAG, packet, length);
                packet.limit(length);
                //mEncrypter.encrypt(packet.array(), length);
                //mTunnel.write(packet);

                /*RawPacket rpacket = new RawPacket(new Timeval(0,0), packet.array(), 0);
                Log.e(TAG, "rpacket: " + rpacket.toString());*/

                /*EthernetPacket epacket = new EthernetPacket (1, packet.array());
                Log.e(TAG, "epacket: " + epacket.toString());*/

                IPPacket ipacket = new IPPacket(0, packet.array ());
                Log.e(TAG, ipacket.toColoredVerboseString(false));

                if (ipacket.getProtocol() == 6)
                {
                    //TCP
                    TCPPacket tpacket = new TCPPacket(0, packet.array ());
                    Log.e(TAG, tpacket.toColoredVerboseString(false));
                }
                else if (ipacket.getProtocol() == 17)
                {
                    //UDP
                    UDPPacket upacket = new UDPPacket(0, packet.array ());
                    Log.e(TAG, upacket.toColoredString(false));

                    DatagramSocket s = new DatagramSocket();
                    Log.d(TAG, "sending UDP Packet! data_length: " + upacket.getLength() + " addr: " + InetAddress.getByName(upacket.getDestinationAddress()) + " port: " + upacket.getDestinationPort());
                    DatagramPacket p = new DatagramPacket(upacket.getData(), upacket.getLength(), InetAddress.getByName(upacket.getDestinationAddress()), upacket.getDestinationPort());

                    /*Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();

                    while (en.hasMoreElements())
                    {
                        NetworkInterface nint = en.nextElement();
                        if ("eth1".equals (nint.getDisplayName()))
                        {
                            s.bind (new InetSocketAddress(nint.getInetAddresses().nextElement(), 0));
                        }
                    }*/

                    s.send(p);

                    byte[] answer = new byte[1500];

                    p = new DatagramPacket(answer, answer.length);
                    s.receive(p);
                    Log.e(TAG, "got answer!!! " + new String(answer, 0, p.getLength()));

                    s.close();
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

    @Override
    public void run() {

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
                //mTunnel.close();
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