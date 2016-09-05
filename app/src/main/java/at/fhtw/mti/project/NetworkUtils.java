package at.fhtw.mti.project;

import android.util.Log;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Locale;

public class NetworkUtils {

    public static byte[] hexStringToBytes(String input) {
        input = input.toLowerCase(Locale.US);
        int n = input.length() / 2;
        byte[] output = new byte[n];
        int l = 0;
        for (int k = 0; k < n; k++) {
            char c = input.charAt(l++);
            byte b = (byte) ((c >= 'a' ? (c - 'a' + 10) : (c - '0')) << 4);
            c = input.charAt(l++);
            b |= (byte) (c >= 'a' ? (c - 'a' + 10) : (c - '0'));
            output[k] = b;
        }
        return output;
    }

    public static String byteArrayToHexString(byte[] src) {

        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            stringBuilder.append(' ');
            if (hv.length() < 2) {
                stringBuilder.append('0');
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    public static long byteToLong(byte[] bytes, int start) {

        return (bytes[start + 3] & 0xff) | ((bytes[start + 2] & 0xff) << 8) |
                ((bytes[start + 1] & 0xff) << 16) |
                ((bytes[start] & 0xff) << 24);
    }

    public static String longToAddressString(final long ip) {
        final long[] mask = {0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000};
        final StringBuilder ipAddress = new StringBuilder();
        for (long i = 0; i < mask.length; i++) {
            long part = (ip & mask[(int) i]) >> (i * 8);
            if (part < 0) {
                part = 256 + part;
            }
            ipAddress.insert(0, part);
            if (i < mask.length - 1) {
                ipAddress.insert(0, ".");
            }
        }
        return ipAddress.toString();
    }

    public static void logIPPack(String TAG, ByteBuffer packet){

        Log.i(TAG, "\n" + NetworkUtils.byteArrayToHexString(packet.array()));
        String sourceAddress = NetworkUtils.longToAddressString(NetworkUtils.byteToLong(packet.array(), 12));
        String destAddress = NetworkUtils.longToAddressString(NetworkUtils.byteToLong(packet.array(), 16));
        Log.i(TAG, "from " + sourceAddress + " to " + destAddress);
    }

    public static String getDomainName(byte[] data) {
        ArrayList<Byte> query = new ArrayList<Byte>();

        //skip the header
        int pos = 41;
        byte block = data[pos];

        while( block != 0x00 && pos < data.length ) {

            //If byte is over 0x21, then it's an ASCII character and
            //we can add the byte to the string as-is
            if (block >= 0x21) {
                query.add(block);
            } else {
                //Otherwise add the ASCII dot character
                query.add((byte) 0x2e);
            }

            ++pos;
            block = data[pos];
        }

        //Convert ArrayList query to string
        byte[] buffer = new byte[query.size()];
        for( int i = 0; i < buffer.length; ++i ) {
            buffer[i] = query.get(i);
        }

        return new String(buffer);
    }
}
