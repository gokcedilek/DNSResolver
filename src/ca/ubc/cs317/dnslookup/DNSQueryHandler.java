package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Set;
import java.util.Arrays;
import java.lang.Integer;
import java.lang.Character;
import java.lang.Byte;
import org.apache.commons.lang3.StringUtils;



public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    private static byte hexToByte(String hexString) {
        // int firstDigit = toDigit(hexString.charAt(0));
        int firstDigit = Character.digit(hexString.charAt(0), 16);
        // int secondDigit = toDigit(hexString.charAt(1));
        int secondDigit = Character.digit(hexString.charAt(1), 16);
        return (byte) ((firstDigit << 4) + secondDigit);
    }
    /*
    private int toDigit(char hexChar) {
    int digit = Character.digit(hexChar, 16);
    if(digit == -1) {
        throw new IllegalArgumentException(
          "Invalid Hexadecimal Character: "+ hexChar);
    }
    return digit;
}
    */

    private static void encodeDomainName(String hostname) {
        System.out.println("entered domain name");
        // System.out.print(StringUtils.split("."));
        //    \\. \. "\"\\s"
        for(String label : hostname.split("\\.")) {
            byte b = (byte)label.length();
            System.out.println("length: " + b);
            byte[] host = label.getBytes();
            System.out.println(Arrays.toString(host));
        }
    }
    
    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server, DNSNode node) throws IOException {
        // TODO (PART 1): Implement this
        // System.out.println(Arrays.toString(message));
        // int queryId = random.nextInt(65535);
        // System.out.println(queryId); 
        // String hex = Integer.toHexString(0x10000 | queryId).substring(1);
        // System.out.println("Hex value is " + hex);
        
        String hostname = node.getHostName();
        System.out.println(hostname);
        encodeDomainName(hostname);
        
        // byte byte1 = hexToByte(hex.substring(0,2));
        // byte bytetest = (byte)hex.substring(0,2);
        // byte byte2 = hexToByte(hex.substring(2, hex.length()));
        // System.out.println("byte1: " + byte1+ " byte2: " + byte2);
        // byte[] byteArray = hex.getBytes();
        // System.out.println("byte array " + Arrays.toString(byteArray)); 
        // String sub1 = hex.substring(0, 2);
        // String sub2 = hex.substring(2, hex.length());
        // System.out.println("sub 0: " + hex.substring(0, 2));
        // System.out.println("sub 1: " + hex.substring(2, hex.length()));  
        // byte b1 = Byte.valueOf(sub1).byteValue();
        // byte b2 = Byte.valueOf(sub2).byteValue(); 
        // System.out.println("b1: " + b1);
        // System.out.println("b2: " + b2);   

        /*
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
        */
         return null;                                           
        /*
        // send request
        // what do we do with the node??
        System.out.println("sending!");
        DatagramPacket packet = new DatagramPacket(message, message.length, server, 53);
        socket.send(packet);

        // get response
        System.out.println("receiving!");
        byte[] response = new byte[1024];
        packet = new DatagramPacket(response, response.length);
        socket.receive(packet);

        // display response
        // String received = new String(packet.getData(), 0, packet.getLength());
        // System.out.println("response: " + Arrays.toString(packet.getData()));
        int transactionID = random.nextInt();
        ByteBuffer buf = ByteBuffer.wrap(packet.getData());
        System.out.println(Arrays.toString(packet.getData()));
        DNSServerResponse res = new DNSServerResponse(buf, transactionID);
        return res;
        */
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // TODO (PART 1): Implement this
        return null;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

