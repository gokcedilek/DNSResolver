package ca.ubc.cs317.dnslookup;

import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Set;

import ca.ubc.cs317.dnslookup.processing.DNSByteResults;

import java.util.Arrays;
import java.lang.Integer;
import java.lang.Character;
import java.lang.Byte;
// import org.apache.commons.lang3.StringUtils;

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
        int firstDigit = Character.digit(hexString.charAt(0), 16);
        int secondDigit = Character.digit(hexString.charAt(1), 16);
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static void printByteArray(byte[] b) {
        for (int i = 0; i < b.length; i++) {
            System.out.print(String.format("0x%02X", b[i]) + ", ");
        }
        System.out.println();
    }

    private static int encodeDomainName(String hostname, byte[] message, int startIndex) {
        for (String label : hostname.split("\\.")) {
            byte b = (byte) label.length();
            // System.out.println("length: " + String.format("0x%02X", b));
            message[startIndex++] = b;
            byte[] hostBytes = label.getBytes();
            for (int i = 0; i < hostBytes.length; i++) {
                message[startIndex++] = hostBytes[i];
            }
        }
        return startIndex;
    }

    /* write an int as 16 bits */
    private static int encodeIntToBytes(int val, byte[] message, int startIndex) {
        String hex = Integer.toHexString(0x10000 | val).substring(1);
        // System.out.println("hex value: " + hex);

        byte byte1 = hexToByte(hex.substring(0, 2));
        byte byte2 = hexToByte(hex.substring(2, hex.length()));
        message[startIndex++] = byte1;
        message[startIndex++] = byte2;
        return startIndex;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the
     *         transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server, DNSNode node)
            throws IOException {
        // TODO (PART 1): Implement this

        /* query id (0, 1) */
        int queryId = random.nextInt(65535);
        encodeIntToBytes(queryId, message, 0);

        /* qr, opcode, aa, tc, rd (2) */

        /* ra, z, rcode (3) */

        /* qcount (4, 5) */
        encodeIntToBytes(1, message, 4);

        /* ancount (6, 7), nscount (8, 9), arcount (10, 11) */

        /* qname (12, _) */
        String hostname = node.getHostName();
        int index = encodeDomainName(hostname, message, 12);

        /* qtype */
        int recordType = node.getType().getCode();
        index = encodeIntToBytes(recordType, message, ++index);

        /* qclass */
        index = encodeIntToBytes(1, message, index);
        System.out.println("last index: " + index);

        /* send query */
        System.out.println("query!");
        byte[] query = Arrays.copyOfRange(message, 0, index);
        printByteArray(query);
        DatagramPacket packet = new DatagramPacket(query, query.length, server, 53);
        socket.send(packet);

        /* receive response */
        byte[] response = new byte[1024];
        packet = new DatagramPacket(response, response.length);
        socket.receive(packet);

        int transactionId = queryId;
        ByteBuffer buf = ByteBuffer.wrap(packet.getData());
        return new DNSServerResponse(buf, transactionId);
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the
     *                       DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the
     *         response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
            DNSCache cache) {
        // TODO (PART 1): Implement this
        System.out.println("response!!!");
        printByteArray(responseBuffer.array());

        DNSByteResults byteResults = new DNSByteResults(responseBuffer);
//        Set<ResourceRecord> records = byteResults.decodeByteResult(cache);
        Set<ResourceRecord> records = byteResults.decodeByteResult();
        // cache.forEachNode(DNSLookupService::printResults);
        return records;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(), record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(), record.getTextResult());
    }
}
