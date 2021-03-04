/* added by us */
package ca.ubc.cs317.dnslookup.processing;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import ca.ubc.cs317.dnslookup.DNSNode;
import ca.ubc.cs317.dnslookup.RecordType;
import ca.ubc.cs317.dnslookup.DNSCache;
import ca.ubc.cs317.dnslookup.ResourceRecord;
import ca.ubc.cs317.dnslookup.DNSLookupService;
import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.*;

public class DNSByteResults {
    private ByteBuffer resultBuffer;
    private byte[] resultArray;
//    private static DNSCache cache = DNSCache.getInstance(); //note: return a list
    // of records from here, store to cache in queryHandler

    /* response fields */
    int qdcount;
    int ancount;
    int nscount;
    int arcount;
    DNSNode node;
    Set<ResourceRecord> setOfRecords;


    public DNSByteResults(ByteBuffer buffer) {
        resultBuffer = buffer;
        resultArray = buffer.array();
        setOfRecords = new HashSet<ResourceRecord>();
    }

    // return something?
    public Set<ResourceRecord> decodeByteResult() {
        decodeRCode();
        qdcount = decodeBytesToInt(4, 5);
        ancount = decodeBytesToInt(6, 7);
        nscount = decodeBytesToInt(8, 9);
        arcount = decodeBytesToInt(10, 11);
        int ind = decodeQuestion(12);
        System.out.println("last index is: " + ind);
        // TODO: if ans available return ans, else can return 0.0.0.0 as the IP

        // decode each record
         int totals = ancount + nscount + arcount;
         while (totals > 0) {
             ind = decodeRecord(ind);
             totals--;
         }
        return setOfRecords;
    }

    // dig +norecurse @199.7.83.42 finance.google.ca --> part1
    // part1: finance.google.ca no answer --> 0.0.0.0 + save decoded
    // part2: iterative lookup --> just answer!

    // /* i think we dont need this? */
    // private static void decodeTransactionId() {

    // }

    private void decodeRCode() {
        byte b = resultArray[3];
        int rcode = (0b1111) & b; // 00001111 & 00000101 == 00000101
        if (rcode != 0) {
            throw new Error(); // TODO: change
        }
    }

    /* decode 2 bytes to an int */
    private int decodeBytesToInt(int startIndex, int endIndex) {
        byte[] b = Arrays.copyOfRange(resultArray, startIndex, endIndex + 1);
        int count = ((b[0] & 0xff) << 8) | ((b[1] & 0xff) << 0);
        return count;
    }

    private int decodeQuestion(int startIndex) {
        byte length = 0;
        StringBuilder sb = new StringBuilder();
        do {
            length = resultArray[startIndex++]; // 12
            if (length == 0)
                break;
            byte[] domain = new byte[length];
            for (int i = 0; i < (int) length; i++) {
                domain[i] = resultArray[startIndex++];
            }
            String domainName;
            try {
                domainName = new String(domain, "US-ASCII");
                sb.append(domainName);
                sb.append(".");
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } while (length != 0);
        sb = sb.deleteCharAt(sb.length() - 1);
        System.out.println("domain name: " + sb.toString());
        int qtype = decodeBytesToInt(startIndex, ++startIndex);
        System.out.println("q type: " + qtype);
        node = new DNSNode(sb.toString(), RecordType.getByCode(qtype));
        startIndex++;

        // TODO store qclass?
        int qclass = decodeBytesToInt(startIndex, ++startIndex);
        return ++startIndex;
    }

//    private String getNameAtOffset(int startIndex) {
//        byte length = 0;
//        StringBuilder sb = new StringBuilder();
//        do {
//            length = resultArray[startIndex++]; // 12
//            if (length == 0)
//                break;
//            byte[] domain = new byte[length];
//            for (int i = 0; i < (int) length; i++) {
//                domain[i] = resultArray[startIndex++];
//            }
//            String domainName;
//            try {
//                domainName = new String(domain, "US-ASCII");
//                sb.append(domainName);
//                sb.append(".");
//            } catch (UnsupportedEncodingException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            }
//        } while (length != 0);
//        sb = sb.deleteCharAt(sb.length() - 1);
//        System.out.println("domain name: " + sb.toString());
//        return sb.toString();
//    }

    private String readNameAtOffsetExperiment(int startIndex) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            byte first = resultArray[startIndex];
            if (first == 0) {
                /* end of the hostname, break */
                sb = sb.deleteCharAt(sb.length() - 1);
                break;
            }
            if (isPointer(startIndex) != -1) {
                /* pointer (start of another name), break */
                startIndex = resultArray[startIndex+1];
                continue;
            }
            byte[] domain = new byte[first];
            for (int i = 0; i < (int) first; i++) {
                domain[i] = resultArray[++startIndex];
            }
            startIndex++;
            String domainName;
            try {
                domainName = new String(domain, "US-ASCII");
                sb.append(domainName);
                sb.append(".");
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        System.out.println("query result: " + sb.toString());
        return sb.toString();
    }

    /* if pointer, return the offset in int, else return -1 */
    private int isPointer(int startIndex) {
        int firstByteAsInt = resultArray[startIndex];
        int shifted = firstByteAsInt >> 6;
        if (shifted == -1) {
            /* pointer: only take the last 14 bits to find the offset */
            int offset = decodeBytesToInt(startIndex, startIndex + 1) & 0x3fff;
            return offset;
        } else {
            /* not a pointer */
            return -1;
        }
    }

    private int decodeRecord(int startIndex) {
        int pointer = isPointer(startIndex);
        String hostname = "";
        if (pointer != -1) {
            /* pointer */
            hostname = readNameAtOffsetExperiment(pointer);
            startIndex = startIndex + 2;
        } else {
            /* not a pointer */
            hostname = readNameAtOffsetExperiment(startIndex);
            startIndex = startIndex + hostname.length() + 2;
        }

        RecordType type = RecordType.getByCode(decodeBytesToInt(startIndex, ++startIndex));
        startIndex++;
        int rclass = decodeBytesToInt(startIndex, ++startIndex);
        startIndex++;
        byte[] ttlBytes = Arrays.copyOfRange(resultArray, startIndex, startIndex + 4);
        int ttl = ByteBuffer.wrap(ttlBytes).getInt();
        startIndex = startIndex + 4;
        int rlength = decodeBytesToInt(startIndex, ++startIndex);
        startIndex++;

        String result = getRecordResultBasedOnRecordType(startIndex,
                    rlength, type, rclass);
        startIndex = startIndex + rlength;
        if (type == RecordType.A) {
            try {
                InetAddress addressInet = InetAddress.getByName(result);
                System.out.println("inet to string: " + addressInet.toString());
                ResourceRecord record = new ResourceRecord(hostname, type, ttl,
                        addressInet);
                setOfRecords.add(record);
            } catch (UnknownHostException e) {
                System.err.println("Invalid root server (" + e.getMessage() + ").");
                System.exit(1);
            }
        } else {
            ResourceRecord record = new ResourceRecord(hostname, type, ttl,
                    result);
            setOfRecords.add(record);
        }
//        cache.addResult(record);
        return startIndex;
    }

    private String readTypeAResult(int startIndex, int addressLength) {
        StringBuilder sb = new StringBuilder();
        while (addressLength > 0) {
            // in byte chunks convert to decimal and append .
            int section = resultArray[startIndex] & 0xff;
            startIndex++;
            sb.append(section);
            sb.append(".");
            addressLength--;
        }

        sb = sb.deleteCharAt(sb.length() - 1);
        System.out.println("type A host address: " + sb.toString());
        return sb.toString();
    }
    private String readTypeAAResult(int startIndex, int addressLength) {
        StringBuilder sb = new StringBuilder();
        while (addressLength > 0) {
            String section = getHexString(resultArray[startIndex], resultArray[startIndex + 1]);
            startIndex += 2;    sb.append(section);
            sb.append(":");
            addressLength = addressLength-2;
        }
        sb = sb.deleteCharAt(sb.length() - 1);
        System.out.println("AAAA address: " + sb.toString());
        return sb.toString();
    }

    private String readCNameResultExp(int startIndex, int length) {
        String hostname = readNameAtOffsetExperiment(startIndex);
        return hostname;
    }

    private String getHexString(byte firstB, byte secondB) {
        String input = String.format("%02x%02x", firstB, secondB);
        input =input.replaceFirst("^0+", "");
        if (input.equals("")) {
            return "0";
        } else {
            return input;
        }
    }

    // TODO
    private String getRecordResultBasedOnRecordType(int startIndex, int rlength, RecordType type, int rclass) {
        int typeCode = type.getCode();
        switch (typeCode) {
            case 1:
                System.out.println("Type A record to be decoded");
                /* class IN */
                if (rclass == 1) {
                    return readTypeAResult(startIndex, rlength);
                }
                // TODO For the CH class, a domain name followed by a 16 bit octal Chaos
                // address.
                break;
            case 2:
            case 5:
                System.out.println("Type CNAME/NS record");
                if (rclass == 1) {
                    String res = readCNameResultExp(startIndex, rlength);
                    return res;
                }
                break;
            case 28:
                System.out.println("Type AAAA record");
                if (rclass == 1) {
                    String res = readTypeAAResult(startIndex, rlength);
                    return res;
                }
                break;
            default:
                return "";
        }
        return "";
    }

}
