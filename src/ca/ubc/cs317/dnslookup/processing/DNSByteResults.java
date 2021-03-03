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

import java.util.*;

public class DNSByteResults {
    private ByteBuffer resultBuffer;
    private byte[] resultArray;
    private static DNSCache cache = DNSCache.getInstance(); //note: return a list
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
//        resultArray = new byte[] { (byte) 0xD5, 0x55, (byte) 0x80, (byte) 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x04, 0x00,
//                0x08, 0x07, 0x66, 0x69, 0x6E, 0x61, 0x6E, 0x63, 0x65, 0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x02, 0x63,
//                0x61, 0x00, 0x00, 0x01, 0x00, 0x01, (byte) 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03, 0x72, (byte) 0x9C,
//                0x00, 0x14, 0x07, 0x66, 0x69, 0x6E, 0x61, 0x6E, 0x63, 0x65, 0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03,
//                0x63, 0x6F, 0x6D, 0x00, (byte) 0xC0, 0x2F, 0x00, 0x05, 0x00, 0x01, 0x00, 0x05, 0x2C, 0x5D, 0x00, 0x09, 0x04,
//                0x77, 0x77, 0x77, 0x33, 0x01, 0x6C, (byte) 0xC0, 0x37 };
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
//        int nextI = decodeRecord(ind);
//        decodeRecord(nextI);
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
        System.out.println(startIndex);
        int qclass = decodeBytesToInt(startIndex, ++startIndex);
        System.out.println("q class: " + qclass);
        // check pointer next or
        return ++startIndex;
    }

    private String getNameAtOffset(int startIndex) {
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
        return sb.toString();
    }

    private String readNameAtOffsetExperiment(int startIndex) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            byte first = resultArray[startIndex];
            if (first == 0) {
                /* end of the hostname, break */
                System.out.println("end of hostname!!!");
                sb = sb.deleteCharAt(sb.length() - 1);
                break;
            }
            if (isPointer(startIndex) != -1) {
                /* pointer (start of another name), break */
                System.out.println("new pointer!!!");
                startIndex = resultArray[startIndex+1];
                System.out.println("pointer at the end to: " + startIndex);
                continue;
//                break;
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
        System.out.println("domain name: " + sb.toString());
        return sb.toString();
    }

    /* if pointer, return the offset in int, else return -1 */
    private int isPointer(int startIndex) {
        int firstByteAsInt = resultArray[startIndex];
        int shifted = firstByteAsInt >> 6;
        if (shifted == -1) {
            /* pointer: only take the last 14 bits to find the offset */
            int offset = decodeBytesToInt(startIndex, startIndex + 1) & 0x3fff;
            System.out.println("offset: " + offset);
            return offset;
        } else {
            /* not a pointer */
            System.out.println("not a pointer!");
            return -1;
        }
    }

    private int decodeRecord(int startIndex) {
        int pointer = isPointer(startIndex);
        String hostname = "";
        if (pointer != -1) {
            /* pointer */
            // System.out.println("pointer offset: " + pointer);
            // hostname = getNameAtOffset(pointer);
            hostname = readNameAtOffsetExperiment(pointer);
            // System.out.println("hostname: " + hostname);
            startIndex = startIndex + 2;
        } else {
            /* not a pointer */
            // hostname = getNameAtOffset(startIndex);
            hostname = readNameAtOffsetExperiment(startIndex);
            // System.out.println("hostname: " + hostname);
            startIndex = startIndex + hostname.length() + 2; // TODO: test
        }

        RecordType type = RecordType.getByCode(decodeBytesToInt(startIndex, ++startIndex));
        // System.out.println("type: " + type);
        startIndex++;
        int rclass = decodeBytesToInt(startIndex, ++startIndex);
        // System.out.println("class: " + rclass);
        startIndex++;
        byte[] ttlBytes = Arrays.copyOfRange(resultArray, startIndex, startIndex + 4);
        int ttl = ByteBuffer.wrap(ttlBytes).getInt();
        // System.out.println("ttl: " + ttl);
        startIndex = startIndex + 4;
        int rlength = decodeBytesToInt(startIndex, ++startIndex);
        // System.out.println("rlength: " + rlength);
        startIndex++;
        // System.out.println("last index: " + startIndex);

        String result = getRecordResultBasedOnRecordType(startIndex, rlength, type, rclass);
        startIndex = startIndex + rlength;
        System.out.println("end of cname: " + startIndex);

        ResourceRecord record = new ResourceRecord(hostname, type, ttl, result);
        // /* add record to recordSet and cache */
        setOfRecords.add(record);
        cache.addResult(record);
        System.out.println("result is:" + result);
        // // TODO how to test record added to the cache
        // System.out.println(cache.getCachedResults(record.getNode()));
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
        System.out.println("host address: " + sb.toString());

        System.out.println("startIndex after host address  " + startIndex);
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
        System.out.println("startIndex after AAAA address  " + startIndex);
        return sb.toString();
    }

    private String readCNameResultExp(int startIndex, int length) {
        String hostname = readNameAtOffsetExperiment(startIndex);
        return hostname;
    }

//    private String readCNameResult(int startIndex, int length) {
//        int endIndex = startIndex + length;
//        StringBuilder sb = new StringBuilder();
//        while (startIndex < endIndex) {
//            System.out.println("startIndex in CNAME -- a: " + startIndex);
//            int pointer = isPointer(startIndex);
//            String hostname = "";
//            if (pointer != -1) {
//                /* pointer */
//                System.out.println("CNAME pointer offset: " + pointer);
//                hostname = readNameAtOffsetExperiment(pointer);
//                System.out.println("CNAME hostname: " + hostname);
//                startIndex = startIndex + 2;
//                System.out.println("startIndex in CNAME -- b: " + startIndex);
//            } else {
//                /* not a pointer */
//                hostname = readNameAtOffsetExperiment(startIndex);
//                System.out.println("not a pointer startindex: " + startIndex);
//                System.out.println("CNAME hostname: " + hostname);
////                if (resultArray[startIndex] == 0) {
////                    /* ends with 0x00 */
////                    /*
////                     * hostname ended with 0x00, increment the index twice to account for one
////                     * missing "." at the end, and the 0x00 byte following that
////                     */
////                    startIndex = startIndex + hostname.length() + 2;
////                    System.out.println("startIndex in CNAME -- c: " + startIndex);
////                } else {
////                    /*
////                     * hostname ended with a pointer, simply add the length because all length bytes
////                     * were replaced by added "."s (there's a trailing "." since a pointer name will
////                     * be appended after this)
////                     */
////                    startIndex = startIndex + hostname.length() + 1;
////                    hostname = hostname + readNameAtOffsetExperiment(startIndex);
////                    startIndex = startIndex + hostname.length() + 1;
////                    System.out.println("startIndex in CNAME -- d: " + startIndex);
////                }
//                startIndex += length;
//            }
//            sb.append(hostname);
//            System.out.println("appended: " + hostname);
//        }
//        System.out.println("final index when leaving cname stuff: " + startIndex);
//        return sb.toString();
//    java -jar $(JARFILE) 199.7.83.42 -p1

//    private String trimStart(String value) {
//
//    }

    private String getHexString(byte firstB, byte secondB) {
        String input = String.format("%02x%02x", firstB, secondB);
        input =input.replaceFirst("^0+", "");
        // input = inp ut.stripLeading("0");
        System.out.println(input);
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
                    System.out.println("PARAMS TO CNAME: " + startIndex + " " + rlength);
                    String res = readCNameResultExp(startIndex, rlength);
                    System.out.println("end result!!!!: " + res);
                    return res;
                    // System.out.println("a bit of hacking here: ");
                    // System.out.println("PARAMS TO CNAME: " + 79 + " " + 9);
                    // res = readCNameResult(79, 9);
                    // System.out.println("end result!!!!: " + res);
                }
                break;
            case 28:
                System.out.println("Type AAAA record");
                if (rclass == 1) {
                    System.out.println("PARAMS TO AAAA: " + startIndex + " " + rlength);
                    String res = readTypeAAResult(startIndex, rlength);
                    System.out.println("end result for AAAA record!!!!: " + res);
                    return res;
                }
                break;
            default:
                return "";
        }
        return "";
    }

}
