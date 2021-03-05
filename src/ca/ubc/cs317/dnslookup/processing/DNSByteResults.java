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
    public Set<ResourceRecord> decodeByteResult(boolean verboseTracing) {
        int rcode = decodeRCode();
        if (rcode != 0) {
            return Collections.emptySet();
        }
        int rid = decodeBytesToInt(0, 1);
        qdcount = decodeBytesToInt(4, 5);
        ancount = decodeBytesToInt(6, 7);
        nscount = decodeBytesToInt(8, 9);
        arcount = decodeBytesToInt(10, 11);
        int ind = decodeQuestion(12);
        if (verboseTracing) {
            System.out.printf("Response ID: %d Authoritative = %s\n", rid, decodeAA());
        }
        if (verboseTracing) {
            System.out.printf("Answers (%d)\n", ancount);
        }
        for(int i = 0; i < ancount; i++) {
            ind = decodeRecord(ind, verboseTracing);
        }
        if (verboseTracing) {
            System.out.printf("Nameservers (%d)\n", nscount);
        }
        for(int i = 0; i < nscount; i++) {
            ind = decodeRecord(ind, verboseTracing);
        }
        if (verboseTracing) {
            System.out.printf("Additional Information (%d)\n", arcount);
        }
        for(int i = 0; i < arcount; i++) {
            ind = decodeRecord(ind, verboseTracing);
        }
        return setOfRecords;
    }
    private boolean decodeAA() {
        int AA = resultArray[2];
        AA = AA >> 2;
        AA = AA & 0xfff1;
        return AA == 1;
    }



    private int decodeRCode() {
        byte b = resultArray[3];
        int rcode = (0b1111) & b; // 00001111 & 00000101 == 00000101
        return rcode;
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
            length = resultArray[startIndex++];
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
//        System.out.println("domain name: " + sb.toString());
        int qtype = decodeBytesToInt(startIndex, ++startIndex);
//        System.out.println("q type: " + qtype);
        node = new DNSNode(sb.toString(), RecordType.getByCode(qtype));
        startIndex++;

        int qclass = decodeBytesToInt(startIndex, ++startIndex);
        return ++startIndex;
    }

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

    private int decodeRecord(int startIndex, boolean verboseTracing) {
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
        if (verboseTracing) {
            System.out.printf("       %-30s %-10d %-4s %s\n", hostname, ttl, type, result);
        }
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
                /* class IN */
                if (rclass == 1) {
                    return readTypeAResult(startIndex, rlength);
                }
                // TODO For the CH class, a domain name followed by a 16 bit octal Chaos
                // address.
                break;
            case 2:
            case 5:
                if (rclass == 1) {
                    String res = readCNameResultExp(startIndex, rlength);
                    return res;
                }
                break;
            case 28:
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
