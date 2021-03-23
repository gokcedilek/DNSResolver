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

    /* convert the DNS server response to a byte array */
    public DNSByteResults(ByteBuffer buffer) {
        resultBuffer = buffer;
        resultArray = buffer.array();
        setOfRecords = new HashSet<ResourceRecord>();
    }

    public Set<ResourceRecord> decodeByteResult(boolean verboseTracing) {
        /* rcode != 0 means there was an error */
        int rcode = decodeRCode();
        if (rcode != 0) {
            return Collections.emptySet();
        }

        /* bytes 0 & 1 is response ID */
        int rid = decodeBytesToInt(0, 1);
        /* bytes 4 & 5 is num entries in question section */
        qdcount = decodeBytesToInt(4, 5);
        /* bytes 6 & 7 is num entries in answer section */
        ancount = decodeBytesToInt(6, 7);
        /* bytes 8 & 9 is num entries in authority section */
        nscount = decodeBytesToInt(8, 9);
        /* bytes 6 & 7 is num entries in additional section */
        /* note: additional section provides IPs for entries in the authority section */
        /* memory aid: dig +norecurse @199.7.83.42 www.ugrad.cs.ubc.ca */
        arcount = decodeBytesToInt(10, 11);

        /* decode QNAME, QTYPE, QCLASS */
        int ind = decodeQuestion(12);

        /*
         * read the Authoritative bit (if the responding name server is an authoritative
         * name server for the domain name being queried)
         */
        if (verboseTracing) {
            System.out.printf("Response ID: %d Authoritative = %s\n", rid, decodeAA());
        }

        /* decode records in the answer section */
        if (verboseTracing) {
            System.out.printf("Answers (%d)\n", ancount);
        }
        for (int i = 0; i < ancount; i++) {
            ind = decodeRecord(ind, verboseTracing);
        }

        /* decode records in the authority section */
        if (verboseTracing) {
            System.out.printf("Nameservers (%d)\n", nscount);
        }
        for (int i = 0; i < nscount; i++) {
            ind = decodeRecord(ind, verboseTracing);
        }

        /* decode records in the additional section */
        if (verboseTracing) {
            System.out.printf("Additional Information (%d)\n", arcount);
        }
        for (int i = 0; i < arcount; i++) {
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

    /* decode QNAME, QTYPE, QCLASS */
    /* note QNAME is the original domain name that was queried */
    /* QTYPE is the type of the record (see RecordType.java) */
    private int decodeQuestion(int startIndex) {
        byte length = 0;
        StringBuilder sb = new StringBuilder();
        do {
            /* each "section" of QNAME starts with length */
            length = resultArray[startIndex++];

            /* QNAME terminates with a 0 byte, so break, and then read QTYPE */
            if (length == 0)
                break;

            /* read length number of bytes, which is one "section" of the domain name */
            byte[] domain = new byte[length];
            for (int i = 0; i < (int) length; i++) {
                domain[i] = resultArray[startIndex++];
            }
            String domainName;
            try {
                /* append a "section" to domain name */
                domainName = new String(domain, "US-ASCII");
                sb.append(domainName);
                sb.append(".");
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } while (length != 0);
        /* delete the last . (ex: www.cs.ubc.ca.) */
        if (sb.length() > 0) {
            sb = sb.deleteCharAt(sb.length() - 1);
        }

        int qtype = decodeBytesToInt(startIndex, ++startIndex);

        /*
         * construct the node field, which represents the original question (domain name
         * that was queried)
         */
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
                startIndex = resultArray[startIndex + 1];
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

    /*
     * each record contains NAME (possibly compressed - see isPointer), TYPE, CLASS,
     * TTL, RDLENGTH, RDATA
     */
    private int decodeRecord(int startIndex, boolean verboseTracing) {
        int pointer = isPointer(startIndex);
        String hostname = "";
        if (pointer != -1) {
            /* pointer */
            hostname = readNameAtOffsetExperiment(pointer);
            /* pointer only takes 2 bytes, increment by 2 bytes */
            startIndex = startIndex + 2;
        } else {
            /* not a pointer */
            hostname = readNameAtOffsetExperiment(startIndex);
            /*
             * if hostname isn't compressed, e.g. www.cs.ubc.ca, observe that we need to
             * increment by hostname length + 2 bytes, because there's an extra 0 byte at
             * the end of the hostname that we need to skip over, AND there's an extra byte
             * for the length of each "section" in the hostname that is not accounted by the
             * "."s in the hostname
             */
            /*
             * example: www.cs.ubc.ca has length 13, its decoded version 03 77 77 77 02 63
             * 73 03 75 62 63 02 63 61 00 has length 15!
             */
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

        /* read rdata */
        String result = getRecordResultBasedOnRecordType(startIndex, rlength, type, rclass);
        startIndex = startIndex + rlength;

        /*
         * ResourceRecord has 2 constructors - either we have an IPv4 or IPv6
         * InetAddress (if), or we have a string domain name (else) as the data of the
         * record
         */
        if (type == RecordType.A || type == RecordType.AAAA) {
            try {
                InetAddress addressInet = InetAddress.getByName(result);
                ResourceRecord record = new ResourceRecord(hostname, type, ttl, addressInet);
                setOfRecords.add(record);
            } catch (UnknownHostException e) {
                System.err.println("Invalid root server (" + e.getMessage() + ").");
                System.exit(1);
            }
        } else {
            ResourceRecord record = new ResourceRecord(hostname, type, ttl, result);
            setOfRecords.add(record);
        }
        if (verboseTracing) {
            if (result.equals("")) {
                result = "----";
            }
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
            startIndex += 2;
            sb.append(section);
            sb.append(":");
            addressLength = addressLength - 2;
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
        input = input.replaceFirst("^0+", "");
        if (input.equals("")) {
            return "0";
        } else {
            return input;
        }
    }

    /* read a type A, AAAA, or CNAME record */
    private String getRecordResultBasedOnRecordType(int startIndex, int rlength, RecordType type, int rclass) {
        int typeCode = type.getCode();
        switch (typeCode) {
        case 1:
            /* class IN */
            if (rclass == 1) {
                return readTypeAResult(startIndex, rlength);
            }
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
