/* added by us */
package ca.ubc.cs317.dnslookup.processing;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import ca.ubc.cs317.dnslookup.DNSNode;
import ca.ubc.cs317.dnslookup.RecordType;

public class DNSByteResults {
  private ByteBuffer resultBuffer;
  private byte[] resultArray;

  /* response fields */
  int qdcount;
  int ancount;
  int nscount;
  int arcount;
  DNSNode node;

  public DNSByteResults(ByteBuffer buffer) {
    resultBuffer = buffer;
    resultArray = buffer.array();
  }

  // return something?
  public void decodeByteResult() {
    decodeRCode();
    qdcount = decodeBytesToInt(4, 5);
    ancount = decodeBytesToInt(6, 7);
    nscount = decodeBytesToInt(8, 9);
    arcount = decodeBytesToInt(10, 11);
    int ind = decodeQuestion(12);
    System.out.println("last index is: " + ind);
    // TODO: if ans available return ans, else can return 0.0.0.0 as the IP

    // decode each record
    // int totals = ancount + nscount + arcount;
    // while (totals > 0) {
    //   decodeRecord(ind);
    //   totals--;
    // }

    decodeRecord(ind);
  }

  // dig +norecurse @199.7.83.42 finance.google.ca --> part1
  // part1: finance.google.ca no answer --> 0.0.0.0  + save decoded
  // part2: iterative lookup  --> just answer!

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
    System.out.println("result: " + count);
    return count;
  }
  // 0x00 0x04 --> 4
  // 0x00 0x01 --> 1

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
    sb = sb.deleteCharAt(sb.length()-1);
    System.out.println("domain name: " + sb.toString());
    int qtype = decodeBytesToInt(startIndex, ++startIndex);
    System.out.println("q type: " + qtype);
    node = new DNSNode(sb.toString(), RecordType.getByCode(qtype));
    startIndex++;
    
    //TODO store qclass?
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
    sb = sb.deleteCharAt(sb.length()-1);
    System.out.println("domain name: " + sb.toString());
    return sb.toString();
  }
  private int decodeRecord(int startIndex){
    // check for message compression - if first byte 11 (17 in int conversion)
    int firstByteAsInt = resultArray[startIndex];
    int shifted = resultArray[startIndex] >> 6;
    System.out.println(shifted);
    // 11 in binary is equivalent to -1 because int datatype is signed by default
    if (shifted == -1) {
      System.out.print(decodeBytesToInt(startIndex, startIndex+1));
      int offset = decodeBytesToInt(startIndex, startIndex+1) & 0x3fff;
      System.out.println(offset);
      String name = getNameAtOffset(offset);
      startIndex = startIndex + 2;
    } else {
      String name = getNameAtOffset(startIndex);
      // TODO how to increment startIndex in this case, maybe startIndex should be global
    }
    RecordType type = RecordType.getByCode(decodeBytesToInt(startIndex, ++startIndex));
    startIndex++;
    int rclass = decodeBytesToInt(startIndex, ++startIndex);
    startIndex++;
    System.out.println("index before ttl grab " + startIndex);
    byte[] ttlBytes = Arrays.copyOfRange(resultArray, startIndex, startIndex+4);
    int ttl = ByteBuffer.wrap(ttlBytes).getInt();
    System.out.println("ttlbytes length: " + ttlBytes.length);
    System.out.println("ttl: " + ttl);
    startIndex = startIndex + 4;
    int rlength = decodeBytesToInt(startIndex, ++startIndex);
    startIndex++;

    String result = getRecordResultBasedOnRecordType(startIndex, rlength, type, rclass);
    // byte shifted = (byte)((int) resultArray[startIndex]) >> 6);
    // System.out.print(String.format("0x%02X", shifted) + ", ");

    // if (firstByteAsInt == 17) {
    //   System.out.println("message compression");
    //   // c0 00 
    //   int offset = resultArray[startIndex++];
    // }
    return startIndex;
  }

//TODO
  private String getRecordResultBasedOnRecordType(int startIndex, int rlength, RecordType type, int rclass){
    int typeCode = type.getCode();
    switch(typeCode) {
      case 1:
        System.out.println("Type A record");
        break;
      case 2:
        System.out.println("Type NS record");
        break;
      case 5:
        System.out.println("Type CNAME record");
        break;
      case 28:
        System.out.println("Type AAAA record");
        break;
      default:
        return "";
    }
    return "";
  }

}
