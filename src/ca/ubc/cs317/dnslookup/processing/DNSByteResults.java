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
    // TODO: qclass?
    return ++startIndex;
  }

}
