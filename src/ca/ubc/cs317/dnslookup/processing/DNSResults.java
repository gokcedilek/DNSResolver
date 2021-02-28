/* added by us */
package ca.ubc.cs317.dnslookup.processing;

import java.util.Set;

import ca.ubc.cs317.dnslookup.DNSNode;
import ca.ubc.cs317.dnslookup.ResourceRecord;

/* represents an object that can be cached */
public class DNSResults {
  /* fields to be cached */
  private DNSNode node;
  private Set<ResourceRecord> records;

  /* other fields */
  private int transactionId;
  private int ancount;
  private int nscount;
  private int arcount;

  public void setDNSNode(DNSNode node) {
    this.node = node;
  }

}
