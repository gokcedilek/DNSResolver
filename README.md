# Welcome to DNS resolver!

- Start the command-line program
  - `make run`
- Look up a domain name
  - `lookup x.x.x.x` (ex: `lookup www.cs.ubc.ca`)
- Set the root name server (optional, default is 199.7.83.42 which is close to UBC!)
  - `server x.x.x.x` (ex: `server 8.8.8.9`)
- Set verbose tracing on (optional, to print a trace of all queries and responses)
  - `trace on | off`
- Print the contents of the DNS cache (optional)
  - `dump`
- Quit
  - `quit`

## How to understand what is happening

This program is an iterative DNS resolver, meaning that the client repeatedly makes requests to DNS servers to resolve a domain name to an IP address (The code contains a lot of comments).
Here are two example lookups, which provide the corresponding [dig commands](https://linuxize.com/post/how-to-use-dig-command-to-query-dns-in-linux/#understanding-the-dig-output) for a live demo:

1. We can simulate `lookup www.cs.ubc.ca` as follows:

- `dig +norecurse @199.7.83.42 www.cs.ubc.ca`
- `dig +norecurse @185.159.196.2 www.cs.ubc.ca`
- `dig +norecurse @137.82.1.1 www.cs.ubc.ca`
- `dig +norecurse @137.82.61.120 www.cs.ubc.ca` &#8594; we got the answer 142.103.6.5!

2. We can simulate `lookup finance.google.ca` (which contains aliases) as follows:

- `dig +norecurse @199.7.83.42 finance.google.ca`
- `dig +norecurse @185.159.196.2 finance.google.ca`
- `dig +norecurse @199.7.83.42 ns3.google.com` &#8594; we needed to lookup the IP of an authoritative nameserver
- `dig +norecurse @192.33.14.30 ns3.google.com` &#8594; we got the answer 216.239.36.10 for the authoritative nameserver
- `dig +norecurse @216.239.36.10 finance.google.ca` &#8594; we got the answer 142.251.33.110!

Reference: https://www.ietf.org/rfc/rfc1035.txt
