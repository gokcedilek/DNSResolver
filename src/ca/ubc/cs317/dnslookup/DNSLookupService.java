package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.stream.Collectors;

import ca.ubc.cs317.dnslookup.DNSNode;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println(
                    "where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("317LOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null)
                break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty())
                continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") || commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    } else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    } else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") || commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard
     * output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /* returns the cached answers for the originalNode param below */
    /* returning happens by modifying the answers set param below */
    /* originalNode: node we are looking for answers for */
    /* node: the current node we are querying (required for CNAME recursion) */
    private static void findAnswer(DNSNode originalNode, DNSNode node, Set<ResourceRecord> answers) {
        Set<ResourceRecord> combinedSet = new HashSet<ResourceRecord>();
        /* look at all the A, AAAA, CNAME records in the cache */
        combinedSet.addAll(cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.A)));
        combinedSet.addAll(cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.AAAA)));
        combinedSet.addAll(cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME)));

        /* loop over the cache */
        /*
         * if our hostname exists with type A / AAAA, the IP we are looking for has
         * already been cached, add it to the answers set!
         */
        /*
         * else if our hostname exists with type CNAME, look for the answers of the
         * CNAME value
         */
        for (ResourceRecord record : combinedSet) {
            if ((node.getHostName().equals(record.getHostName()))) {
                // hostname exists in the cache
                if (record.getType() == RecordType.A || record.getType() == RecordType.AAAA) {
                    answers.add(new ResourceRecord(originalNode.getHostName(), record.getType(), record.getTTL(),
                            record.getInetResult()));
                } else if (record.getType() == RecordType.CNAME) {
                    /* look for the answers of the CNAME value (which is another hostname) */
                    DNSNode cnameNode = new DNSNode(record.getTextResult(), RecordType.A);
                    findAnswer(originalNode, cnameNode, answers);
                }
            }
        }
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to
     *                         CNAME redirection. The initial call should be made
     *                         with 0 (zero), while recursive calls for regarding
     *                         CNAME results should increment this value by 1. Once
     *                         this value reaches MAX_INDIRECTION_LEVEL, the
     *                         function prints an error message and returns an empty
     *                         set.
     * @return A set of resource records corresponding to the specific query
     *         requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (p1Flag) { // For isolating part 1 testing only
            retrieveResultsFromServer(node, rootServer);
            return Collections.emptySet();
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        Set<ResourceRecord> answers = new HashSet<>();
        findAnswer(node, node, answers);
        /* if an answer(s) have been cached, simply return them from the cache! */
        if (answers.size() > 0) {
            return answers;
        }

        /*
         * query the domain name represented by node starting from the rootServer
         * (defined in the class)
         */
        retrieveResultsFromServer(node, rootServer);

        /* check if there are CNAMEs for this node in the cache */
        DNSNode d = new DNSNode(node.getHostName(), RecordType.CNAME);
        ArrayList<ResourceRecord> cnames = cache.getCachedResults(d).stream()
                .filter(rr -> (rr.getType() == RecordType.CNAME)).collect(Collectors.toCollection(ArrayList::new));
        if (cnames.size() > 0) {
            // found our cname answer
            /*
             * we now need to query for newNodeCNAME, which will give us the answer for the
             * original query, because the IP we are looking for is the same as the IP of
             * the CNAME for the original query
             */
            DNSNode newNodeCNAME = new DNSNode(cnames.get(0).getTextResult(), RecordType.A);

            /* if the answer for this CNAME has been cached, return from cache */
            answers = new HashSet<>();
            findAnswer(newNodeCNAME, newNodeCNAME, answers);
            if (answers.size() > 0) {
                return answers;
            } else {
                /*
                 * else, initiate a brand new query to query for the CNAME, note we increment
                 * indirectionLevel by 1 so that we can eventually cut-off the query if we get
                 * too many CNAMEs. also note the answer to the original query is the same as
                 * the answer to the CNAME.
                 */
                return getResults(newNodeCNAME, indirectionLevel + 1);
            }
        }

        /*
         * if there are no CNAMEs for this node in the cache, we must have found the
         * answer, return it from the cache!
         */
        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in
     * iterative mode, and the query is repeated with a new server if the provided
     * one is non-authoritative. Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes

        try {

            DNSServerResponse serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node);

            /* get all the ResourceRecord instances for the query */
            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(), cache);

            if (nameservers == null)
                nameservers = Collections.emptySet();

            if (p1Flag)
                return; // For testing part 1 only

            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored) {
        }
    }

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to
     *                    query the next level.
     */
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        for (ResourceRecord record : nameservers) {
            /* if we found type A / AAAA, great! we found an answer! */
            /*
             * if we found type CNAME, we need to initiate a brand new query, so instead of
             * "querying next level", which means querying the IP of an NS record / an
             * authoritative server, exit (we will then initiate a brand new query)
             */
            if ((node.getHostName().equals(record.getHostName())) && (record.getType() == RecordType.A
                    || record.getType() == RecordType.AAAA || record.getType() == RecordType.CNAME)) {
                return;
            }
        }

        /* find the type A records in the result */

        /*
         * , because if we have any type As for the NSs, we can simply send our original
         * query to that IP (the new DNS server).
         */
        ArrayList<ResourceRecord> nextServersTypeA = nameservers.stream().filter(rr -> (rr.getType() == RecordType.A))
                .collect(Collectors.toCollection(ArrayList::new));

        /*
         * case 1: there are no type A records among the NSs. this means that we don't
         * have an IP we can immediately use as the "next level server" to ask our
         * original query/domain name.
         */
        if (nextServersTypeA.size() == 0) {
            // we just have NSs
            ArrayList<ResourceRecord> nextServersTypeNS = nameservers.stream()
                    .filter(rr -> (rr.getType() == RecordType.NS)).collect(Collectors.toCollection(ArrayList::new));
            if (nextServersTypeNS.size() == 0) {
                return;
            }
            /* get the first NS randomly, any one should do */
            DNSNode newNSNode = new DNSNode(nextServersTypeNS.get(0).getTextResult(), RecordType.A);

            /*
             * check if the IP for this NS (domain name) has been cached. if yes, query for
             * the original domain name using the IP of this new NS as the nameserver.
             */
            Set<ResourceRecord> answers = new HashSet<>();
            findAnswer(newNSNode, newNSNode, answers);
            if (answers.size() > 0) {
                retrieveResultsFromServer(node, answers.iterator().next().getInetResult());
            } else {
                /*
                 * if IPs for this NS have not been cached, we will have to initiate a brand new
                 * query for the IP of newNSNode, and then query for the original domain name
                 * using the IP we found for this new NS, same as above.
                 */
                Set<ResourceRecord> resultsForNS = getResults(newNSNode, 0);
                if (resultsForNS.size() == 0) {
                    return;
                }
                retrieveResultsFromServer(node, resultsForNS.iterator().next().getInetResult());
            }
        }
        /*
         * case 2: there are type A records among the NSs. this means that we have an IP
         * we can immediately use as the "next level server" to ask our original
         * query/domain name.
         */
        else {
            retrieveResultsFromServer(node, nextServersTypeA.get(0).getInetResult());
        }
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), record.getTTL(),
                    record.getTextResult());
        }
    }
}
