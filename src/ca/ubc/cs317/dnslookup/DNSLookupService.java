package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.Set;
import java.util.stream.Collectors;

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
        // TODO (PART 1/2): Implement this
        // ANS is cname query --> increment by 1, call getResults again
        // only call this one again if ans is cname
//        retrieveResultsFromServer(node, rootServer);
        // cache? check for CNAME
        // loop through cache

        // check whether things are cached
        // if not, iterative query
        // first thing to do here is to check cache before retrieve results

        for (ResourceRecord record : cache.getCachedResults(node)) {
            // check if answer and not CNAME
            System.out.printf("Record!: %-30s %-5s %-8d %s\n", node.getHostName(), record.getNode().getType(),
                    record.getTTL(), record.getTextResult());
            // if we found the answer
            if ((node.getHostName().equals(record.getNode().getHostName()))) {
                // if we dont have cname
                if (record.getNode().getType() != RecordType.CNAME) {
                    System.out.printf("ANSWER found: %-30s %-5s %-8d %s\n", node.getHostName(),
                            record.getNode().getType(), record.getTTL(), record.getTextResult());
                    return cache.getCachedResults(node);
                } else {
                    DNSNode newNodeCNAME = new DNSNode(record.getTextResult(), RecordType.CNAME);
                    return getResults(newNodeCNAME, indirectionLevel + 1);
                }
            }
        }

        System.out.println("No answer yet");
        retrieveResultsFromServer(node, rootServer);
        ArrayList<ResourceRecord> cnames =
                cache.getCachedResults(node).stream().filter(rr -> (rr.getType() == RecordType.CNAME)).collect(toCollection(ArrayList::new));
        // ERROR TO FIX!!!!!!!!!!!!!!!

        if (cnames.size() > 0) {
             // found our cname answer
            DNSNode newNodeCNAME = new DNSNode(cnames[0].getHostName(),
                    RecordType.CNAME);
            return getResults(newNodeCNAME, indirectionLevel + 1);
        }

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

            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(), cache);
            // edit
            System.out.println("retrieveResultsfromserver cache size: " + cache.getCachedResults(node).size());
            System.out.println("nameservers size: " + nameservers.size());
            // end of edit

            if (nameservers == null)
                nameservers = Collections.emptySet();

            if (p1Flag)
                return; // For testing part 1 only

            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored) {
        }
    }

    // retrieve calls queryNext level
    // qnl: decide if we should call retrieveresultsfromserver, ows stop

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to
     *                    query the next level.
     */
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        // declare indirectionlevel = 0
        // getResults(indirectionlevel+1) when you get a cname answer

        // answer, nameserver, additional --> only cache addresses not names

        // if we dont have answer AND we find A or AAAA, call it nextNS -->
        // retrieveResultsFromServer
        // (node, nextNS)
        // if we dont have answer AND we dont have A / AAAA --> getResults
        // (one of the NSs, 0) query for the IP of one of the NSs --> loop
        // over all NSs, if one of them returns nonempty, we have answer -->
        // retrieveResultsFromServer(node, one of the IPs we got as the answer)

        // TODO (PART 2): Implement this
        System.out.println("in queryNextLevel");
        // printResults(node, nameservers)
        for (ResourceRecord record : nameservers) {
            System.out.printf("question: %s, answer: %s, node type: %s, " +
                            "record type: %s, text result: %s, inet result: " +
                            "%s " +
                            "\n",
                    node.getHostName(), record.getNode().getHostName(),
                    record.getNode().getType(), record.getType(),
                    record.getTextResult(), record.getInetResult());

//            // we have an answer
            if ((node.getHostName().equals(record.getNode().getHostName()))) {
                System.out.printf("QUERY NEXT LEVEL ANSWER: %-30s %-5s %-8d %s\n", node.getHostName(),
                            record.getType(), record.getTTL(), record.getTextResult());
                System.out.println("SHOULD STOP SEARCHING HERE");
                return;
//                if (record.getType() != RecordType.CNAME) {
//                    System.out.printf("QUERY NEXT LEVEL ANSWER: %-30s %-5s %-8d %s\n", node.getHostName(),
//                            record.getType(), record.getTTL(), record.getTextResult());
//                    return;
//                } else {
//                    // how to increment indirectionLevel? recurse
//                    System.out.println("we have a CNAME answer???");
//                    return;
//                }
            }
        }

        // start the ip of ns --> check all of the ns's --> see if we find an
        // IP --> start a new query for that domain name ~ similar to cname
        // cname -- stop when we find an answer
        // nameserver -- when we find an naswer, need to communicate to
        // original query

        Set<ResourceRecord> nextServersTypeA = nameservers.stream().filter(rr -> ((rr.getType() == RecordType.A) || (rr.getType() == RecordType.AAAA))).collect(Collectors.toSet());
        if (nextServersTypeA.size() == 0) {
            Set<ResourceRecord> nextServersTypeNS =
                    nameservers.stream().filter(rr -> (rr.getType() == RecordType.NS)).collect(Collectors.toSet());
            printResults(node, nextServersTypeNS);
//            for (ResourceRecord record : nextServersTypeNS) {
//
//            }
        } else {
//            System.out.println("next server to use for the query: %s",
//                    nextServersTypeA.get(0));
            // retrieveResFromServer(node, nextServers.get(0));
            // for loop over nextServers one might not give an answer
            int count = 0;
            for (ResourceRecord record: nextServersTypeA) {
                System.out.printf("type A server loop: %d", count);
                count++;
                retrieveResultsFromServer(node,
                        record.getInetResult());
                // TODO ???
            }
        }


            // NSs
//            else {
//                // we have no answer yet (check type, break and use A or AAAA
//                // else )
//
//                // you see NS type and theres no A or AAAA below we should
//                // use the NS -->
//                //
//                if (record.getType() == RecordType.NS){
//                    Set<ResourceRecord> nextServers = nameservers.stream().filter(rr -> ((rr.getType() == RecordType.A) || (rr.getType() == RecordType.AAAA))).collect(Collectors.toSet());
//                    // if no remaining records with A or AAAA type then have to
//                    // use NS type for next query
//                    if (nextServers.size() == 0) {
//                        DNSNode newNode = new DNSNode(record.getTextResult(),
//                                record.getType());
////                        Set<ResourceRecord> resultsForNextServer =
////                        getResults(newNode, 0);
//                        System.out.println("we only have NS records");
//                        printResults(node, nameservers);
////                        printResults(newNode, resultsForNextServer);
//                    } else {
//                        System.out.println("we have A/AAAA later on!");
//                        continue;
//                    }
//                } else if(record.getType() == RecordType.A || record.getType() == RecordType.AAAA) {
//                    System.out.println("we found A!");
//                    System.out.printf("we will query %s with IP: %s",
//                            node.getHostName(), record.getInetResult());
////                    retrieveResultsFromServer(node, record.getInetResult());
//                }
//            }
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
