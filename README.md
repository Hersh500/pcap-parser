What is working so far:

    I am able to parse simple pcap files and pass flow information to R.
    There are some tricky packet headers (with 802.1q VLAN and some other
        stuff I don't know) I am not able to parse as yet.
    R Interface works as follows:
        read_pcap_file(filename, print_debug_info)
            This creates flow table which is available in C world.
            I support parsing only 1 pcap file for now.
        get_flow_table()
            This prints the flow table with flow_id per flow.
        flow <- get_flow_info(flow_id)
            This creates flow data frame in R for the particular flow.
        As an example of how to access/plot information for the flow I provide
        two functions
            plot_flow_initiator_seq (flow)
        &   plot_flow_responder_seq (flow)

        These plot timestamps on x-axis and tcp sequence num on y-axis for two
        directions of the flow (initiator = side that sent first syn).

    Working on:
        Plot flows Src and Dst on Google Map based on Geo IP database lookup.


Following assumes you have already installed R. I tested this with R-2.13.1.

1. to install:
    tar -xzvf pcap_r.tar.gz

2. to compile:
    cd pcap_r
    R CMD SHLIB pcap_parser.c

3. to run:
    start R from pcap_r
    > source ("pcap.R")
    > read_pcap_file ("test.pcap", 0)
    > get_flow_table()
    > flow <- get_flow_info (0)
    > plot_flow_responder_seq (flow)
