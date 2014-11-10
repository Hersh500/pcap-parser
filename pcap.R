setwd("/Users/Hersh/Programming/Dell/pcap_parser")
dyn.load("pcap_parser.so")
.Call("read_pcap_file")

get_flow_table <- function () {
	src_ips <- .Call("get_src_ipaddr_vector")
	dst_ips <- .Call("get_dst_ipaddr_vector")
	src_ports <- .Call("get_src_port_vector")
	dst_ports <- .Call("get_dst_port_vector")
	start_time <- .Call("get_start_time_vector")
	flow_id <- .Call("get_flow_id_vector")

	flow_table <- data.frame (SrcIP = src_ips, DstIP = dst_ips, SrcPort = src_ports, DstPorts = dst_ports, 
                                    StartTime = start_time, FlowId = flow_id)
	return(flow_table)
}

get_flow_info <- function (flow_id) {
	src_timestamps <- .Call("get_src_timestamps_vector", flow_id)
	dst_timestamps <- .Call("get_dst_timestamps_vector", flow_id)
	src_ack_nums <- .Call("get_src_ack_nums_vector", flow_id)
	dst_ack_nums <- .Call("get_dst_ack_nums_vector", flow_id)
	src_seq_nums <- .Call("get_src_seq_nums_vector", flow_id)
	dst_seq_nums <- .Call("get_dst_seq_nums_vector", flow_id)
	flow_info <- data.frame (SrcTimeStamp = src_timestamps, DstTimeStamp = dst_timestamps, 
					SrcSeqNums = src_seq_nums, DstAckNums = dst_ack_nums,
					DstSeqNums = dst_seq_nums, SrcAckNums = src_ack_nums) 
	return(flow_info)	
}	

plot_flow_src_seq <- function (flow_info) {
	seq_nums <- (flow_info[flow_info$SrcSeqNums > 0,])$SrcSeqNums
	timestamp <- (flow_info[flow_info$SrcTimeStamp > 0,])$SrcTimeStamp
	plot(timestamp, seq_nums) 
}

get_spec_flow <- function (flow_table) {
	flow <- flow_table[flow_table$FlowId == 366,]
	return(flow) 
}
