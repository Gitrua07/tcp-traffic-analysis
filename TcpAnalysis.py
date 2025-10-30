import struct
import sys
import IPPacket

def getCapFile(file):
    """
    Parses cap file provided by PCAP_FILE

    Returns:
        ip_packet_list: Parsed cap file
    """
    #parse using struct
    ip_packet_list = []
    with open(file, 'rb') as f:
        #Reads TCP Header
        global_header = f.read(24) #Retrieves global header
        if len(global_header) < 24: #If global header is less than 24 bytes
            print("Incomplete global header")
            exit(1)
    
        #Finds if PCAP is big-endian or little-endian
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big == 0xa1b2c3d4 or magic_big == 0xa1b23c4d:
            endian = '>' #big-endian
        elif magic_little == 0xa1b2c3d4 or magic_little == 0xa1b23c4d:
            endian = '<' #little-endian
        else:
            print("Unnown magic number, cannot determine endianness")
            exit(1)

        #Reads packet header
        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break

            #Retrieve header values
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print("Incomplete packet data")
                break

            ip_packet = IPPacket.IPPacket.from_bytes(packet_data[14:])
            ip_packet_list.append((ts_sec, ts_usec, ip_packet))
    
    return ip_packet_list

def parseData(partB):
    """
    Obtains and returns data of cap file

    Returns:
        connections: Tuple of four showing source, destination address and source, destination port
        time_list: A triplet with the start time, end time, and duration
        nums_packet: Contains a triplet with number of source, destination, total packets
        num_data: Contains a triplet with number of source, destination, total bytes
        statuses: Contains list of text showing number of SYN, FIN and if it contains an RST
        rtt_list: Contains a list of RTT values 
        window_sizes: Contains a dictionary of window sizes including "to" and "from" TCP connections
        estab_before: Contains a value showing the number of connections established before the connection began

    """

    connections = {}
    num_data = []
    window_sizes = {}
    seq_nums = {}
    ack_nums = {}
    packets_count = {}
    time_list = []
    statuses = []
    data_len = []
    rtt_list = []
    time_sent_list = {}
    time_ack_list = {}

    connection_id = 0
    estab_before = 0
    first_time = partB[0][0] + (partB[0][1]/1_000_000)

    #Loop deconstructs ip packet and obtains elements in packet 
    for ip_packet in partB:
        packet = ip_packet[2]
        payload = packet.payload #Get the Packet Data

        src_port, dst_port = struct.unpack('!HH', payload[:4])
        seq_num = struct.unpack('!I', payload[4:8])
        window_size = struct.unpack('!H', payload[14:16])[0]
        ack_num = struct.unpack('!I', payload[8:12])[0]
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        tcp_segment = payload
        flags = tcp_segment[13]

        #Establish both direction connections
        connection_to = (src_ip, src_port, dst_ip, dst_port)
        connection_from = (dst_ip, dst_port, src_ip, src_port) 

        #New SYN detected, create new connection
        if (flags & 0x02) and (connection_to in connections or connection_from in connections):
            connection_id += 1
            connection_to = (src_ip, src_port, dst_ip, dst_port, connection_id)

        #Append packet values to matching connections
        if connection_to in connections:
            connections[connection_to].append(ip_packet)
            seq_nums[connection_to].append(seq_num)
            ack_nums[connection_to].append(ack_num)
            window_sizes[connection_to].append(window_size)
            packets_count[connection_to][0] += 1
        elif connection_from in connections:
            connections[connection_from].append(ip_packet)
            seq_nums[connection_from].append(seq_num)
            ack_nums[connection_from].append(ack_num)
            window_sizes[connection_from].append(window_size)
            packets_count[connection_from][1] += 1
        else:
            connections[connection_to] = [ip_packet]
            seq_nums[connection_to] = [seq_num]
            ack_nums[connection_to] = [ack_num]
            window_sizes[connection_to] = [window_size]
            packets_count[connection_to] = [1,0]

    #Looks through each connection in packet
    for key, packet in connections.items():

        #Find the time stamp: start time, end time, duration
        time_stamp = [
            sec_time + (usec_time/1_000_000) - first_time
            for sec_time, usec_time, data in packet
        ]
        start_time = min(time_stamp)
        end_time = max(time_stamp)
        duration = end_time - start_time
        times = (start_time, end_time, duration)
        time_list.append(times)

        ack = ack_nums[key]
        seq = seq_nums[key]
        index = 0

        #Find number of data bytes
        num_of_data_bytes_src_dst = 0
        num_of_data_bytes_dst_src = 0
        total_num_of_data_bytes = 0
        status = ""
        is_rst = False
        syn_count = 0
        fin_count = 0
        syn_cont = []
        is_data_len = False

        #Go through each individual packet
        for sec_time, usec_time, data in packet:
            time_stamp = sec_time + (usec_time/1_000_000) 
            tcp_segment = data.payload
            flags = tcp_segment[13]

            if flags & 0x02:
                syn_count += 1
                syn_cont.append("SYN")
            else:
                syn_cont.append("NO SYN")
            if flags & 0x01:
                fin_count += 1
                syn_cont.append("FIN")
            if flags & 0x10:
                is_ack = True
                syn_cont.append("ACK")

            seq_number = seq[index][0]
            ack_number = ack[index]
            header_length = (tcp_segment[12] >> 4) * 4
            data_length = len(tcp_segment) - header_length
            seq_end = data_length + seq_number

            #Intializes time sent for both ack and sequence time
            time_sent_list[seq_end] = sec_time + (usec_time/1_000_000) 
            time_ack_list[ack_number] = sec_time + (usec_time/1_000_000)
            index += 1

            #Counts bytes and calculates RTT value
            if data.src_ip == key[0] and data.src_ip != key[2]:
                time_sent_list[seq_end] = time_stamp
                num_of_data_bytes_src_dst += data_length
            else: 
                num_of_data_bytes_dst_src += data_length
                if ack_number in time_sent_list:
                    rtt = time_stamp - time_sent_list[ack_number]
                    rtt_list.append(rtt)
            
            #Breaks connection when there is a RST flag detected
            if flags & 0x04:
                is_rst = True
                syn_cont.append("RST")
                break

        #If Packet did not start with SYN then it was established before connection began
        if syn_cont[0] != 'SYN':
            estab_before += 1

        #Create status
        status += f'S{syn_count}F{fin_count}'
        if is_rst:
            status += " R"
        statuses.append(status)

        #Insert data byte information
        total_data_bytes = num_of_data_bytes_dst_src + num_of_data_bytes_src_dst
        num_data.append((num_of_data_bytes_src_dst, num_of_data_bytes_dst_src, total_data_bytes))

    #Calculate number of packets
    nums_packet = [
        (src, dst, src + dst)
        for key, (src, dst) in packets_count.items()
    ]

    return (connections, time_list, nums_packet, num_data, statuses, rtt_list, window_sizes, estab_before)

def getConnectionsDetails(connections, time_list, num_packets, num_data, statuses):
    """
    Output connection details

    Returns:
        output: String outputting connection details per connection
    """
    count = 0
    output = ''
    for key, packet_list in connections.items():
        output += f'\nConnection: {count+1}'
        output += f'\nSource Address: {key[0]}\n'
        output += f'Destination Address: {key[2]}\n'
        output += f'Source Port: {key[1]}\n'
        output += f'Destination Port: {key[3]}\n'
        output += f'Status: {statuses[count]}\n'
        output += f'Start Time: {time_list[count][0]} seconds\n'
        output += f'End Time: {time_list[count][1]} seconds\n'
        output += f'Duration: {time_list[count][2]} seconds\n'
        output += f'Number of packets sent from Source to Destination: {num_packets[count][0]}\n'
        output += f'Number of packets sent from Destination to Source: {num_packets[count][1]}\n'
        output += f'Total number of packets: {num_packets[count][2]}\n'
        output += f'Number of data bytes sent from Source to Destination: {num_data[count][0]}\n'
        output += f'Number of data bytes sent from Destination to Source: {num_data[count][1]}\n'
        output += f'Total number of data bytes: {num_data[count][2]}\n'
        output += f'END\n'
        output += f'+++++++++++++++++++++++++++++++++\n'

        count += 1
    return output

def getGeneralInfo(connections, statuses, estab_before):
    """
    Outputs general information about TCP connection

    Returns:
        output: String of information about TCP connection
    """
    is_complete = 0
    is_reset = 0
    is_open = 0

    for status in statuses:
        if ('S1' in status or 'S2' in status) and ('F1' in status or 'F2' in status):
            is_complete += 1
        if 'R' in status:
            is_reset += 1
        if 'F0' in status and 'R' not in status and 'S0' not in status:
            is_open += 1

    output = f'Total Number of complete TCP Connections: {is_complete}\n'
    output += f'The number of reset TCP connections: {is_reset}\n'
    output += f'The number of TCP connections that were still open when the trace capture ended: {is_open}\n'
    output += f'The number of TCP connections established before the capture started: {estab_before}\n'
    return output

def getCompleteConnections(partD, time_list, rtt_list, window_sizes, num_packets):
    """
    Calculates and outputs the complete TCP connection information

    Returns:
        output: String of information about TCP complete connections
    """

    #Calculate duration
    d = [
        duration
        for start_time, end_time, duration in time_list
    ]

    min_time_d = min(d)
    max_time_d = max(d)
    mean_time_d = sum(d)/len(d)

    output = f'Minimum time duration: {min_time_d}\n'
    output += f'Mean time duration: {mean_time_d}\n'
    output += f'Maximum time duration: {max_time_d}\n'
    output += f'\n'

    #Calculate RTT value
    min_rtt = min(rtt_list)
    max_rtt = max(rtt_list)
    mean_rtt = sum(rtt_list)/len(rtt_list)

    output += f'Minimum RTT value: {min_rtt}\n'
    output += f'Mean RTT value: {mean_rtt}\n'
    output += f'Maximum RTT value: {max_rtt}\n'
    output += f'\n'

    #Calculate packet numbers
    packet_nums = [
        num_packets[count][0] + num_packets[count][1]
        for count in range(0,len(num_packets))
    ]

    min_packet = min(packet_nums)
    max_packet = max(packet_nums)
    mean_packet = sum(packet_nums)/len(packet_nums)

    output += f'Minimum number of packets including both send/received: {min_packet}\n'        
    output += f'Mean number of packets including both send/received: {mean_packet}\n'
    output += f'Maximum number of packets including both send/received: {max_packet}\n'
    output += f'\n'

    #Calculate window size
    min_window_size = 0
    max_window_size = 0
    mean_window_size = 0
    for key, win_to in window_sizes.items():
        win_to_min = min(win_to)
        win_to_max = max(win_to)

        if win_to_min < min_window_size:
            min_window_size = win_to_min
        if win_to_max > max_window_size:
            max_window_size = win_to_max

    sum_win = [
        sum(win_to)
        for key, win_to in window_sizes.items()
    ]

    mean_window_size = sum(sum_win)/len(window_sizes)

    output += f'Minimum receive window size including both send/received: {min_window_size}\n'
    output += f'Mean receive window size including both send/received: {mean_window_size}\n'
    output += f'Maximum receive window size including both send/received: {max_window_size}\n'

    return output

def printOutput(A, B, C, D):
    """
    Outputs the results of the TCP Analysis

    """
    #Part A
    print(f'A) Total number of connections:\n --------------------------------\n')
    print(A)
    #Part B
    print(f"\nB) Connections' details: \n --------------------------------\n")
    print(B)
    #Part C
    print(f'\nC) General: \n --------------------------------\n')
    print(C)
    #Part D
    print(f'\nD) Complete TCP connections: \n --------------------------------\n')
    print(D)

def main():
    #Get file input (tracefile)
    file = sys.argv[1]
    #Decode file input (Use struct.unpack(format type, file input bytes))
    packet = getCapFile(file)
    #Obtain packet data
    connections, time_list, num_packets, num_data, statuses, rtt_list, window_sizes, is_establish = parseData(packet)
    #Process data for part A
    A = len(connections)
    #Process data for part B
    B = getConnectionsDetails(connections, time_list, num_packets, num_data, statuses)
    #Process data for part C  
    C = getGeneralInfo(connections, statuses, is_establish)
    #Process data for part D
    D = getCompleteConnections(connections, time_list, rtt_list, window_sizes, num_packets)
    #Print all data
    printOutput(A, B, C, D)

if __name__ == "__main__":
    main()