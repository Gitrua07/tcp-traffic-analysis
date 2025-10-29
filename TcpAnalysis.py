import struct
import sys
import IPPacket

PCAP_FILE = './sample-capture-file.cap'

def getCapFile(file):
    #parse using struct
    ip_packet_list = []
    with open(PCAP_FILE, 'rb') as f:
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
    connections = {}
    num_packets = []
    num_data = []
    window_sizes = []
    seq_nums = {}
    ack_nums = {}
    num_packets_src_dst = 0
    num_packets_dst_src = 0

    for ip_packet in partB:
        packet = ip_packet[2]
        payload = packet.payload #Get the Packet Data

        src_port, dst_port = struct.unpack('!HH', payload[:4])
        seq_num = struct.unpack('!I', payload[4:8])
        window_size = struct.unpack('!H', payload[14:16])[0]
        ack_num = struct.unpack('!I', payload[8:12])[0]
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        #Establish both direction connections
        connection_to = (src_ip, src_port, dst_ip, dst_port)
        connection_from = (dst_ip, dst_port, src_ip, src_port) 

        #Append ip_packets to matching connections
        if connection_to in connections:
            connections[connection_to].append(ip_packet)
            seq_nums[connection_to].append(seq_num)
            ack_nums[connection_to].append(ack_num)
            num_packets_src_dst += 1
        elif connection_from in connections:
            connections[connection_from].append(ip_packet)
            seq_nums[connection_from].append(seq_num)
            ack_nums[connection_from].append(ack_num)
            num_packets_dst_src += 1
        else:
            connections[connection_to] = [ip_packet]
            seq_nums[connection_to] = [seq_num]
            ack_nums[connection_to] = [ack_num]
            #Append final count
            total_num_of_packets = num_packets_dst_src + num_packets_src_dst
            num_p = (num_packets_src_dst, num_packets_dst_src, total_num_of_packets)
            num_packets.append(num_p)
            window_sizes.append(window_size)
            #Reset num packet count
            num_packets_src_dst = 0
            num_packets_dst_src = 0
    
    time_list = []
    num_data = []
    statuses = []
    data_len = []
    rtt_list = []

    time_sent_list = {}
    time_ack_list = {}
    is_syn_count = 0
    is_fin_count = 0
    is_fin = 0
    estab_before = 0
    for key, packet in connections.items():
        #Find the time stamp: start time, end time, duration
        time_stamp = [
            sec_time + (usec_time/1_000_000)
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
            if flags & 0x04:
                is_rst = True
                syn_cont.append("RST")

            seq_number = seq[index][0]
            ack_number = ack[index]
            header_length = (tcp_segment[12] >> 4) * 4
            data_length = len(tcp_segment) - header_length
            if data_length > 0:
                is_data_len = True
            else:
                is_data_len = False
            seq_end = data_length + seq_number
            #Intializes time sent for both ack and sequence time
            time_sent_list[seq_end] = sec_time + (usec_time/1_000_000) 
            time_ack_list[ack_number] = sec_time + (usec_time/1_000_000)
            index += 1

            if data.src_ip == key[0] and data.src_ip != key[2]:
                time_sent_list[seq_end] = time_stamp
                num_of_data_bytes_src_dst += data_length
            else: 
                num_of_data_bytes_dst_src += data_length
                if ack_number in time_sent_list:
                    rtt = time_stamp - time_sent_list[ack_number]
                    rtt_list.append(rtt)
        

        if is_data_len == False:
            is_fin += 1
        
        if syn_cont[0] != 'SYN':
            estab_before += 1

        status += f'S{syn_count}F{fin_count}'
        #if is_syn & is_fin:
         #   status = "SYN + FIN"
        #elif is_rst:
         #   status = "RST"
        #elif is_ack & is_fin:
         #   status = "ACK + FIN"
        #elif is_ack:
         #   status = "ACK"
        #elif is_syn:
         #   status = "SYN"
        #else:
         #   status = "None"

        statuses.append(status)
        total_data_bytes = num_of_data_bytes_dst_src + num_of_data_bytes_src_dst
        num_data.append((num_of_data_bytes_src_dst, num_of_data_bytes_dst_src, total_data_bytes))
    return (connections, time_list, num_packets, num_data, statuses, rtt_list, window_sizes, is_fin, estab_before)

def getTotalConnections(partA):
    return partA

def getConnectionsDetails(connections, time_list, num_packets, num_data, statuses):
    count = 0
    output = ''
    for key, packet_list in connections.items():
        output += f'\nConnection: {count+1}'
        output += f'\nSource Address: {key[0]}\n'
        output += f'Destination Address: {key[2]}\n'
        output += f'Source Port: {key[1]}\n'
        output += f'Destination Port: {key[3]}\n'
        if statuses[count] == "SYN + FIN":
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

def getGeneralInfo(connections, statuses, is_fin, estab_before):
    is_complete = 0
    is_reset = 0

    for status in statuses:
        if ('S1' in status or 'S2' in status) and ('F1' in status or 'F2' in status):
            is_complete += 1
        if 'F0' in status:
            is_reset += 1

    output = f'Total Number of complete TCP Connections: {is_complete}\n'
    output += f'The number of reset TCP connections: {is_reset}\n'
    output += f'The number of TCP connections that were still open when the trace capture ended: {is_fin}\n'
    output += f'The number of TCP connections established before the capture started: {estab_before}\n'
    return output

def getPartD(partD, time_list, rtt_list, window_sizes, num_packets):
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

    min_rtt = min(rtt_list)
    max_rtt = max(rtt_list)
    mean_rtt = sum(rtt_list)/len(rtt_list)

    output += f'Mean RTT value: {mean_rtt}\n'
    output += f'Maximum RTT value: {max_rtt}\n'
    output += f'Minimum RTT value: {min_rtt}\n'
    output += f'\n'

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

    min_window_size = min(window_sizes)
    max_window_size = max(window_sizes)
    mean_window_size = sum(window_sizes)/len(window_sizes)

    output += f'Minimum receive window size including both send/received: {min_window_size}\n'
    output += f'Mean receive window size including both send/received: {mean_window_size}\n'
    output += f'Maximum receive window size including both send/received: {max_window_size}\n'


    return output

def printOutput(A, B, C, D):
    #Part A
   # print(f'A) Total number of connections:\n --------------------------------\n')
   # print(A)
    #Part B
    #print(f"\nB) Connections' details: \n --------------------------------\n")
   # print(B)
    #Part C
    #print(f'\nC) General: \n --------------------------------\n')
    #print(C)
    #Part D
   # print(f'\nD) Complete TCP connections: \n --------------------------------\n')
    print(D)

def main():
    #Get file input (tracefile)
    file = sys.argv[1]
    #Decode file input (Use struct.unpack(format type, file input bytes))
    packet = getCapFile(file)
    connections, time_list, num_packets, num_data, statuses, rtt_list, window_sizes, is_fin, estab_before = parseData(packet)
    #Process data for part A
    A = getTotalConnections(len(connections))
    #Process data for part B
    B = getConnectionsDetails(connections, time_list, num_packets, num_data, statuses)
    #Process data for part C  
    C = getGeneralInfo(connections, statuses, is_fin, estab_before)
    #Process data for part D
    D = getPartD(connections, time_list, rtt_list, window_sizes, num_packets)
    #Print all data
    printOutput(A, B, C, D)

if __name__ == "__main__":
    main()