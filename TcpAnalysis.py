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
    num_packets_src_dst = 0
    num_packets_dst_src = 0

    for ip_packet in partB:
        packet = ip_packet[2]

        payload = packet.payload #Get the Packet Data

        src_port, dst_port = struct.unpack('!HH', payload[:4])
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        #Establish both direction connections
        connection_to = (src_ip, src_port, dst_ip, dst_port)
        connection_from = (dst_ip, dst_port, src_ip, src_port) 

        #Append ip_packets to matching connections
        if connection_to in connections:
            connections[connection_to].append(ip_packet)
            num_packets_src_dst += 1
        elif connection_from in connections:
            connections[connection_from].append(ip_packet)
            num_packets_dst_src += 1
        else:
            connections[connection_to] = [ip_packet]
            #Append final count
            total_num_of_packets = num_packets_dst_src + num_packets_src_dst
            num_p = (num_packets_src_dst, num_packets_dst_src, total_num_of_packets)
            num_packets.append(num_p)
            #Reset num packet count
            num_packets_src_dst = 0
            num_packets_dst_src = 0
    
    time_list = []
    num_data = []
    statuses = []
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

        #Find number of data bytes
        num_of_data_bytes_src_dst = 0
        num_of_data_bytes_dst_src = 0
        total_num_of_data_bytes = 0
        status = "None"
        is_syn = False
        is_ack = False
        is_rst = False
        is_fin = False
        for usec_time, msec_time, data in packet:
            tcp_segment = data.payload
            flags = tcp_segment[13]

            if flags & 0x02:
                is_syn = True
            if flags & 0x01:
                is_fin = True
            if flags & 0x10:
                is_ack = True
            if flags & 0x04:
                is_rst = True
            
            header_length = (tcp_segment[12] >> 4) * 4
            data_length = len(tcp_segment) - header_length

            if data.src_ip == key[0] and data.src_ip != key[2]:
                num_of_data_bytes_src_dst += data_length
            else: 
                num_of_data_bytes_dst_src += data_length

        if is_syn & is_fin:
            status = "SYN + FIN"
        elif is_rst:
            status = "RST"
        elif is_ack & is_fin:
            status = "ACK + FIN"
        elif is_ack:
            status = "ACK"
        elif is_syn:
            status = "SYN"
        else:
            status = "None"

        statuses.append(status)
        total_data_bytes = num_of_data_bytes_dst_src + num_of_data_bytes_src_dst
        num_data.append((num_of_data_bytes_src_dst, num_of_data_bytes_dst_src, total_data_bytes))
        
    return (connections, time_list, num_packets, num_data, statuses)

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
        output += f'Start Time: {time_list[count][0]}\n'
        output += f'End Time: {time_list[count][1]}\n'
        output += f'Duration: {time_list[count][2]}\n'
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

def getGeneralInfo(connections, statuses):
    is_complete = 0
    is_reset = 0
    is_open = 0
    is_established = 0
    for status in statuses:
        if status == 'SYN + FIN':
            is_complete += 1
        if status == 'RST':
            is_reset += 1
        if status == 'ACK':
            is_open += 1
        if status != 'SYN' and status != 'SYN + FIN':
            is_established += 1
    output = f'Total Number of complete TCP Connections: {is_complete}\n'
    output += f'The number of reset TCP connections: {is_reset}\n'
    output += f'The number of TCP connections that were still open when the trace capture ended: {is_open}\n'
    output += f'The number of TCP connections established before the capture started: {is_established}\n'
    return output

def getPartD(partD, time_list):
    d = [
        duration
        for start_time, end_time, duration in time_list
    ]

    min_time_d = min(d)
    max_time_d = max(d)
    mean_time_d = sum(d)/len(d)

    output = f'Minimum time duration: {min_time_d}\n'
    output += f'Mean time duration: {max_time_d}\n'
    output += f'Maximum time duration: {mean_time_d}\n'
    output += f'\n'
    output += f'Mean RTT value: \n'
    output += f'Maximum RTT value: \n'
    output += f'Minimum RTT value: \n'
    output += f'\n'
    output += f'Minimum number of packets including both send/received: \n'        
    output += f'Mean number of packets including both send/received: \n'
    output += f'Maximum number of packets including both send/received: \n'
    output += f'\n'
    output += f'Minimum receive window size including both send/received: \n'
    output += f'Mean receive window size including both send/received: \n'
    output += f'Maximum receive window size including both send/received: \n'


    return output

def printOutput(A, B, C, D):
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
    connections, time_list, num_packets, num_data, statuses = parseData(packet)
    #Process data for part A
    A = getTotalConnections(len(connections))
    #Process data for part B
    B = getConnectionsDetails(connections, time_list, num_packets, num_data, statuses)
    #Process data for part C  
    C = getGeneralInfo(connections, statuses)
    #Process data for part D
    D = getPartD(connections, time_list)
    #Print all data
    #printOutput(A, B, C, D)

if __name__ == "__main__":
    main()