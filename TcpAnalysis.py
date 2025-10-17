import struct
import sys
import IPPacket

PCAP_FILE = './sample-capture-file.cap'

def getCapFile(file):
    #parse using struct
    ip_packet_list = []
    with open(PCAP_FILE, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("Incomplete global header")
            exit(1)
    
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big == 0xa1b2c3d4 or magic_big == 0xa1b23c4d:
            endian = '>' #big-endian
        elif magic_little == 0xa1b2c3d4 or magic_little == 0xa1b23c4d:
            endian = '<' #little-endian
        else:
            print("Unnown magic number, cannot determine endianness")
            exit(1)

        packet_count = 0

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
        
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print("Incomplete packet data")
                break
            packet_count += 1

            ip_packet = IPPacket.IPPacket.from_bytes(packet_data[14:])
            ip_packet_list.append((ts_sec, ts_usec, ip_packet))
    
    return ip_packet_list

def parseData(partB):
    connections = {}
    count = 1
    num_packets = []
    num_packets_src_dst = 0
    num_packets_dst_src = 0

    num_data = []
    for ip_packet in partB:
        payload = ip_packet[2].payload
        src_port, dst_port = struct.unpack('!HH', payload[:4])
        src_ip = ip_packet[2].src_ip
        dst_ip = ip_packet[2].dst_ip

        connection_to = (src_ip, src_port, dst_ip, dst_port)
        connection_from = (dst_ip, dst_port, src_ip, src_port) 

        duration = ''

        if connection_to in connections:
            connections[connection_to].append(ip_packet)
            num_packets_src_dst = num_packets_src_dst + 1
        elif connection_from in connections:
            connections[connection_from].append(ip_packet)
            num_packets_dst_src = num_packets_dst_src + 1
        else:
            connections[connection_to] = [ip_packet]
            total_num_of_packets = num_packets_dst_src + num_packets_src_dst
            num_p = (num_packets_src_dst, num_packets_dst_src, total_num_of_packets)
            num_packets.append(num_p)
            num_packets_src_dst = 0
            num_packets_dst_src = 0
            count = count + 1
    
    time_list = []
    num_data = []
    statuses = []
    for key, packet in connections.items():
        time_stamp = [
            usec_time + (msec_time/1_000_000)
            for usec_time, msec_time, z in packet
        ]

        start_time = min(time_stamp)
        end_time = max(time_stamp)
        duration = end_time - start_time

        times = (start_time, end_time, duration)
        time_list.append(times)
        num_of_data_bytes_src_dst = 0
        num_of_data_bytes_dst_src = 0
        total_num_of_data_bytes = 0
        status = "None"
        for usec_time, msec_time, pack in packet:
            tcp_segment = pack.payload
            flags = tcp_segment[13]
            if flags & 0x02:
                if flags & 0x01:
                    status = "SYN + FIN"
            
            header_length = (tcp_segment[12] >> 4) * 4
            data_length = len(tcp_segment) - header_length

            if pack.src_ip == key[0] and pack.src_ip != key[2]:
                num_of_data_bytes_src_dst += data_length
            else: 
                num_of_data_bytes_dst_src += data_length

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
        if statuses[count] is not "None":
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

        count += 1
    return output

def getGeneralInfo(partC):
    return 0

def getPartD(partD):
    return 0

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
    C = getGeneralInfo(packet)
    #Process data for part D
    D = getPartD(packet)
    #Print all data
    printOutput(A, B, C, D)

if __name__ == "__main__":
    main()