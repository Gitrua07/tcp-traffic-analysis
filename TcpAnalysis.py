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

def getTotalConnections(partA):
    num_connections = len(partA)
    return num_connections

def getConnectionsDetails(partB):
    output_list = []
    count = 1
    for ip_packet in partB:
        output = 'Connection ' + str(count) + ': \nSource Address: '
        src_ip = ip_packet[2].src_ip
        output = output + src_ip + '\n' + 'Destination Address: '
        dst_ip = ip_packet[2].dst_ip
        output = f'{output}{dst_ip}\n' 
        src_port = ''
        #output = output + src_port + '\n'
        dst_port = ''
        #output = output + dst_port + '\n'
        status = ''
        if count == 1:
            start_time = ip_packet[0]
            output = f'{output} Start Time: {start_time}'
        
        if count == len(partB):
            end_time = ip_packet[0]
            output = f'{output} End Time: {end_time}'

        duration = ''


        output_list.append(output)
        count = count + 1

    return output_list

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
    for detailB in B:
        print(detailB)
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
    #Process data for part A
    A = getTotalConnections(packet)
    #Process data for part B
    B = getConnectionsDetails(packet)
    #Process data for part C  
    C = getGeneralInfo(packet)
    #Process data for part D
    D = getPartD(packet)
    #Print all data
    printOutput(A, B, C, D)

if __name__ == "__main__":
    main()