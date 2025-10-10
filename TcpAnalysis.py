import struct
import sys

PCAP_FILE = './sample-capture-file.cap'

def getCapFile(file):
    #parse using struct
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
    print(f'packet_count: {packet_count}, packet_data: {packet_data}, packet_header: {packet_header}')
    return (0,0,0,packet_data)

def getTotalConnections(partA):
    return 0

def getConnectionsDetails(partB):
    return 0

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
    partA, partB, partC, partD = getCapFile(file)
    #Process data for part A
    A = getTotalConnections(partA)
    #Process data for part B
    B = getConnectionsDetails(partB)
    #Process data for part C  
    C = getGeneralInfo(partC)
    #Process data for part D
    D = getPartD(partD)
    #Print all data
    printOutput(A, B, C, D)

if __name__ == "__main__":
    main()