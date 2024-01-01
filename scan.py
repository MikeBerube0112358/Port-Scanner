''' Only run port scanner on consenting websites. This script is for educational purposes only. '''
import argparse
import socket

'''
Use BSD socket API to help with TCP port scanner 
- Step 1 => Input hostname and list of ports to scan in a csv
- Step 2 => Translate hostname to an IPv4 address
- Step 3 => Connect to the target address and specific port for each port listed 
- Step 4 => Send garbage data to each port to help determine service of port
- Step 5 => Read banner of each port to help determine service
'''

# example usage: nslookup scanme.nmap.org
# IPv4 output => 45.33.32.156 
# python3 scan.py -H 45.33.32.156 -p 80,443      
# python3 scan.py -H scanme.nmap.org -p 80,443,20,25,53

def main():
    # Create an argument parser
    parser = argparse.ArgumentParser(description ="Usage: -H <target host> -p <target port>")
    # Add arguments for target host and port
    parser.add_argument('-H', dest='tgtHost', type=str, help='specify target host')
    parser.add_argument('-p', dest='tgtPort', type=str, help='specify target port(s) seperated by comma')

    # Parse arguments
    args = parser.parse_args()
    # Extract the target host and port
    tgtHost = args.tgtHost
    tgtPorts = [int(port.strip()) for port in args.tgtPort.split(',')] if args.tgtPort else [] # Passes inputed port numbers into a list of ints

    # Check for missing arguments and handle errors
    if tgtHost is None or tgtPorts is None:
        print(parser.description)
        parser.print_help()
        exit(1)
    port_scan(tgtHost, tgtPorts)

def connection_scan(tgtHost, tgtPort):
    ''' Takes 2 args: tgtHost, tgtPort. Trys to create connection between host and port. '''
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creates a socket object w/IPv4 (AF_INET) and TCP (SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort)) # Connect to specified host and port
        connSkt.send("ViolentPython\r\n".encode())
        results = connSkt.recv(100)
        print(f'[+] {tgtPort}/tcp open')
        print(f'[+] {results}')
        connSkt.close()
    except ConnectionRefusedError: # When connection is actively refused by host
        print(f'[-] {tgtPort}/tcp closed: Connection refused')
    except OSError as e: # "e" holds the exception object. OSError handles other socket and network related issues
        print(f'[-] {tgtPort}/tcp closed: {e}')

def port_scan(tgtHost, tgtPorts):
    try: # Attempt to resolve the target host to an IP address (DNS lookup)
        tgtIP = socket.gethostbyname(tgtHost)
    except socket.gaierror: # gaierror occurs when DNS lookup fails
        print(f"[-] Cannot resolve '{tgtHost}': Unknown host")
        return

    try: # Attempts a reverse DNS lookup using target IP
        tgtName = socket.gethostbyaddr(tgtIP)
        print(f'\n[+] Scan Results for: {tgtName[0]}')
    except socket.herror: # herror is raised when IP address does not have corresponding hostname
        print(f'\n[+] Scan Results for: {tgtIP}')

    socket.setdefaulttimeout(1)  # Set the default timeout for new socket connections to 1 second to avoid hanging on unresponsive ports
    for tgtPort in tgtPorts: # Iterate through the list of target ports provided
        print(f'Scanning port {tgtPort}')
        connection_scan(tgtHost, int(tgtPort))

if __name__=="__main__":
    main()