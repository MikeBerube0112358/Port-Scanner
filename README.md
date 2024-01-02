Disclaimer: Only run this port scanner on consenting websites. Unauthorized port scanning is illegal. This script is provided and 
was developed for educational purposes only.

A TCP port scanner that uses the BSD socket API to scan specified ports on a target host. 

Features:
- Hostname Resolution: Converts a hostname to an IPv4 address.
- Port Scanning: Scans specified ports on the target address.
- Banner Grabbing: Sends a sample request to open ports and reads the response to help identify the service running on each port.

Usage:
The script is run from the command line with the following syntax:
python3 scan.py -H <target_host> -p <target_port>
-H: Specify the target host (either hostname or IP address).
-p: Specify target port(s), separated by commas (no spaces).

Example:
python3 scan.py -H scanme.nmap.org -p 80,443
