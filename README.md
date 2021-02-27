# CSS_IA2

The Project implements some of the functionalities of the Tcpdump tool.
It is implemented in Java and uses the jnetpcap package.

The functionalities implemented are: - (Option to be used mentioned in the bracket)

1. Display Available interfaces (-D)
2. Capture packets from specific interface (-i 1)     // -i <interface_number>
3. Capture and save packets in a file (-i 1 -f filename.txt)
4. Read captured packets file (-f filename.txt)
5. Capture only IP packets (ip -i 1)
6. Capture only TCP packets (tcp -i 1)