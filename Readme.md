# Diamanti Pcap Info Extractor

This is an assignment repo for Diamanti's Software Engineer Internship interview. It has small c program to process a pcap file and print the IP header information for the packets.

This app has been built and tested on linux machine and to run this app, following dependencies are needed.  
- `gcc`
- `libpcap`
- `.pcap` file

To run the app, go to the root of this repo in the terminal and enter the following commands  
```
gcc ip_extractor.c -lpcap
```

```
./a.out <file_name.pcap>
```

After running the following commands one should see the IP header information of the packets.

### Create a .pcap file using tcpdump
`.pcap` file can generated using many tools and one of them is `tcpdump`. For testing purposes, tcpdump was used to capture packets and store them in a file. To do the same, follow the below commands.

```
sudo tcpdump -i any -c50 -nn -w data.pcap
```

The `-i` attribute provides the interface to listen to and providing `any` listens to all the interfaces.  
The `-c` attributes provides the count of packets to capture.
The `-nn` attributes tells tcpdump to resolve domain-name to their ip.  
The `-w` attributes provides the filename to write the data to.  

### References
Introduction to tcpdump - https://opensource.com/article/18/10/introduction-tcpdump  
libpcap example in C - https://elf11.github.io/2017/01/22/libpcap-in-C.html