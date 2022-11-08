# PLOT OF MAXIMUM SEGMENT SIZE(MSS) FOR TCP-ORIENTED APPLICATION LAYER PROTOCOLS

## Computer Networks Lab Mini Project 2022

### Team Details:-
* [Praveen Varma](https://github.com/geekyprawins)
* [Ishita Pandey](https://github.com/IshitaP26)
* [Yashwanth](https://github.com/yashwanth008)

### Project Details:-

TCP is a very commonly used and important network protocol as several abstract application layer protocols like HTTP, SMTP and FTP use TCP as their transport layer protocol. The maximum segment size (MSS) is a parameter of the options field of the TCP header that specifies the largest amount of data, in bytes, that a device can receive or send in a single TCP segment. This does not include the TCP header or the IP header length, and is a measure for only the data being sent. The Maximum Segment Size is set at the beginning of the connection within the TCP option area, by the TCP SYN packet during the TCP handshake.

In this mini project we used dpktmodule of python to parse the pcap file received from Wireshark, containing the packets of any application layer protocol and extract the MSS information from the SYN packets in the pcap file. We then plot a graph of the MSS vs relative time using matplotlib module of python in order to physically model the changes in MSS value over time and analyze the same.


### Running the application:-

In the project directory, you can run: `python3 script.py` or `py script.py`, and then give `my-sample.pcap` as input file name to generate the graph.


#### Detailed explanation can be found [here](https://github.com/geekyprawins/MSS-Plot-TCP/raw/master/CN-MiniProjReport.pdf).
