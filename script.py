import dpkt
import os
import sys
import socket
import datetime
import struct
from  datetime import datetime as dtime
import matplotlib.pyplot as plt

#method to get the MSS size from the options field of TCP header
def get_MSS(options) :
    options_list = dpkt.tcp.parse_opts ( options )      #Parse TCP option buffer into a list of (option, data) tuples
    for option in options_list :
        if option[0] == 2 :
            mss = struct.unpack(">H", option[1])        #extracting the mss value
            return mss[0]

#Method to extract the payload present in the  packets of different layers    
def parsePcap(pcap):
    mss=[]      #initializing mss and time arrays to extract and store values of each tcp segment
    time=[]
    cnt = 0
    pkt_cnt = 0
    for (ts,buf) in pcap:       #ts as timestamp and buffer, traversing over each packet in pcap file

        try:
            eth = dpkt.ethernet.Ethernet(buf)       #unpacking the ethernet frame
            ip = eth.data                           #getting the data within the ethernet frame(ip packet)
            if ip.p==dpkt.ip.IP_PROTO_TCP:      #checking if it is a tcp packet
                tcp = ip.data                   #set the tcp data
                pkt_cnt += 1
                m = get_MSS(tcp.opts)           #send the options part of the tcp packet to extract mss from
                if m==None:
                    cnt+=1
                    continue
                    # mss.append(m)
                mss.append(m)           #appending newest  mss value to the array
                temp = str(datetime.datetime.utcfromtimestamp(ts))
                time_string = temp[11:19]
                date_time = dtime.strptime(time_string, "%H:%M:%S")
                a_timedelta = date_time - datetime.datetime(1900, 1, 1)
                seconds = a_timedelta.total_seconds()
                time.append(seconds)                    #appeding according time into the time array in seconds
        except Exception as e:
            print("Error!",e)
            sys.exit(1)
            
    #IF no packet found with MSS or no SYN packet found
    if cnt==pkt_cnt:
        print("No packets found with MSS info")
        sys.exit(1)
    print("Total number of mss values recorded are ")
    print(len(time))
    print("Total number of time values recorded are " )
    print(len(mss))
    t = time[0]
    for i in range(len(time)):
        time[i] -= t
   
    print("MSS:",*mss)
    print("Time:",*time)
    #plot graph
    plt.plot(time,mss,color='b')
    plt.scatter(time,mss,color='k')
    plt.title('MSS vs Time (seconds)')
    plt.xlabel('Time (seconds)')
    plt.ylabel('MSS')
    plt.show()

def main():
    file_name = input("Enter the pcap filename or pathname: ")
    try:
        f = open(file_name,'rb')
        pcap = dpkt.pcap.Reader(f)      #sending the file to be read by the pcap reader
    except Exception as e:
        print("Error!",e)
        sys.exit(1)
    try:
        parsePcap(pcap)     #sending pcap variable into parsing function
    except Exception as e:
        print("Error!",e)

if __name__== "__main__":
    main()