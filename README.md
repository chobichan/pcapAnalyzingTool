# pcapAnalyzingTool
Analyze PCAP format capture data

Wireshark's packet capture screen is difficult to read the packet as it is.
This tool analyzes the pcap file output by Wireshark and outputs it in a human-readable format.

Works on Windows command line.
normal usage : 
pcapreader.exe TCP hoge.pcap 192.168.1.1:1280

simple usage : 
pcapreader.exe TCP hoge.pcap 192.168.1.1:1280 -s

normal output : 
BUILD : Mar 16 2020 14:34:40
PCAP FILE is mc001.pcap TCP server ip = 192.168.40.1:1280

packet00000001
    ETHERNET> source:08:00:70:38:A9:EF destination:00:02:CB:03:71:71 frame type:ETHER2 IPV4
    time stamp:1535509693.321654 2018/8/29 11:28:13.321654(JST) delay:1535509693.321654s
    packet size:64byte

    IPV4> source:192.168.40.1 destination:192.168.40.2 type:TCP
    ver:4 header size:20 TOS:0 packet len:44 id:0 fragment:0000 TOL:250 check sum:EF77

    TCP> source:1280() destination:1280() seq:149(0x00000095) ack:0(0x00000000)
    flag:.......S. offset:24 window:0 urgent:0 check sum:B9F1
    OPTION DUMP
    00000000 : 02,04,08,00,                                         .... 

packet00000002
    ETHERNET> source:00:02:CB:03:71:71 destination:08:00:70:38:A9:EF frame type:ETHER2 IPV4
    time stamp:1535509693.322839 2018/8/29 11:28:13.322839(JST) delay:0.001185s
    packet size:60byte

    IPV4> source:192.168.40.2 destination:192.168.40.1 type:TCP
    ver:4 header size:20 TOS:0 packet len:44 id:58851 fragment:0000 TOL:128 check sum:8394

    TCP> source:1280() destination:1280() seq:29184(0x00007200) ack:150(0x00000096)
    flag:....A..S. offset:24 window:1536 urgent:0 check sum:442C
    OPTION DUMP
    00000000 : 02,04,05,B4,                                         .... 

packet00000003
    ETHERNET> source:08:00:70:38:A9:EF destination:00:02:CB:03:71:71 frame type:ETHER2 IPV4
    time stamp:1535509693.324955 2018/8/29 11:28:13.324955(JST) delay:0.002116s
    packet size:64byte

    IPV4> source:192.168.40.1 destination:192.168.40.2 type:TCP
    ver:4 header size:20 TOS:0 packet len:40 id:1 fragment:0000 TOL:250 check sum:EF7A

    TCP> source:1280() destination:1280() seq:150(0x00000096) ack:29185(0x00007201)
    flag:....A.... offset:20 window:6144 urgent:0 check sum:49E9

packet00000004
    ETHERNET> source:00:02:CB:03:71:71 destination:08:00:70:38:A9:EF frame type:ETHER2 IPV4
    time stamp:1535509698.562924 2018/8/29 11:28:18.562924(JST) delay:5.237969s
    packet size:66byte

    IPV4> source:192.168.40.2 destination:192.168.40.1 type:TCP
    ver:4 header size:20 TOS:0 packet len:52 id:64092 fragment:0000 TOL:128 check sum:6F13

    TCP> source:1280() destination:1280() seq:29185(0x00007201) ack:150(0x00000096)
    flag:....AP... offset:20 window:1536 urgent:0 check sum:A323

    PAYLOAD> size:12byte
    from 192.168.40.2:1280 to 192.168.40.1:1280 time stamp:2018/8/29 11:28:18.562924(JST) delay:1535509698.562924s
    DATA No. 1
    00000000 : 60,00,04,00,00,00,00,06, 55,AA,FF,00,                `....... U...


simple output : 
BUILD : Mar 16 2020 14:34:40
PCAP FILE is mc001.pcap TCP server ip = 192.168.40.1:1280

    PAYLOAD> size:12byte
    from 192.168.40.2:1280 to 192.168.40.1:1280 time stamp:2018/8/29 11:28:18.562924(JST) delay:1.53551e+09s
    DATA No. 1
    00000000 : 60,00,04,00,00,00,00,06, 55,AA,FF,00,                `....... U...

    PAYLOAD> size:2byte
    from 192.168.40.1:1280 to 192.168.40.2:1280 time stamp:2018/8/29 11:28:18.638763(JST) delay:0.075839s
    DATA No. 2
    00000000 : E0,00,                                               .. 

    PAYLOAD> size:12byte
    from 192.168.40.2:1280 to 192.168.40.1:1280 time stamp:2018/8/29 11:28:33.562735(JST) delay:14.924s
    DATA No. 3
    00000000 : 60,00,04,00,00,00,00,06, 55,AA,FF,00,                `....... U...

