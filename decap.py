from scapy.all import *
from scapy.layers.l2 import *


def GTP_Decap(iface, count):
    dpkt = sniff(iface=iface, count=count)
    #dpkt = sniff(offline="dns.pcap")
    pkt_decap = []
    for pkt in dpkt:
        data = pkt[Raw].load
        if data[0] & 0xe0 == 0x20:          #GTPv1
            if data[0] & 0x0f == 0x00:      #无可选字段
                data = data[8:]
            elif data[0] & 0x0f == 0x01:    #判断是否有拓展信息
                data = data[12:]
                len = data[0]
                while len != 0:             #判断拓展信息是否结束
                    data = data[len-1:]
                    if data[0] == 0x00:
                        len = 0
                    else:
                        len = data[1]
                    data = data[1:]
            else:
                data = data[12:]
        elif data[0] & 0xe0 == 0x40:        #GTPv2
            if data[0] & 0x0f == 0x08:      #判断是否有TEID
                data = data[12:]
            elif data[0] & 0x0f == 0x00:
                data = data[8:]
        pkt_decap.append(data)
        sendp(Ether(type=0x0800)/data, iface=iface)
    return pkt_decap




