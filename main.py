import logging
from threading import Thread, Lock
from queue import Queue
from decap import *


class DataReceive(Thread):
    def __init__(self, iface, prn):
        Thread.__init__(self)
        self.iface = iface
        self.prn = prn

    def run(self):
        sniff(iface=self.iface, prn=self.prn)


class DataDecap(Thread):

    def __init__(self, iface):
        Thread.__init__(self)
        self.iface = iface

    def run(self):
        while True:
            if not data_buffer.empty():
                pkt = data_buffer.get()
                GTP_DeCap(pkt, iface=self.iface)
                logging.info("Packet successfully sent.")


def buffering(pkt):
    if not data_buffer.full():
        if UDP in pkt[0] or TCP in pkt[0]:
            if pkt[0][2].dport == 2152:
                data_buffer.put(pkt)
                logging.info("buffer length: %d" % (data_buffer.qsize()))
        else:
            logging.info("not a GTP packet.")
    else:
        logging.warning("Buffer is full.")


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%Y/%m/%d %H:%M:%S %p"
    logging.basicConfig(filename='decap.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)

    net_iface = input("please input the target iface: ")

    data_buffer = Queue(maxsize=50)
    recv = DataReceive(net_iface, buffering)
    decap = DataDecap(net_iface)

    logging.info("start decapping")
    recv.start()
    decap.start()
