import configparser
import os

def read_config():
    root_dir = os.getcwd()
    cf = configparser.ConfigParser()
    cf.read(root_dir + "/config.ini")

    recv_iface = cf.get("Target-Interface", "recv_iface")
    send_iface = cf.get("Target-Interface", "send_iface")

    return recv_iface, send_iface
