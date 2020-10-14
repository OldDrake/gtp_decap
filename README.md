# gtp_decap
环境：python3.7
第三方库：scapy

实现功能：从指定网口捕获GTP包，获取GTP载荷后从原端口发送出去。在主机上运行main.py, 输入网口名称后开始接收数据并对GTP包进行处理，使用键盘中断终止程序。

dns.pcap和http.pcap为GTP包样例
