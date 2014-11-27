#!/usr/bin/env python
# -*- coding: utf8 -*-

import argparse
import sys
from pprint import pprint as pp
import traceback
from scapy import *
from scapy.all import *
from scapy.error import *
from time import sleep
import xml.etree.ElementTree as ET

def pkt_callback(pkt):
    pkt.show() # debug statement
    sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="data pro analýzu se získají ze souboru formátu pcap se zadaným názvem")
    parser.add_argument("-i", "--interface",type=str, help="data se odchytávají s rozhraním se zadaným názvem")
    parser.add_argument("-o", "--output", type=str, help="výsledky sa zapíší do souboru se zadaným názvem")
    parser.add_argument("-p", "--port", type=int, help="číslo portu na kterém probíha signalizace SIP", default=5060)
    argv = parser.parse_args()
    if (argv.file is None and argv.interface is None) or (argv.file and argv.interface):
        sys.stderr.write("Musí být zadáno %r nebo %r\n" % ("-f", "-i"))
        exit(1)

    if argv.output is None:
        sys.stderr.write("Musí být zadáno %r\n" % ("-o", ))
        exit(1)
    print argv.file

    root = ET.Element("sipscan")
    if argv.file:
        pkts = PcapReader(argv.file)
        for pkt in pkts:
            typ = TCP if (TCP in pkt) else None
            typ = UDP if (UDP in pkt and typ is None) else None
            print typ
            print repr(pkt)
            if typ is None:
                continue
            print repr(pkt[typ].sport), repr(pkt[typ].dport)
            if not (pkt[typ].sport == argv.port and pkt[typ].dport == argv.port and int(pkt[typ].len) > 15):
                continue
            print repr(pkt[typ].sport)
            if pkt[typ]:
                print repr(pkt)
                print pkt.sprintf("{IP:%IP.src% -> %IP.dst%}")
                pp(pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n"))
                if "BYE":
                    pass
                sleep(0.5)
    else:
        sniff(iface=argv.interface, prn=pkt_callback, filter="port %s" % argv.port, store=0)

    tree.write()
