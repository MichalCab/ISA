#!/usr/bin/env python
# -*- coding: utf8 -*-

import argparse
import sys
from pprint import pprint as pp
from scapy.all import sr1, IP, ICMP

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

    print pp(argv)
