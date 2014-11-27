#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
author: Michal Cab <xcabmi00 at stud.fit.vutbr.cz>
"""
import argparse
import sys
from pprint import pprint as pp
import traceback
from scapy import *
from scapy.all import *
from scapy.error import *
from time import sleep
import xml.etree.ElementTree as ET
import signal
import date_time
import socket
MIN_RAW_DATA_LEN = 15
DEFAULT_SIP_SIGNALIZATION_PORT = 5060

def packet_analysis(pkt):
    pass

def save_registration(registration, root):
    pp(registration)
    registration_xml = ET.SubElement(root, "registration")
    registrar_xml = ET.SubElement(registration_xml, "registrar")
    registrar_xml.set("ip", registration["registrar"]["ip"]) # "212.242.33.35"
    registrar_xml.set("uri", registration["registrar"]["uri"]) # "sip.cybercity.dk"

    user_agent_xml = ET.SubElement(registration_xml, "user-agent")
    user_agent_xml.set("ip", registration["user-agent"]["ip"]) #"192.168.1.2"
    user_agent_xml.set("uri", registration["user-agent"]["uri"]) # voi18062@sip.cybercity.dk

    authentication_xml = ET.SubElement(registration_xml, "authentication")
    authentication_xml.set("username", registration["authentication"]["username"]) # "voi18062"
    authentication_xml.set("realm", registration["authentication"]["realm"]) # "sip.cybercity.dk"

    time_xml = ET.SubElement(registration_xml, "time")
    time_xml.set("registration", registration["time"]["registration"]) #2005-12-30T09:00:00

def save_call(call, root):
    pp(call)
    call_xml = ET.SubElement(root, "call")
    caller_1_xml = ET.SubElement(call_xml, "caller")
    caller_1_xml.set("ip", call["caller_1"]["ip"]) # "192.168.1.117"
    caller_1_xml.set("ip", call["caller_1"]["uri"]) # bbb@192.168.1.50

    caller_2_xml = ET.SubElement(call_xml, "caller")
    caller_2_xml.set("ip", call["caller_2"]["ip"]) # "192.168.1.117"
    caller_2_xml.set("ip", call["caller_2"]["uri"]) # bbb@192.168.1.50

    time_xml = ET.SubElement(call_xml, "time")
    time_xml.set("start", call["time"]["start"]) # 2013-08-15T09:00:02

    #rtp
    rtp_xml = ET.SubElement(call_xml, "rtp")
    caller_xml = ET.SubElement(rtp_xml, "caller")
    caller_xml.set("ip", call["rtp"]["caller"]["ip"]) # "192.168.1.117"
    caller_xml.set("port", call["rtp"]["caller"]["port"]) # "5084"

    callee_xml = ET.SubElement(rtp_xml, "callee")
    callee_xml.set("ip", call["rtp"]["callee"]["ip"]) # "192.168.1.50"
    callee_xml.set("port", call["rtp"]["callee"]["port"]) # "5066"

    codec_xml = ET.SubElement(rtp_xml, "codec")
    codec_xml.set("payload-type", call["rtp"]["codec"]["payload-type"]) # "3"
    codec_xml.set("name", call["rtp"]["codec"]["name"]) # gsm/8000/1

def output_error(msg):
    sys.stderr.write(msg)
    exit(1)

def sigint_handler(signum, frame):
    tree = ET.ElementTree(root)
    tree.write(argv.output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="data pro analýzu se získají ze souboru formátu pcap se zadaným názvem")
    parser.add_argument("-i", "--interface",type=str, help="data se odchytávají s rozhraním se zadaným názvem")
    parser.add_argument("-o", "--output", type=str, help="výsledky sa zapíší do souboru se zadaným názvem")
    parser.add_argument("-p", "--port", type=int, help="číslo portu na kterém probíha signalizace SIP", default=DEFAULT_SIP_SIGNALIZATION_PORT)
    argv = parser.parse_args()
    if (argv.file is None and argv.interface is None) or (argv.file and argv.interface):
        output_error("Musí být zadáno %r nebo %r\n" % ("-f", "-i"))

    if argv.output is None:
        output_error("Musí být zadáno %r\n" % ("-o", ))

    root = ET.Element("sipscan")
    if argv.file:
        pkts = PcapReader(argv.file)

        #init
        call = {}
        registration = {}

        for pkt in pkts:
            typ = TCP if (TCP in pkt) else None
            typ = UDP if (UDP in pkt and typ is None) else None
            if typ is None:
                continue
            if not (pkt[typ].sport == argv.port and pkt[typ].dport == argv.port and int(pkt[typ].len) > MIN_RAW_DATA_LEN):
                continue
            if pkt[typ]:
                print repr(pkt)
                print pkt.sprintf("{IP:%IP.src% -> %IP.dst%}")

                #get main sip data from raw data
                sip_data_list = pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n")
                pp(sip_data_list)
                timestamp = datetime.datetime.fromtimestamp(int(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
                status = sip_data_list[0]
                c_seq = [sip_data for sip_data in sip_data_list if sip_data.startwith("CSeq: ")][0]
                #init call
                if "200 OK" in status and "REGISTER" in c_seq:
                    registration = {}
                    registration["registrar"] = {}
                    registration["user-agent"] = {}
                    registration["authentication"] = {}
                    registration["time"] = {}
                    sip_data_list = pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n")
                    pp(sip_data_list)
                    for sip_data in sip_data_list:
                        if "Contact: " in sip_data:
                            d = sip_data.split(" ")[1][:-2].split("@")[1][:-1]
                            registration["registrar"]["ip"] = socket.gethostbyname(d)
                            registration["registrar"]["uri"] = d
                        if "Via: " in sip_data:
                            registration["user-agent"]["ip"] = sip_data.split(" ")[1][:-2].split(" ")[1].split(";")[0].split(":")[0]
                        if "To: " in sip_data:
                            d = sip_data.split(" ")[1][:-2] #
                            registration["authentication"]["username"] = d.split("@")[0].split(":")[1]
                            registration["authentication"]["realm"] = d.split("@")[1].split(">")[0]
                            registration["user-agent"]["uri"] = registration["authentication"]["username"]+"@"+registration["authentication"]["realm"]

                    registration["time"]["registration"] = timestamp
                    save_registration(registration, root)
                elif "INVITE" in status and "INVITE" in c_seq:
                    call = {}
                    call["caller_1"] = {}
                    call["caller_2"] = {}
                    call["time"] = {}
                    call["rtp"] = {}
                    call["rtp"]["caller"] = {}
                    call["rtp"]["callee"] = {}
                    call["rtp"]["codec"] = {}

                    registration["registrar"]["ip"] = ""
                    registration["registrar"]["uri"] = ""

                    call["caller_1"]["ip"] = "192.168.1.117"
                    call["caller_1"]["uri"] =  "bbb@192.168.1.50"

                    call["caller_2"]["ip"] = "192.168.1.117"
                    call["caller_2"]["uri"] = "bbb@192.168.1.50"

                    call["time"]["start"] = timestamp
                    call["time"]["answer"] = "2013-08-15T09:00:02"
                    call["time"]["end"] = "2013-08-15T09:00:02"

                    call["rtp"]["caller"]["ip"] = "192.168.1.117" #volajici
                    call["rtp"]["caller"]["port"] = "5084" #volajici

                    call["rtp"]["callee"]["ip"] = "192.168.1.50" #volany
                    call["rtp"]["callee"]["port"] = "5066" #volany
                    
                    call["rtp"]["codec"]["payload-type"] = "3"
                    call["rtp"]["codec"]["name"] = "gsm/8000/1"
                    save_call(call, root)
                elif "183":
                    #set answer="2013-08-15T09:00:16"
                    call["time"]["answer"] = timestamp
                    
            sleep(3)
    else:
        signal.signal(signal.SIGINT, sigint_handler)
        sniff(iface=argv.interface, prn=packet_analysis, filter="port %s" % argv.port, store=0)

    tree = ET.ElementTree(root)
    tree.write(argv.output)
