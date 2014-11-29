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
import datetime
import socket
import traceback

MIN_RAW_DATA_LEN = 15
DEFAULT_SIP_SIGNALIZATION_PORT = 5060

def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def packet_analysis(pkt):
    pass

def save_registration(registration, root):
    #pp(registration)
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
    authentication_xml.set("uri", registration["authentication"]["uri"])

    time_xml = ET.SubElement(registration_xml, "time")
    time_xml.set("registration", registration["time"]["registration"]) #2005-12-30T09:00:00

def save_call(call, root, rtp=True):
    #pp(call)
    call_xml = ET.SubElement(root, "call")
    caller_xml = ET.SubElement(call_xml, "caller")
    caller_xml.set("ip", call["caller"]["ip"]) # "192.168.1.117"
    caller_xml.set("uri", call["caller"]["uri"]) # bbb@192.168.1.50

    callee_xml = ET.SubElement(call_xml, "callee")
    callee_xml.set("ip", call["callee"]["ip"]) # "192.168.1.117"
    callee_xml.set("uri", call["callee"]["uri"]) # bbb@192.168.1.50

    time_xml = ET.SubElement(call_xml, "time")
    time_xml.set("start", call["time"]["start"]) # 2013-08-15T09:00:02
    time_xml.set("answer", call["time"]["answer"]) # 2013-08-15T09:00:02
    time_xml.set("end", call["time"]["end"]) # 2013-08-15T09:00:02
    if rtp:
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
        call["caller"] = {}
        call["callee"] = {}
        call["time"] = {}
        call["rtp"] = {}
        call["rtp"]["caller"] = {}
        call["rtp"]["callee"] = {}
        call["rtp"]["codec"] = {}
        call["rtp"]["codec"]["payload-type"] = ""
        registration = {}
        registration["registrar"] = {}
        registration["user-agent"] = {}
        registration["authentication"] = {}
        registration["time"] = {}
        
        for pkt in pkts:
            typ = TCP if (TCP in pkt) else None
            typ = UDP if (UDP in pkt and typ is None) else None
            if typ is None:
                continue
            if not (pkt[typ].sport == argv.port and pkt[typ].dport == argv.port and int(pkt[typ].len) > MIN_RAW_DATA_LEN):
                continue
            if pkt[typ]:
                #print repr(pkt)
                #print pkt.sprintf("{IP:%IP.src% -> %IP.dst%}")

                #get main sip data from raw data
                sip_data_list = pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n")
                #pp(sip_data_list)
                timestamp = datetime.datetime.fromtimestamp(int(pkt.time)).isoformat()#.strftime('%Y-%m-%d %H:%M:%S')
                status = sip_data_list[0]
                c_seq = [sip_data for sip_data in sip_data_list if sip_data.startswith("CSeq: ")][0]
                #init call
                #print timestamp
                #print status, c_seq

                for sip_data in sip_data_list:
                    if sip_data.startswith("WWW-Authenticate: "):
                        registration["authentication"]["realm"] = re.findall(r'realm="(.*?)"',sip_data)[0]
                if "REGISTER" in status:
                    registration["user-agent"]["ip"], registration["registrar"]["ip"] = pkt.sprintf("{IP:%IP.src%-%IP.dst%}").split("-")
                if "200 OK" in status and "REGISTER" in c_seq:
                    sip_data_list = pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n")
                    for sip_data in sip_data_list:
                        if sip_data.startswith("From: "):
                            registration["registrar"]["uri"] = sip_data.split(" ")[1].split("@")[1].split(">")[0]
                        if sip_data.startswith("To: "):
                            d = sip_data.split(" ")[1]
                            registration["authentication"]["username"] = d.split("@")[0].split(":")[1]
                            registration["user-agent"]["uri"] = re.findall(r'<(.*?)>',d)[0].strip("sip:")
                        if sip_data.startswith("Via: "):
                            registration["authentication"]["uri"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',sip_data)[0]

                    registration["time"]["registration"] = timestamp
                    save_registration(registration, root)
                if "INVITE" in status and "INVITE" in c_seq:
                    for sip_data in sip_data_list:
                        if sip_data.startswith("From: "):
                            call["caller"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                        if sip_data.startswith("m="):
                            call["rtp"]["caller"]["port"] = sip_data.split(" ")[1]
                        if sip_data.startswith("c="):
                            call["rtp"]["caller"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                            call["caller"]["ip"] = call["rtp"]["caller"]["ip"]
                    if call["time"].get("start","") is "":
                        call["time"]["start"] = timestamp
                if "200" in status and "INVITE" in c_seq:
                    for sip_data in sip_data_list:
                        if sip_data.startswith("a=rtpmap:"):
                            if call["rtp"]["codec"]["payload-type"] is "":
                                call["rtp"]["codec"]["payload-type"] = re.findall(r'rtpmap:([0-9]+)',sip_data)[0]
                                call["rtp"]["codec"]["name"] = sip_data.split(" ")[-1]
                        if sip_data.startswith("m="):
                            call["rtp"]["callee"]["port"] = sip_data.split(" ")[1]
                    call["time"]["answer"] = timestamp

                if "183" in status and "INVITE" in c_seq:
                    for sip_data in sip_data_list:
                        if sip_data.startswith("From: "):
                            call["caller"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                        if sip_data.startswith("To: "):
                            call["callee"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                        if sip_data.startswith("c=IN"):
                            call["rtp"]["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                            call["callee"]["ip"] = call["rtp"]["callee"]["ip"]

                    call["time"]["answer"] = timestamp
                if len(re.findall(r'[4-6][0-9][0-9]', status)) > 0 and "INVITE" in c_seq and "401" not in status:
                    print status
                    pp(sip_data_list)
                    for sip_data in sip_data_list:
                        if sip_data.startswith("Contact: "):
                            call["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                        if sip_data.startswith("To: "):
                            call["callee"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                            
                    call["time"]["answer"] = call["time"]["end"] = timestamp
                    if "403" not in status and "408" not in status:
                        print "saving form ERROR"
                        save_call(call, root, rtp=False)
                    call["time"]["start"] = ""
                if "BYE" in status:
                    call["time"]["end"] = timestamp
                    print "saving from BYE"
                    save_call(call, root)
                    call["rtp"]["codec"]["payload-type"] = ""
                    call["time"]["start"] = ""
            #sleep(0.3)
    else:
        signal.signal(signal.SIGINT, sigint_handler)
        sniff(iface=argv.interface, prn=packet_analysis, filter="port %s" % argv.port, store=0)

    indent(root)
    tree = ET.ElementTree(root)
    tree.write(argv.output)
