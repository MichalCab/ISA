#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
author: Michal Cab <xcabmi00 at stud.fit.vutbr.cz>
last edit: 29.11.2014
college year and program: 3BIT
"""

import argparse
import sys
import signal
import socket
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from pprint import pprint as pp

from scapy import *
from scapy.all import *
from scapy.error import *

class SipScaner(object):
    """
    Class for creating SIP analises
    according to rfc
    https://www.ietf.org/rfc/rfc3261.txt
    """
    MIN_RAW_DATA_LEN = 15
    def __init__(self, input_file, interface, port, output_file):
        #registration data
        self.registration = {}
        self.registration["registrar"] = {}
        self.registration["user-agent"] = {}
        self.registration["authentication"] = {}
        self.registration["time"] = {}

        #call data
        self.call = {}
        self.call["caller"] = {}
        self.call["callee"] = {}
        self.call["time"] = {}
        self.call["rtps"] = {
            "audio":
            {
                "payload_types":[], 
                "caller":{"port":"","ip":""},
                "callee":{"port":"","ip":""},
                "codecs":[]
            },
            "video":
            {
                "payload_types":[], 
                "caller":{"port":"","ip":""}, 
                "callee":{"port":"","ip":""},
                "codecs":[]
            }
        }
       

        #create output xml
        self.root = ET.Element("sipscan")

        self.input_file = input_file
        self.output_file = output_file
        self.interface = interface
        self.port = port 

    def run(self):
        if self.input_file:
            pkts = PcapReader(argv.file)
            for pkt in pkts:
                self.do_packet_analysis(pkt)
        else:
            signal.signal(signal.SIGINT, self.sigint_signal_handler)
            sniff(iface=argv.interface, prn=self.do_packet_analysis, filter="port %s" % argv.port, store=0)

        self.save_output()

    def do_packet_analysis(self, pkt):
        """
        main function which does packet analysis.
        On input is packet. After analis it create an nodes in xml sctructure
        """
        typ = TCP if (TCP in pkt) else None
        typ = UDP if (UDP in pkt and typ is None) else None
        if typ is None:
            return
        # filter out packets which have another source and destination port
        if (not ((pkt[typ].sport == self.port 
                or pkt[typ].dport == self.port)
                and int(pkt[typ].len) > self.MIN_RAW_DATA_LEN)):
            return
        if pkt[typ]:
            # get raw data from layer 7
            sip_data_list = pkt.sprintf("{Raw:%Raw.load%}").split("\\r\\n")

            # convert timestamp to isoformat
            timestamp = datetime.fromtimestamp(int(pkt.time)).isoformat()

            # parse main key status code for future decision 
            # what to do with packet and what does it mean
            status = sip_data_list[0]
            c_seq = ([sip_data for sip_data in sip_data_list 
                            if sip_data.startswith("CSeq: ")][0])

            # Save realm when user doing authentication
            for sip_data in sip_data_list:
                if sip_data.startswith("WWW-Authenticate: "):
                    realm = re.findall(r'realm="(.*?)"',sip_data)[0]
                    self.registration["authentication"]["realm"] = realm

            output_info("c_seq: %s, status: %s" % (c_seq, status))
            """
            Save ips of client and registrar when 
            some request about registration is maded
            """
            if "REGISTER" in status:
                ua_ip, r_ip = pkt.sprintf("{IP:%IP.src%-%IP.dst%}").split("-")
                self.registration["user-agent"]["ip"] = ua_ip
                self.registration["registrar"]["ip"] = r_ip
            """
            If self.registration is ok (registrar returns 200 OK code), 
            then save succesfull registration to xml
            """
            if "200 OK" in status and "REGISTER" in c_seq:
                for sip_data in sip_data_list:
                    if sip_data.startswith("To: "):
                        d = re.findall(r'<(.*?)>', sip_data)[0].strip("sip:")
                        u = d.split("@")[0]
                        r = d.split("@")[1]
                        self.registration["registrar"]["uri"] = r
                        self.registration["authentication"]["username"] = u
                        self.registration["user-agent"]["uri"] = d
                    if sip_data.startswith("Via: "):
                        u = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',sip_data)[0]
                        self.registration["authentication"]["uri"] = u #TODO not done

                self.registration["time"]["registration"] = timestamp
                self.save_registration()

            """
            Get data about who want to call where.
            """
            if "INVITE" in status and "INVITE" in c_seq:
                #pp(sip_data_list)
                for sip_data in sip_data_list:
                    if sip_data.startswith("From: "):
                        u = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                        self.call["caller"]["uri"] = u
                    if sip_data.startswith("m=audio"):
                        p = sip_data.split(" ")[1]
                        self.call["rtps"]["audio"]["caller"]["port"] = p
                    if sip_data.startswith("m=video"):
                        p = sip_data.split(" ")[1]
                        self.call["rtps"]["video"]["caller"]["port"] = p
                if self.call["time"].get("start","") is "":
                    self.call["time"]["start"] = timestamp
                self.call["rtps"]["audio"]["caller"]["ip"] = pkt.sprintf("{IP:%IP.src%}")
                self.call["rtps"]["video"]["caller"]["ip"] = pkt.sprintf("{IP:%IP.src%}")
                self.call["caller"]["ip"] = pkt.sprintf("{IP:%IP.src%}")

            """
            Parse data, if connection is established. That mean callee answer.
            """
            if "200" in status and "INVITE" in c_seq:
                pp(sip_data_list)
                codecs = []
                self.call["rtps"]["audio"]["payload_types"] = []
                self.call["rtps"]["video"]["payload_types"] = []
                for sip_data in sip_data_list:
                    # take caller uri
                    if sip_data.startswith("From: "):
                        self.call["caller"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                    # take callee uri
                    if sip_data.startswith("To: "):
                        self.call["callee"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                    # take callee ip
                    if sip_data.startswith("o="):
                        self.call["rtps"]["audio"]["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                        self.call["rtps"]["video"]["callee"]["ip"] = self.call["rtps"]["audio"]["callee"]["ip"]
                        self.call["callee"]["ip"] = self.call["rtps"]["audio"]["callee"]["ip"]
                    # take codecs
                    if sip_data.startswith("a=rtpmap:"):
                        #try:
                        codec = {
                            "payload-type":re.findall(r'rtpmap:([0-9]+)',sip_data)[0], 
                            "name":sip_data.split(" ")[-1]
                        }
                        codecs.append(codec)
                        #except Exception, e:
                        #    output_info(traceback.print_exc(e))

                    # take audio port and codecs
                    if sip_data.startswith("m=audio"):
                        self.call["rtps"]["audio"]["callee"]["port"] = sip_data.split(" ")[1]
                        for payload_number in sip_data.split(" "):
                            number = re.findall(r'[0-9]+', payload_number)
                            if len(number) > 0 and int(number[0]) != int(self.call["rtps"]["audio"]["callee"]["port"]):
                                self.call["rtps"]["audio"]["payload_types"].append(int(number[0]))
                    # take video port and codecs
                    if sip_data.startswith("m=video"):
                        self.call["rtps"]["video"]["callee"]["port"] = sip_data.split(" ")[1]
                        for payload_number in sip_data.split(" "):
                            number = re.findall(r'[0-9]+', payload_number)
                            if len(number) > 0 and int(number[0]) != int(self.call["rtps"]["video"]["callee"]["port"]):
                                self.call["rtps"]["video"]["payload_types"].append(int(number[0]))
                    # take callee ip
                    if sip_data.startswith("o="):
                        self.call["rtps"]["audio"]["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                        self.call["rtps"]["video"]["callee"]["ip"] = self.call["rtps"]["audio"]["callee"]["ip"]
                self.call["time"]["answer"] = timestamp
                print "--------------------------", self.call["rtps"]["video"]["callee"]["port"]
                self.call["rtps"]["audio"]["codecs"] = []
                self.call["rtps"]["video"]["codecs"] = []
                # sort codecs to video/audio
                for codec in codecs:
                    if int(codec["payload-type"]) in self.call["rtps"]["video"]["payload_types"]:
                        self.call["rtps"]["video"]["codecs"].append(codec)
                    if int(codec["payload-type"]) in self.call["rtps"]["audio"]["payload_types"]:
                        self.call["rtps"]["audio"]["codecs"].append(codec)


            """
            call is established, rtp communication will start in sec..
            get callers uri and ip of callee, also answer time is saved
            """
            if "183" in status and "INVITE" in c_seq:
                for sip_data in sip_data_list:
                    if sip_data.startswith("From: "):
                        self.call["caller"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                    if sip_data.startswith("To: "):
                        self.call["callee"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                    if sip_data.startswith("o="):
                        self.call["rtps"]["audio"]["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                        self.call["rtps"]["video"]["callee"]["ip"] = self.call["rtps"]["audio"]["callee"]["ip"]
                        self.call["callee"]["ip"] = self.call["rtps"]["audio"]["callee"]["ip"]

                self.call["time"]["answer"] = timestamp

            """
            If error ocurated (4xx - 6xx).
            """
            if (len(re.findall(r'[4-6][0-9][0-9]', status)) > 0
                    and "INVITE" in c_seq #invite request (call)
                    and "401" not in status #not save if "Unauthorized"
                    and "403" not in status
                    and "408" not in status
                    and "407" not in status #not save if "Proxy Authentication Required"
                    and not ("INVITE" in c_seq and "INVITE" in status)): # if double invite.. it is not final status, lets ignore that
                for sip_data in sip_data_list:
                    if sip_data.startswith("Contact: "):
                        self.call["callee"]["ip"] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sip_data)[0]
                    if sip_data.startswith("To: "):
                        self.call["callee"]["uri"] = re.findall('<(.*?)>',sip_data)[0].strip("sip:")
                self.call["time"]["answer"] = self.call["time"]["end"] = timestamp
                output_info("saving form ERROR %s & %s" % (status, c_seq))
                self.save_call()
                self.call["time"]["start"] = ""

            """
            Set end time, and save call data when status is BYE
            """
            if "BYE" in status:
                self.call["time"]["end"] = timestamp
                output_info("saving from BYE")
                self.save_call()
                self.call["time"]["start"] = ""

    def save_registration(self):
        """
        save registration data to xml scructure
        """
        registration_xml = ET.SubElement(self.root, "registration")
        registrar_xml = ET.SubElement(registration_xml, "registrar")
        registrar_xml.set("ip", self.registration["registrar"]["ip"]) # "212.242.33.35"
        registrar_xml.set("uri", self.registration["registrar"]["uri"]) # "sip.cybercity.dk"

        user_agent_xml = ET.SubElement(registration_xml, "user-agent")
        user_agent_xml.set("ip", self.registration["user-agent"]["ip"]) #"192.168.1.2"
        user_agent_xml.set("uri", self.registration["user-agent"]["uri"]) # voi18062@sip.cybercity.dk

        authentication_xml = ET.SubElement(registration_xml, "authentication")
        authentication_xml.set("username", self.registration["authentication"]["username"]) # "voi18062"
        authentication_xml.set("realm", self.registration["authentication"]["realm"]) # "sip.cybercity.dk"
        authentication_xml.set("uri", self.registration["authentication"]["uri"]) # "sip.cybercity.dk"

        time_xml = ET.SubElement(registration_xml, "time")
        time_xml.set("registration", self.registration["time"]["registration"]) #2005-12-30T09:00:00

    def save_call(self):
        """
        save call data to xml scructure
        """
        call_xml = ET.SubElement(self.root, "call")
        caller_xml = ET.SubElement(call_xml, "caller")
        caller_xml.set("ip", self.call["caller"]["ip"]) # "192.168.1.117"
        caller_xml.set("uri", self.call["caller"]["uri"]) # bbb@192.168.1.50

        callee_xml = ET.SubElement(call_xml, "callee")
        callee_xml.set("ip", self.call["callee"]["ip"]) # "192.168.1.117"
        callee_xml.set("uri", self.call["callee"]["uri"]) # bbb@192.168.1.50

        time_xml = ET.SubElement(call_xml, "time")
        time_xml.set("start", self.call["time"]["start"]) # 2013-08-15T09:00:02
        time_xml.set("answer", self.call["time"]["answer"]) # 2013-08-15T09:00:02
        time_xml.set("end", self.call["time"]["end"]) # 2013-08-15T09:00:02
        for rtp in self.call["rtps"].values():
            pp(rtp)
            if len(rtp["payload_types"]) is 0:
                continue
            rtp_xml = ET.SubElement(call_xml, "rtp")
            caller_xml = ET.SubElement(rtp_xml, "caller")
            caller_xml.set("ip", rtp["caller"]["ip"]) # "192.168.1.117"
            caller_xml.set("port", rtp["caller"]["port"]) # "5084"

            callee_xml = ET.SubElement(rtp_xml, "callee")
            callee_xml.set("ip", rtp["callee"]["ip"]) # "192.168.1.50"
            callee_xml.set("port", rtp["callee"]["port"]) # "5066"

            codec_xml = ET.SubElement(rtp_xml, "codec")
            for codec in rtp["codecs"]:
                codec_xml.set("payload-type", codec["payload-type"]) # "3"
                codec_xml.set("name", codec["name"]) # gsm/8000/1

    def save_output(self):
        """
        save xml to file
        """
        indent(self.root)
        tree = ET.ElementTree(self.root)
        tree.write(self.output_file)
    def sigint_signal_handler(self, signum, frame):
        self.save_output()
        exit(1)

def indent(elem, level=0):
    """
    function just for readable format of xml output
    copied from
    http://stackoverflow.com/a/4590052/2540163
    """
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def output_info(msg):
    sys.stderr.write(msg+"\n")

def output_error(msg):
    sys.stderr.write(msg+"\n")
    exit(1)

if __name__ == "__main__":
    DEFAULT_SIP_SIGNALIZATION_PORT = 5060
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="data pro analyzu se ziskaji ze souboru formatu pcap se zadanym nazvem")
    parser.add_argument("-i", "--interface",type=str, help="data se odchytavaji s rozhranim se zadanym nazvem")
    parser.add_argument("-o", "--output", type=str, help="vysledky sa zapisi do souboru se zadanym nazvem")
    parser.add_argument("-p", "--port", type=int, help="cislo portu na kterem probiha signalizace SIP", default=DEFAULT_SIP_SIGNALIZATION_PORT)
    argv = parser.parse_args()
    if (argv.file is None and argv.interface is None) or (argv.file and argv.interface):
        output_error("musi byt zadano %r nebo %r\n" % ("-f", "-i"))

    if argv.output is None:
        output_error("Musi byt zadano %r\n" % ("-o", ))

    SipScaner(argv.file, argv.interface, argv.port, argv.output).run()
