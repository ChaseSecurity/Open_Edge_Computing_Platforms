from collections import defaultdict
from concurrent.futures.thread import _worker
import json
import os
import sys
import logging
import argparse
import datetime
import dpkt
import dpkt_methods
from dpkt_methods import check_tls_version, client_hello_ssl_v2, parse_client_records, parse_certificate_records, is_bittorrent_handshake, parse_bittorrent_handshake, is_bittorrent_protocol, parse_bittorrent
from threading import Thread
from dpkt_http_methods import Request, Response
from dpkt.compat import BytesIO, iteritems
import gzip
import re


#from io import stringIO
class TCPConnection:
    # for tcp connection
    def __init__(self):
        self.ip_port = None # record this connection ip port keywords, such as (src_ip,src_port,dst_ip,dst_port)
        self.start_timestamp = None # record this connection start time
        self.end_timestamp = None # record this connection end time
        self.packet_count = 0 # record this connection's packets num
        self.byte_count = 0 # record this connection's bytes num
        self.src_dst_packet_count = 0 # record packets num from source IP to destination IP
        self.dst_src_packet_count = 0 # record packets num from destination IP to source IP
        self.src_dst_byte_count = 0 # record bytes num from source IP to destination IP
        self.dst_src_byte_count = 0 # record bytes num from destination IP to source IP
        self.protocol_type = "tcp" # record this connection protocol
        self.http_req_time = None # If this connection protocol is http, then record the request time
        self.https_SNI = "" # if this connection protocol is https, then record the Sever Name Indication
        self.https_SNI_ip = "" # record which IP corresponding this SNI 
        self.https_SNI_time = None # record send this SNI packet time
        self.https_Cert_domain = "" # record send this cert domain
        self.https_Cert_ip = "" # record send this cert IP
        self.https_Cert_time = None # record this cert time
        self.bit_peer_ip_1 = "" # if this protocol is BitTorrent, record send keywords IP, only find in OneThingCloud
        self.bit_peer_id_1 = "" # if this protocol is BitTorrent, record send keywords
        self.bit_peer_ip_2 = ""
        self.bit_peer_id_2 = ""
        self.xunlei_ip_1 = "" # if this protocol belong xunlei provider, record send keywords IP, only find in OneThingCloud
        self.xunlei_id_1 = "" # if this protocol belong xunlei provider, record send keywords
        self.xunlei_ip_2 = ""
        self.xunlei_id_2 = ""
        self.RTT = {} # record this RTT
        self.RTT_Results = {}
        self.syn_flag = 0
        self.fin_flag = 0
        self.rst_flag = 0


class UDPConnection:
    # for udp connection
    def __init__(self):
        self.ip_port = None
        self.start_timestamp = None
        self.end_timestamp = None
        self.packet_count = 0
        self.byte_count = 0
        self.src_dst_packet_count = 0
        self.dst_src_packet_count = 0
        self.src_dst_byte_count = 0
        self.dst_src_byte_count = 0
        self.bit_peer_ip_1 = ""
        self.bit_peer_id_1 = ""
        self.bit_peer_ip_2 = ""
        self.bit_peer_id_2 = ""
        self.toutiao_ip = ""
        self.toutiao_value = ""
        self.toutiao_location = 0
        self.xunlei_ip_1 = ""
        self.xunlei_id_1 = ""
        self.xunlei_ip_2 = ""
        self.xunlei_id_2 = ""
        self.stun_values = []
        self.protocol_type = "udp"


class ReqResBody:

    def __init__(self):
        self.req = None
        self.res = None
        self.ip_port = None
        self.req_time = None
        self.res_time = None
        self.flag = 0


class ProcessPcapTT:
    # input source file and destination dictory
    def __init__(self, src_file, dst_dir, file_data=None):
        if not os.path.isfile(src_file):
            logging.info("please input source file")
            sys.exit()
        self.src_file = src_file
        self.dst_dir = dst_dir
        self.SNI = []
        self.Certs = {}
        self.Cert_domain_time = []
        self.ts_domain_ip = []
        self.tmp_con = {}
        self.savecon_list = []
        self.tmp_http = {}
        self.http_list = []
        self.tcp_num = 0
        #self.udp_sessions = {}
        self.tmp_udp = {}
        self.udpcon_list = []
        self.xycdn_stun_ip_port_dict = {}
        self.xycdn_websocket_streams = {}
        if not file_data:
            self.file_data = {
                "noip_packets": 0,
                "packets_count": 0,
                "tcp_packets": 0,  # tcp packets number
                "tcp_packets_len": 0,  # tcp packets all length
                "tcp_payload_len": 0,
                "udp_packets": 0,  # udp packets number
                "udp_packets_len": 0,  # udp packets all length
                "udp_payload_len": 0,
                "icmp_packets": 0,
                "other_ip_protocol_packets": 0,
            }
        else:
            self.file_data = file_data

    def main(self):
        fd = open(self.src_file, 'rb')
        logging.info("Start Process")
        logging.info(f"{self.src_file}")
        # read pcap file as dpkt_mode
        try:
            pcap = dpkt.pcap.Reader(fd)
        except Exception as e:
            logging.error(
                "Read File ERROR,maybe is none or not a pcap file \n Exception: {}"
                .format(e))
            return
        loop_num = 0
        # process each payload
        try:
            for (ts, buf) in pcap:
                timestamp = str(datetime.datetime.fromtimestamp(ts))
                if loop_num % 100000 == 0:
                    logging.info("""
                        loop_num is {},packets_count is {},percent is {:.2f}%,
                        tcp packets are {},udp packets are {},icmp packets are {},other_ip_protocol_packets are {},noip_packets are {},
                        """.format(
                        loop_num,
                        self.file_data["packets_count"],
                        self.file_data["packets_count"] * 100 / loop_num if loop_num != 0 else self.file_data["packets_count"],
                        self.file_data["tcp_packets"],
                        self.file_data["udp_packets"],
                        self.file_data["icmp_packets"],
                        self.file_data["other_ip_protocol_packets"],
                        self.file_data["noip_packets"],
                    ))
                loop_num += 1
                try:
                    # if it is Linux cooked capture v1
                    if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                        eth = dpkt.sll.SLL(buf)
                    elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                        eth = dpkt.sll2.SLL2(buf)
                    else:
                        eth = dpkt.ethernet.Ethernet(buf)
                except Exception as e:
                    logging.warning(
                        "this packet can't be decompress,packet_time is {},\n Exception: {}"
                        .format(timestamp, e))
                    continue
                try:
                    self.file_data["packets_count"] += 1
                    # if IP is not,continue
                    if not isinstance(eth.data, dpkt.ip.IP):
                        self.file_data["noip_packets"] += 1
                        continue
                    ip = eth.data
                    # for tcp
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        self.tcp_num += 1
                        ip_port, tcp = dpkt_methods.parse_ip(ip)
                        self.file_data["tcp_packets"] += 1
                        self.file_data["tcp_packets_len"] += len(buf)
                        self.file_data["tcp_payload_len"] += len(tcp.data)
                        try:
                            self._tcp_connection(timestamp, ip_port, tcp, ts)
                        except Exception as e:
                            logging.error(
                                "Maybe error in _tcp_connection method,packet_time is {} ,tcp ip_port is {}\n Exception: {}"
                                .format(timestamp, ip_port, e))
                            continue
                    # for udp
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        ip_port, udp = dpkt_methods.parse_ip(ip)
                        self.file_data["udp_packets"] += 1
                        self.file_data["udp_packets_len"] += len(buf)
                        self.file_data["udp_payload_len"] += len(udp.data)
                        try:
                            dns_flag = self._dns_packet_parse(timestamp, udp)
                            if dns_flag == 0:
                                self._udp_connection(ts, ip_port, udp)
                        except Exception as e:
                            logging.error(
                                "Maybe error in _dns_packet_parse method,packet_time is {} ,udp ip_port is {}\n Exception: {}"
                                .format(timestamp, ip_port, e))
                            continue
                    # for icmp
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        self.file_data["icmp_packets"] += 1
                    else:
                        self.file_data["other_ip_protocol_packets"] += 1
                except Exception as e:
                    logging.critical(
                        "there may be have critical error in methods block,time is {} \n Exception: {}"
                        .format(timestamp, e))
                    continue
        except Exception as e:
            logging.critical(
                "there may be have critical error in main \"for\" loop \n Exception: {}"
                .format(e))
        fd.close()
        # pcap end ,once have fin_flag can be move to save
        self._move_tmp_to_save(fin_flag_count=1)
        for ip_port_key in list(self.tmp_udp.keys()):
            self.udpcon_list.append(self.tmp_udp[ip_port_key])
            self.tmp_udp.pop(ip_port_key)
        logging.info("""
            loop_num is {},packets_count is {},percent is {:.2f}%,
            tcp packets are {},udp packets are {},icmp packets are {},other_ip_protocol_packets are {},noip_packets are {},
            """.format(
            loop_num,
            self.file_data["packets_count"],
            self.file_data["packets_count"] * 100 / loop_num,
            self.file_data["tcp_packets"],
            self.file_data["udp_packets"],
            self.file_data["icmp_packets"],
            self.file_data["other_ip_protocol_packets"],
            self.file_data["noip_packets"],
        ))
        logging.info("self.savecon_list len is {}".format(
            len(self.savecon_list)))
        logging.info("self.tmp_con len is {}".format(len(self.tmp_con)))
        logging.info("self.save_http len is {}".format(len(self.http_list)))
        logging.info("self.tmp_http is {}".format(len(self.tmp_http)))
        logging.info("self.tcp_num is {}".format(self.tcp_num))
        logging.info("self.Certs is {}".format(len(self.Certs)))
        logging.info("self.Cert_domain_time is {}".format(
            len(self.Cert_domain_time)))
        return self.file_data, self.ts_domain_ip, self.savecon_list, self.http_list, self.SNI, self.tmp_con, self.tmp_http, self.Certs, self.Cert_domain_time, self.udpcon_list,self.xycdn_stun_ip_port_dict

    def _udp_connection(self, ts, ip_port, udp):
        # Sort the source IP and destination IP addresses
        src_ip = ip_port["src_ip"]
        dst_ip = ip_port["dst_ip"]
        src_port = ip_port["src_port"]
        dst_port = ip_port["dst_port"]
        payload = udp.data
        key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)
        udp_toutiao_list = self._udp_toutiao(payload)

        if key not in self.tmp_udp and reverse_key not in self.tmp_udp:
            udc = UDPConnection()
            udc.ip_port = key
            udc.src_dst_byte_count += len(payload)
            udc.byte_count += len(payload)
            udc.src_dst_packet_count += 1
            udc.packet_count += 1
            udc.start_timestamp = ts
            udc.end_timestamp = ts
            if udp_toutiao_list[0] != 0:
                udc.protocol_type = "toutiao"
                udc.toutiao_ip = ip_port["src_ip"]
                udc.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
            self.tmp_udp[key] = udc

        elif key in self.tmp_udp:
            udp_item = self.tmp_udp[key]
            udp_item.src_dst_byte_count += len(payload)
            udp_item.byte_count += len(payload)
            udp_item.src_dst_packet_count += 1
            udp_item.packet_count += 1
            if ts > udp_item.end_timestamp:
                udp_item.end_timestamp = ts

            if udp_toutiao_list[0] != 0:
                udp_item.protocol_type = "toutiao"
                udp_item.toutiao_ip = ip_port["src_ip"]
                udp_item.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
        elif reverse_key in self.tmp_udp:
            udp_item = self.tmp_udp[reverse_key]
            udp_item.dst_src_byte_count += len(payload)
            udp_item.byte_count += len(payload)
            udp_item.dst_src_packet_count += 1
            udp_item.packet_count += 1
            if ts > udp_item.end_timestamp:
                udp_item.end_timestamp = ts
            if udp_toutiao_list[0] != 0:
                udp_item.protocol_type = "toutiao"
                udp_item.toutiao_ip = ip_port["src_ip"]
                udp_item.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
        # The Stun protocol contains keywords related to OneThingCloud
        if udp_toutiao_list[0] == 0 and dpkt_methods.is_stun_packet(payload):
            # Analyze the various fields in STUN messages
            stun_pkt = dpkt.stun.STUN(payload)
            msg_type = stun_pkt.type
            msg_length = len(payload)
            try:
                attrs = dpkt.stun.parse_attrs(stun_pkt.data)
                for item in attrs:
                    if item[0] == 57346:
                        new_item = item[1].decode('utf-8')
                        new_data = json.loads(new_item.strip())
                        new_data["data_ip"] = src_ip
                        if key in self.tmp_udp:
                            self.tmp_udp[key].stun_values.append(new_data)
                            self.tmp_udp[key].protocol_type = "stun"
                        else:
                            self.tmp_udp[reverse_key].stun_values.append(
                                new_data)
                            self.tmp_udp[reverse_key].protocol_type = "stun"
            except Exception as e:
                pass

        #Export UDP connection from tmp_com
        if len(self.tmp_udp) > 1500:
            for ip_port_key in list(self.tmp_udp.keys()):
                self.udpcon_list.append(self.tmp_udp[ip_port_key])
                self.tmp_udp.pop(ip_port_key)

    def _udp_toutiao(self, payload):
        if b'toutiaovod.com' in payload[50:]:
            return [
                1, payload[50:].split(b'\x00', 1)[0].decode('utf-8', 'ignore'),50
            ]
        elif b'toutiaovod.com' in payload[30:]:
            return [
                1,payload[30:].split(b'\x00',1)[0].decode('utf-8','ignore'),30
            ]
        else:
            return [0]

    def _tcp_connection(self, timestamp, ip_port, tcp, ts):
        flags, seqAck, payload = dpkt_methods.parse_tcp(tcp)
        ip_port_key = dpkt_methods.get_ip_port_key(ip_port)
        reverse_ip_port_key = dpkt_methods.get_reverse_ip_port_key(ip_port)

        # first handshake
        if flags["syn_flag"] and not flags["ack_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:  #one tcp connection need to pop,new tcp connection need to be established
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.savecon_list.append(self.tmp_con[ip_port_key])
                self.tmp_con.pop(ip_port_key)
            elif reverse_ip_port_key in self.tmp_con:
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.savecon_list.append(self.tmp_con[reverse_ip_port_key])
                self.tmp_con.pop(reverse_ip_port_key)
            tco = TCPConnection()
            tco.ip_port = ip_port_key
            tco.start_timestamp = timestamp
            tco.end_timestamp = timestamp
            tco.syn_flag += 1
            seq_end = seqAck["seq_num"] + 1  # first handshake ack = seq + 1
            tmp_ip = ip_port_key.split("-")[0]
            tco.RTT.setdefault(tmp_ip, {})[seq_end] = ts
            self.tmp_con[ip_port_key] = tco
            self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)

        # second handshake
        elif flags["syn_flag"] and flags["ack_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if reverse_ip_port_key not in self.tmp_con:
                tco = TCPConnection()
                tco.ip_port = reverse_ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.syn_flag += 1
                seq_end = seqAck["seq_num"] + 1  # second handshake ack = seq + 1
                tmp_ip = reverse_ip_port_key.split("-")[2]
                tco.RTT.setdefault(tmp_ip, {})[seq_end] = ts
                self.tmp_con[reverse_ip_port_key] = tco
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)
            else:
                seq_end = seqAck["seq_num"] + 1 
                tmp_ip = reverse_ip_port_key.split("-")[2]
                self.tmp_con[reverse_ip_port_key].RTT.setdefault(
                    tmp_ip, {})[seq_end] = ts
                self.tmp_con[reverse_ip_port_key].syn_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)
        # good bye
        elif flags["fin_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                self.tmp_con[ip_port_key].fin_flag += 1
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
            elif reverse_ip_port_key in self.tmp_con:
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                self.tmp_con[reverse_ip_port_key].fin_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
            else:
                # don't need
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.fin_flag += 1
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
        # interrupt
        elif flags["rst_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                self.tmp_con[ip_port_key].rst_flag += 1
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
            elif reverse_ip_port_key in self.tmp_con:
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                self.tmp_con[reverse_ip_port_key].rst_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
            else:
                # don't need
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.rst_flag += 1
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
        # normal commucation
        elif flags["ack_flag"]:
            httpflaglist = self._http_connection(timestamp, ip_port_key, reverse_ip_port_key, payload)#judge whether is http protocol
            if httpflaglist[0] == 0:#judge whether is https protocol
                httpsflaglist = self._https_connection(timestamp, ip_port_key, payload)
            else:
                httpsflaglist = [0]

            if ip_port_key in self.tmp_con:
                tmp_ip = ip_port_key.split("-")[0]
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.tcp_rtt_values(ip_port_key, seqAck["ack_num"], ts)

            elif reverse_ip_port_key in self.tmp_con:
                tmp_ip = reverse_ip_port_key.split("-")[2]
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)

            else:
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tmp_ip = ip_port_key.split("-")[0]
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.tcp_rtt_values(ip_port_key, seqAck["ack_num"], ts)

        else:
            logging.info("tcp connection time is {}".format(timestamp))
        if len(self.tmp_con) >= 1000:
            self._move_tmp_to_save()

    def _http_connection(self, timestamp, ip_port_key, reverse_ip_port_key,
                         payload):
        if ip_port_key in self.tmp_http and self.tmp_http[
                ip_port_key].req is not None:  # Next request packet
            if self.tmp_http[ip_port_key].req.length_chunked_gzip[
                    "need_length"] > 0:
                if self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "gzip"] == 0:
                    self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "need_length"] -= len(payload)
                    self.tmp_http[ip_port_key].req.body += payload
                else:
                    self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "need_length"] -= len(payload)
                    try:
                        body = gzip.decompress(payload)
                        self.tmp_http[ip_port_key].req.body += body
                    except Exception:
                        self.tmp_http[ip_port_key].req.body += payload
            return [1]
        elif reverse_ip_port_key in self.tmp_http and self.tmp_http[
                reverse_ip_port_key].res is not None:  # Next response packet
            if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] > 0:  # first packet maybe have content-length
                self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] -= len(payload)
                if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                        "gzip"] == 0:
                    self.tmp_http[reverse_ip_port_key].res.body += payload
                else:  #gzip decompress
                    try:
                        body = gzip.decompress(payload)
                        self.tmp_http[reverse_ip_port_key].res.body += body
                    except:
                        self.tmp_http[ip_port_key].res.body += payload
            if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] == 0 or self.tmp_http[
                        reverse_ip_port_key].res.length_chunked_gzip[
                            "need_length"] > 5120:  # need log data,other type file such as video don't need
                self.http_list.append(self.tmp_http[reverse_ip_port_key])
                del self.tmp_http[reverse_ip_port_key]
            return [1]
        try:
            requestbody = Request(payload)
            reqresbody = ReqResBody()
            reqresbody.req = requestbody
            reqresbody.ip_port = ip_port_key
            reqresbody.req_time = timestamp
            self.tmp_http[ip_port_key] = reqresbody
            return [1, reqresbody.req_time, ip_port_key]
        except Exception:
            try:
                responsebody = Response(payload)
                if reverse_ip_port_key in self.tmp_http:
                    self.tmp_http[reverse_ip_port_key].res = responsebody
                    self.tmp_http[reverse_ip_port_key].res_time = timestamp
                    if self.tmp_http[
                            reverse_ip_port_key].req.length_chunked_gzip[
                                "need_length"] == 0 and self.tmp_http[
                                    reverse_ip_port_key].res.length_chunked_gzip[
                                        "need_length"] == 0:
                        self.http_list.append(
                            self.tmp_http[reverse_ip_port_key])
                        del self.tmp_http[reverse_ip_port_key]
                    return [1]
                else:
                    return [1]
            except Exception:
                return [0]

    def _dns_packet_parse(self, timestamp, udp):
        try:
            dns = dpkt.dns.DNS(udp.data)
        except Exception:
            return 0
        domain_ip = dpkt_methods.parse_dns_response(dns)
        if domain_ip:
            domain_ip["timestamp"] = timestamp
            self.ts_domain_ip.append(domain_ip)
        else:
            return 1
        return 1

    def _https_connection(self, timestamp, ip_port_key, payload):
        https_flag = 0
        try:
            is_tls_v2, version3 = check_tls_version(payload)
            if not (is_tls_v2 or version3):
                return [0]
            try:
                if is_tls_v2:
                    length = client_hello_ssl_v2(payload)
                    records, bytes_used = dpkt.ssl.tls_multi_factory(
                        payload[length:])
                else:
                    records, bytes_used = dpkt.ssl.tls_multi_factory(payload)
            except Exception:
                return [0]
            # https_flag = 1
            reslist = parse_client_records(records, https_flag)
            server_name = reslist[0]
            https_flag = reslist[1]
            if server_name != "1":
                jsonline = {
                    "sni_domain": server_name,
                    "sni_ip": ip_port_key.split("-")[2],
                    "timestamp": timestamp
                }
                self.SNI.append(jsonline)
                return [1, server_name, ip_port_key.split("-")[2], timestamp]
            else:  # maybe have certificate
                reslist = parse_certificate_records(records, https_flag)
                cert_fingerprint_domains_certs = reslist[0]
                https_flag = reslist[1]
                if len(cert_fingerprint_domains_certs) > 0:
                    for key in cert_fingerprint_domains_certs:
                        if key not in self.Certs:
                            self.Certs[key] = cert_fingerprint_domains_certs[
                                key][1]
                        jsonline = {
                            "sha256_fingerprint": key,
                            "domains":
                            list(cert_fingerprint_domains_certs[key][0]),
                            "timestamp": timestamp
                        }
                        #logging.info(jsonline)
                        self.Cert_domain_time.append(jsonline)
                        return [
                            1,
                            list(cert_fingerprint_domains_certs[key][0])[0],
                            ip_port_key.split("-")[0], timestamp, "cert"
                        ]
                return [https_flag]
        except Exception:
            return [https_flag]

    def _move_tmp_to_save(self, fin_flag_count=2):
        for ip_port_key in list(self.tmp_con.keys()):
            if self.tmp_con[ip_port_key].syn_flag >= 1 and (
                    self.tmp_con[ip_port_key].fin_flag >= fin_flag_count
                    or self.tmp_con[ip_port_key].rst_flag >= 1):
                self.savecon_list.append(self.tmp_con[ip_port_key])
                self.tmp_con.pop(ip_port_key)

    def tcp_rtt_values(self, ip_port_key, ack_num, ts):
        ip = ip_port_key.split("-")[0]  #
        tmp_RTT_dict = self.tmp_con[ip_port_key].RTT.get(ip, {})

        if ack_num in tmp_RTT_dict:
            sent_ts = tmp_RTT_dict[ack_num]
            rtt = ts - sent_ts
            try:
                self.tmp_con[ip_port_key].RTT_Results.setdefault(ip, []).append(rtt)
                del tmp_RTT_dict[ack_num]
            except Exception as e:
                logging.info(e)
        else:
            ip = ip_port_key.split("-")[2]  #
            tmp_RTT_dict = self.tmp_con[ip_port_key].RTT.get(ip, {})
            if ack_num in tmp_RTT_dict:
                sent_ts = tmp_RTT_dict[ack_num]
                rtt = ts - sent_ts
                try:
                    self.tmp_con[ip_port_key].RTT_Results.setdefault(ip, []).append(rtt)
                    del tmp_RTT_dict[ack_num]
                except Exception as e:
                    logging.info(e)

    def _assignment_values_to_con(self,ip_port_key, tcp_payload, httpflaglist,httpsflaglist,reverse):
        self.tmp_con[ip_port_key].byte_count += len(tcp_payload)
        self.tmp_con[ip_port_key].packet_count += 1
        if reverse == 0:
            self.tmp_con[ip_port_key].src_dst_byte_count += len(tcp_payload)
            self.tmp_con[ip_port_key].src_dst_packet_count += 1
        else:
            self.tmp_con[ip_port_key].dst_src_byte_count += len(tcp_payload)
            self.tmp_con[ip_port_key].dst_src_packet_count += 1
        if httpflaglist[0] == 1:
            if len(httpflaglist) == 1:
                self.tmp_con[ip_port_key].protocol_type = "http"
            else:
                self.tmp_con[ip_port_key].protocol_type = "http"
                self.tmp_con[ip_port_key].http_req_time = httpflaglist[1]
        else:
            if len(httpsflaglist) == 4:
                self.tmp_con[ip_port_key].protocol_type = "https"
                self.tmp_con[ip_port_key].https_SNI = httpsflaglist[1]
                self.tmp_con[ip_port_key].https_SNI_ip = httpsflaglist[2]
                self.tmp_con[ip_port_key].https_SNI_time = httpsflaglist[3]
            elif len(httpsflaglist) == 5:
                self.tmp_con[ip_port_key].protocol_type = "https"
                self.tmp_con[ip_port_key].https_Cert_domain = httpsflaglist[1]
                self.tmp_con[ip_port_key].https_Cert_ip = httpsflaglist[2]
                self.tmp_con[ip_port_key].https_Cert_time = httpsflaglist[3]
            elif httpsflaglist[0] == 1:
                self.tmp_con[ip_port_key].protocol_type = "https"
        return None



class ProcessPcapWXY:
    # input source file and destination dictory
    def __init__(self, src_file, dst_dir, file_data=None):
        if not os.path.isfile(src_file):
            logging.info("please input source file")
            sys.exit()
        self.src_file = src_file
        self.dst_dir = dst_dir
        self.SNI = []
        self.Certs = {}
        self.Cert_domain_time = []
        self.ts_domain_ip = []
        self.tmp_con = {}
        self.savecon_list = []
        self.tmp_http = {}
        self.http_list = []
        self.tcp_num = 0
        #self.udp_sessions = {}
        self.tmp_udp = {}
        self.udpcon_list = []
        self.xycdn_stun_ip_port_dict = {}
        self.xycdn_websocket_streams = {}
        if not file_data:
            self.file_data = {
                "noip_packets": 0,
                "packets_count": 0,
                "tcp_packets": 0,  # tcp packets number
                "tcp_packets_len": 0,  # tcp packets all length
                "tcp_payload_len": 0,
                "udp_packets": 0,  # udp packets number
                "udp_packets_len": 0,  # udp packets all length
                "udp_payload_len": 0,
                "icmp_packets": 0,
                "other_ip_protocol_packets": 0,
            }
        else:
            self.file_data = file_data

    def main(self):
        fd = open(self.src_file, 'rb')
        logging.info("Start Process")
        logging.info(f"{self.src_file}")
        # read pcap file as dpkt_mode
        try:
            pcap = dpkt.pcap.Reader(fd)
        except Exception as e:
            logging.error(
                "Read File ERROR,maybe is none or not a pcap file \n Exception: {}"
                .format(e))
            return
        loop_num = 0
        # process each payload
        try:
            for (ts, buf) in pcap:
                timestamp = str(datetime.datetime.fromtimestamp(ts))
                if loop_num % 100000 == 0:
                    logging.info("""
                        loop_num is {},packets_count is {},percent is {:.2f}%,
                        tcp packets are {},udp packets are {},icmp packets are {},other_ip_protocol_packets are {},noip_packets are {},
                        """.format(
                        loop_num,
                        self.file_data["packets_count"],
                        self.file_data["packets_count"] * 100 / loop_num if loop_num != 0 else self.file_data["packets_count"],
                        self.file_data["tcp_packets"],
                        self.file_data["udp_packets"],
                        self.file_data["icmp_packets"],
                        self.file_data["other_ip_protocol_packets"],
                        self.file_data["noip_packets"],
                    ))
                loop_num += 1
                try:
                    # if it is Linux cooked capture v1
                    if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                        eth = dpkt.sll.SLL(buf)
                    elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                        eth = dpkt.sll2.SLL2(buf)
                    else:
                        eth = dpkt.ethernet.Ethernet(buf)
                except Exception as e:
                    logging.warning(
                        "this packet can't be decompress,packet_time is {},\n Exception: {}"
                        .format(timestamp, e))
                    continue
                try:
                    self.file_data["packets_count"] += 1
                    # if IP is not,continue
                    if not isinstance(eth.data, dpkt.ip.IP):
                        self.file_data["noip_packets"] += 1
                        continue
                    ip = eth.data
                    # for tcp
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        self.tcp_num += 1
                        ip_port, tcp = dpkt_methods.parse_ip(ip)
                        self.file_data["tcp_packets"] += 1
                        self.file_data["tcp_packets_len"] += len(buf)
                        self.file_data["tcp_payload_len"] += len(tcp.data)
                        try:
                            self._tcp_connection(timestamp, ip_port, tcp, ts)
                        except Exception as e:
                            logging.error(
                                "Maybe error in _tcp_connection method,packet_time is {} ,tcp ip_port is {}\n Exception: {}"
                                .format(timestamp, ip_port, e))
                            continue
                    # for udp
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        ip_port, udp = dpkt_methods.parse_ip(ip)
                        self.file_data["udp_packets"] += 1
                        self.file_data["udp_packets_len"] += len(buf)
                        self.file_data["udp_payload_len"] += len(udp.data)
                        try:
                            dns_flag = self._dns_packet_parse(timestamp, udp)
                            if dns_flag == 0:
                                self._udp_connection(ts, ip_port, udp)
                        except Exception as e:
                            logging.error(
                                "Maybe error in _dns_packet_parse method,packet_time is {} ,udp ip_port is {}\n Exception: {}"
                                .format(timestamp, ip_port, e))
                            continue
                    # for icmp
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        self.file_data["icmp_packets"] += 1
                    else:
                        self.file_data["other_ip_protocol_packets"] += 1
                except Exception as e:
                    logging.critical(
                        "there may be have critical error in methods block,time is {} \n Exception: {}"
                        .format(timestamp, e))
                    continue
        except Exception as e:
            logging.critical(
                "there may be have critical error in main \"for\" loop \n Exception: {}"
                .format(e))
        fd.close()
        # pcap end ,once have fin_flag can be move to save
        self._move_tmp_to_save(fin_flag_count=1)
        for ip_port_key in list(self.tmp_udp.keys()):
            self.udpcon_list.append(self.tmp_udp[ip_port_key])
            self.tmp_udp.pop(ip_port_key)
        logging.info("""
            loop_num is {},packets_count is {},percent is {:.2f}%,
            tcp packets are {},udp packets are {},icmp packets are {},other_ip_protocol_packets are {},noip_packets are {},
            """.format(
            loop_num,
            self.file_data["packets_count"],
            self.file_data["packets_count"] * 100 / loop_num,
            self.file_data["tcp_packets"],
            self.file_data["udp_packets"],
            self.file_data["icmp_packets"],
            self.file_data["other_ip_protocol_packets"],
            self.file_data["noip_packets"],
        ))
        logging.info("self.savecon_list len is {}".format(len(self.savecon_list)))
        logging.info("self.tmp_con len is {}".format(len(self.tmp_con)))
        logging.info("self.save_http len is {}".format(len(self.http_list)))
        logging.info("self.tmp_http is {}".format(len(self.tmp_http)))
        logging.info("self.tcp_num is {}".format(self.tcp_num))
        logging.info("self.Certs is {}".format(len(self.Certs)))
        logging.info("self.Cert_domain_time is {}".format(len(self.Cert_domain_time)))
        logging.info("self.xycdn_stun_ip_port_dict is {}".format(len(self.xycdn_stun_ip_port_dict)))
        return self.file_data, self.ts_domain_ip, self.savecon_list, self.http_list, self.SNI, self.tmp_con, self.tmp_http, self.Certs, self.Cert_domain_time, self.udpcon_list,self.xycdn_stun_ip_port_dict
      
    def _tcp_connection(self, timestamp, ip_port, tcp, ts):
        flags, seqAck, payload = dpkt_methods.parse_tcp(tcp)
        ip_port_key = dpkt_methods.get_ip_port_key(ip_port)
        reverse_ip_port_key = dpkt_methods.get_reverse_ip_port_key(ip_port)
        # first handshake
        if flags["syn_flag"] and not flags["ack_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:  #one tcp connection need to pop,new tcp connection need to be established
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.savecon_list.append(self.tmp_con[ip_port_key])
                self.tmp_con.pop(ip_port_key)
            elif reverse_ip_port_key in self.tmp_con:
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.savecon_list.append(self.tmp_con[reverse_ip_port_key])
                self.tmp_con.pop(reverse_ip_port_key)
            tco = TCPConnection()
            tco.ip_port = ip_port_key
            tco.start_timestamp = timestamp
            tco.end_timestamp = timestamp
            tco.syn_flag += 1
            seq_end = seqAck["seq_num"] + 1  # first handshake ack = seq + 1
            tmp_ip = ip_port_key.split("-")[0]
            tco.RTT.setdefault(tmp_ip, {})[seq_end] = ts
            self.tmp_con[ip_port_key] = tco
            self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)

        # second handshake
        elif flags["syn_flag"] and flags["ack_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if reverse_ip_port_key not in self.tmp_con:
                tco = TCPConnection()
                tco.ip_port = reverse_ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.syn_flag += 1
                seq_end = seqAck["seq_num"] + 1  # second handshake ack = seq + 1
                tmp_ip = reverse_ip_port_key.split("-")[2]
                tco.RTT.setdefault(tmp_ip, {})[seq_end] = ts
                self.tmp_con[reverse_ip_port_key] = tco
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)
            else:
                seq_end = seqAck[
                    "seq_num"] + 1  
                tmp_ip = reverse_ip_port_key.split("-")[2]
                self.tmp_con[reverse_ip_port_key].RTT.setdefault(
                    tmp_ip, {})[seq_end] = ts
                self.tmp_con[reverse_ip_port_key].syn_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)
        # good bye
        elif flags["fin_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                self.tmp_con[ip_port_key].fin_flag += 1
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
            elif reverse_ip_port_key in self.tmp_con:
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                self.tmp_con[reverse_ip_port_key].fin_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
            else:
                # don't need
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.fin_flag += 1
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
        # interrupt
        elif flags["rst_flag"]:
            httpflaglist = [0]
            httpsflaglist = [0]
            if ip_port_key in self.tmp_con:
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                self.tmp_con[ip_port_key].rst_flag += 1
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
            elif reverse_ip_port_key in self.tmp_con:
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                self.tmp_con[reverse_ip_port_key].rst_flag += 1
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
            else:
                # don't need
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                tco.rst_flag += 1
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
        # normal commucation
        elif flags["ack_flag"]:
            if ip_port["src_port"] == 8408 or ip_port["dst_port"] == 8408:#xycdn websocket stream
                self._xycdn_websocket(ip_port_key,payload)
            if ip_port_key in self.tmp_con:
                seq_end = seqAck["seq_num"] + len(payload)
                tmp_ip = ip_port_key.split("-")[0]
                self.tmp_con[ip_port_key].end_timestamp = timestamp
                protocol = self.tmp_con[ip_port_key].protocol_type
                httpflaglist,httpsflaglist,tcp_bit_list,tcp_xunlei_list = self._protocol_flag_list(protocol,timestamp,ip_port_key,reverse_ip_port_key,payload)
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.tcp_rtt_values(ip_port_key, seqAck["ack_num"], ts)
                if tcp_bit_list[0] != 0:
                    self.tmp_con[ip_port_key].protocol_type = "BitTorrent"
                    self.tmp_con[ip_port_key].bit_peer_ip_1 = ip_port["src_ip"]
                    self.tmp_con[ip_port_key].bit_peer_id_1 = tcp_bit_list[1]
                elif tcp_xunlei_list[0] != 0:
                    self.tmp_con[ip_port_key].protocol_type = "xunlei"
                    if len(self.tmp_con[ip_port_key].xunlei_ip_1) == 0:
                        self.tmp_con[ip_port_key].xunlei_ip_1 = ip_port["src_ip"]
                        self.tmp_con[ip_port_key].xunlei_id_1 = tcp_xunlei_list[1]
                        # logging.info(xunlei_list[1])
                    elif ip_port["src_ip"] != self.tmp_con[ip_port_key].xunlei_ip_1:
                        self.tmp_con[ip_port_key].xunlei_ip_2 = ip_port["src_ip"]
                        self.tmp_con[ip_port_key].xunlei_id_2 = tcp_xunlei_list[1]
            elif reverse_ip_port_key in self.tmp_con:
                seq_end = seqAck["seq_num"] + len(payload)
                tmp_ip = reverse_ip_port_key.split("-")[2]
                #self.tmp_con[reverse_ip_port_key].RTT.setdefault(tmp_ip, {})[seq_end] = ts
                self.tmp_con[reverse_ip_port_key].end_timestamp = timestamp
                protocol = self.tmp_con[reverse_ip_port_key].protocol_type
                httpflaglist,httpsflaglist,tcp_bit_list,tcp_xunlei_list = self._protocol_flag_list(protocol,timestamp,ip_port_key,reverse_ip_port_key,payload)
                self._assignment_values_to_con(reverse_ip_port_key,payload,httpflaglist,httpsflaglist,1)
                self.tcp_rtt_values(reverse_ip_port_key, seqAck["ack_num"], ts)
                if tcp_bit_list[0] != 0:
                    self.tmp_con[reverse_ip_port_key].protocol_type = "BitTorrent"
                    self.tmp_con[reverse_ip_port_key].bit_peer_ip_2 = ip_port["src_ip"]
                    self.tmp_con[reverse_ip_port_key].bit_peer_id_2 = tcp_bit_list[1]
                elif tcp_xunlei_list[0] != 0:
                    self.tmp_con[reverse_ip_port_key].protocol_type = "xunlei"
                    if len(self.tmp_con[reverse_ip_port_key].xunlei_ip_1) == 0:
                        self.tmp_con[reverse_ip_port_key].xunlei_ip_1 = ip_port["src_ip"]
                        self.tmp_con[reverse_ip_port_key].xunlei_id_1 = tcp_xunlei_list[1]
                        # logging.info(xunlei_list[1])
                    elif ip_port["src_ip"] != self.tmp_con[reverse_ip_port_key].xunlei_ip_1:
                        self.tmp_con[reverse_ip_port_key].xunlei_ip_2 = ip_port["src_ip"]
                        self.tmp_con[reverse_ip_port_key].xunlei_id_2 = tcp_xunlei_list[1]
            else:
                tco = TCPConnection()
                tco.ip_port = ip_port_key
                tco.start_timestamp = timestamp
                tco.end_timestamp = timestamp
                seq_end = seqAck["seq_num"] + len(payload)
                httpflaglist,httpsflaglist,tcp_bit_list,tcp_xunlei_list = self._protocol_flag_list("tcp",timestamp,ip_port_key,reverse_ip_port_key,payload)
                tmp_ip = ip_port_key.split("-")[0]
                if tcp_bit_list[0] != 0:
                    tco.protocol_type = "BitTorrent"
                    tco.bit_peer_ip_1 = ip_port["src_ip"]
                    tco.bit_peer_id_1 = tcp_bit_list[1]
                elif tcp_xunlei_list[0] != 0:
                    tco.protocol_type = "xunlei"
                    tco.xunlei_ip_1 = ip_port["src_ip"]
                    tco.xunlei_id_1 = tcp_xunlei_list[1]
                self.tmp_con[ip_port_key] = tco
                self._assignment_values_to_con(ip_port_key,payload,httpflaglist,httpsflaglist,0)
                self.tcp_rtt_values(ip_port_key, seqAck["ack_num"], ts)

        else:
            logging.info("tcp connection time is {}".format(timestamp))
        if len(self.tmp_con) >= 1500:
            self._move_tmp_to_save()

    def _udp_connection(self, ts, ip_port, udp):
        # Sort the source IP and destination IP addresses
        src_ip = ip_port["src_ip"]
        dst_ip = ip_port["dst_ip"]
        src_port = ip_port["src_port"]
        dst_port = ip_port["dst_port"]
        payload = udp.data
        key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)
        udp_bit_list = self._udp_bittorrent(payload)
        if udp_bit_list[0] == 0:
            udp_toutiao_list = self._udp_toutiao(payload)
        else:
            udp_toutiao_list = [0]
        if key not in self.tmp_udp and reverse_key not in self.tmp_udp:
            udc = UDPConnection()
            udc.ip_port = key
            udc.src_dst_byte_count += len(payload)
            udc.byte_count += len(payload)
            udc.src_dst_packet_count += 1
            udc.packet_count += 1
            udc.start_timestamp = ts
            udc.end_timestamp = ts

            if udp_bit_list[0] != 0:
                udc.protocol_type = "BitTorrent"
                udc.bit_peer_ip_1 = ip_port["src_ip"]
                udc.bit_peer_id_1 = udp_bit_list[1]
            if udp_toutiao_list[0] != 0:
                udc.protocol_type = "toutiao"
                udc.toutiao_ip = ip_port["src_ip"]
                udc.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
            self.tmp_udp[key] = udc

        elif key in self.tmp_udp:
            udp_item = self.tmp_udp[key]
            udp_item.src_dst_byte_count += len(payload)
            udp_item.byte_count += len(payload)
            udp_item.src_dst_packet_count += 1
            udp_item.packet_count += 1
            if ts > udp_item.end_timestamp:
                udp_item.end_timestamp = ts
            if udp_bit_list[0] != 0:
                udp_item.protocol_type = "BitTorrent"
                udp_item.bit_peer_ip_1 = ip_port["src_ip"]
                udp_item.bit_peer_id_1 = udp_bit_list[1]
            if udp_toutiao_list[0] != 0:
                udp_item.protocol_type = "toutiao"
                udp_item.toutiao_ip = ip_port["src_ip"]
                udp_item.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
        elif reverse_key in self.tmp_udp:
            udp_item = self.tmp_udp[reverse_key]
            udp_item.dst_src_byte_count += len(payload)
            udp_item.byte_count += len(payload)
            udp_item.dst_src_packet_count += 1
            udp_item.packet_count += 1
            if ts > udp_item.end_timestamp:
                udp_item.end_timestamp = ts
            if udp_bit_list[0] != 0:
                udp_item.protocol_type = "BitTorrent"
                udp_item.bit_peer_ip_2 = ip_port["src_ip"]
                udp_item.bit_peer_id_2 = udp_bit_list[1]
            if udp_toutiao_list[0] != 0:
                udp_item.protocol_type = "toutiao"
                udp_item.toutiao_ip = ip_port["src_ip"]
                udp_item.toutiao_value = udp_toutiao_list[1]
                udp_item.toutiao_location = udp_toutiao_list[2]
        # The Stun protocol contains keywords related to OneThingCloud
        if udp_toutiao_list[0] == 0 and dpkt_methods.is_stun_packet(payload):
            # Analyze the various fields in STUN messages
            stun_pkt = dpkt.stun.STUN(payload)
            msg_type = stun_pkt.type
            msg_length = len(payload)
            try:
                attrs = dpkt.stun.parse_attrs(stun_pkt.data)
                for item in attrs:
                    if item[0] == 57346:
                        new_item = item[1].decode('utf-8')
                        new_data = json.loads(new_item.strip())
                        new_data["data_ip"] = src_ip
                        if key in self.tmp_udp:
                            self.tmp_udp[key].stun_values.append(new_data)
                            self.tmp_udp[key].protocol_type = "stun"
                        else:
                            self.tmp_udp[reverse_key].stun_values.append(
                                new_data)
                            self.tmp_udp[reverse_key].protocol_type = "stun"
            except Exception as e:
                pass
        elif udp_toutiao_list[0] == 0 and not dpkt_methods.is_stun_packet(
                payload):
            xunlei_list = self._udp_xunlei(payload)
            if xunlei_list[0] != 0:
                if key in self.tmp_udp:
                    self.tmp_udp[key].protocol_type = "xunlei"
                    if len(self.tmp_udp[key].xunlei_ip_1) == 0:
                        self.tmp_udp[key].xunlei_ip_1 = src_ip
                        self.tmp_udp[key].xunlei_id_1 = xunlei_list[1]
                    elif src_ip != self.tmp_udp[key].xunlei_ip_1:
                        self.tmp_udp[key].xunlei_ip_2 = src_ip
                        self.tmp_udp[key].xunlei_id_2 = xunlei_list[1]
                elif reverse_key in self.tmp_udp:
                    self.tmp_udp[reverse_key].protocol_type = "xunlei"
                    if len(self.tmp_udp[reverse_key].xunlei_ip_1) == 0:
                        self.tmp_udp[reverse_key].xunlei_ip_1 = src_ip
                        self.tmp_udp[reverse_key].xunlei_id_1 = xunlei_list[1]
                    elif src_ip != self.tmp_udp[reverse_key].xunlei_ip_1:
                        self.tmp_udp[reverse_key].xunlei_ip_2 = src_ip
                        self.tmp_udp[reverse_key].xunlei_id_2 = xunlei_list[1]

        #Export UDP connection from tmp_com
        if len(self.tmp_udp) > 1500:
            for ip_port_key in list(self.tmp_udp.keys()):
                self.udpcon_list.append(self.tmp_udp[ip_port_key])
                self.tmp_udp.pop(ip_port_key)

    def _protocol_flag_list(self,protocol,timestamp,ip_port_key,reverse_ip_port_key,payload):
        if protocol=="tcp":
            httpflaglist = self._http_connection(timestamp, ip_port_key,
                                        reverse_ip_port_key, payload)#judge whether is http protocol
            if httpflaglist[0] == 0:
                httpsflaglist = self._https_connection(timestamp, ip_port_key, payload)#judge whether is https protocol
            else:
                httpsflaglist = [0]
                tcp_bit_list = [0]
                tcp_xunlei_list = [0]

            if httpflaglist[0] + httpflaglist[0] == 0:#judge whether is bitTorrent protocol
                tcp_bit_list = self._tcp_bittorrent(payload)
            else:
                tcp_bit_list = [0]
                tcp_xunlei_list = [0]

            if tcp_bit_list[0] + httpflaglist[0] + httpsflaglist[0] == 0:#judge whether is xunlei protocol
                tcp_xunlei_list = self._tcp_xunlei(payload)
            else:
                tcp_xunlei_list = [0]
        elif protocol == "http":
            httpflaglist = self._http_connection(timestamp, ip_port_key,
                                        reverse_ip_port_key, payload)#http protocol
            httpsflaglist = [0]
            tcp_bit_list = [0]
            tcp_xunlei_list = [0]
        elif protocol == "https":
            httpsflaglist = self._https_connection(timestamp, ip_port_key, payload)#https protocol
            httpflaglist = [0]
            tcp_bit_list = [0]
            tcp_xunlei_list = [0]
        elif protocol == "BitTorrent":
            tcp_bit_list = self._tcp_bittorrent(payload)
            httpflaglist = [0]
            httpsflaglist = [0]
            tcp_xunlei_list = [0]
        elif protocol=="xunlei":
            tcp_xunlei_list = self._tcp_xunlei(payload)
            httpflaglist = [0]
            httpsflaglist = [0]
            tcp_bit_list = [0]
        return httpflaglist,httpsflaglist,tcp_bit_list,tcp_xunlei_list

    def _xycdn_websocket(self,ip_port_key,payload):
        if ip_port_key not in self.xycdn_websocket_streams:
            self.xycdn_websocket_streams[ip_port_key] = b''
        self.xycdn_websocket_streams[ip_port_key] += payload
        # Process WebSocket data
        stream_data = self.xycdn_websocket_streams[ip_port_key]
        while len(stream_data) >= 2:
            opcode = stream_data[0] & 0b00001111
            payload_len = stream_data[1] & 0b01111111
            mask_flag = 1 if stream_data[
                1] & 0b10000000 == 128 else 0
            Msking_Key = ""
            if payload_len == 126:
                payload_len = int.from_bytes(stream_data[2:4],
                                                byteorder='big')
                mask_offset = 4
                if mask_flag == 1:
                    Msking_Key = stream_data[4:8]
                    mask_offset = 8
            elif payload_len == 127:
                payload_len = int.from_bytes(stream_data[2:10],
                                                byteorder='big')
                mask_offset = 10
                if mask_flag == 1:
                    Msking_Key = stream_data[10:14]
                    mask_offset = 14
            else:
                mask_offset = 2
                if mask_flag == 1:
                    Msking_Key = stream_data[2:6]
                    mask_offset = 6
            payload_offset = mask_offset
            frame_length = payload_offset + payload_len

            if len(stream_data) < frame_length:
                # Insufficient data to parse the entire WebSocket data frame
                break
            payload = stream_data[payload_offset:frame_length]
            try:
                ascii_string = ''
                for byte in payload:
                    try:
                        ascii_char = chr(byte)
                        if ord(ascii_char) < 128:
                            ascii_string += ascii_char
                        else:
                            ascii_string += '*'
                    except ValueError:
                        ascii_string += '*'

                decoded_payload = ascii_string
                results = self.process_websocket_payload(
                    decoded_payload)
                # Remove parsed data from the stream
                stream_data = stream_data[frame_length:]
                self.xycdn_websocket_streams[ip_port_key] = stream_data
                if len(results) == 2:
                    key = "{}-{}".format(results[0], results[1])
                    self.xycdn_stun_ip_port_dict[key] = self.xycdn_stun_ip_port_dict.get(key,0) + 1
                else:
                    for key in results:
                        self.xycdn_stun_ip_port_dict[key] = self.xycdn_stun_ip_port_dict.get(key, 0) + 1
            except:
                # Remove parsed data from the stream
                stream_data = stream_data[frame_length:]
                self.xycdn_websocket_streams[ip_port_key] = stream_data
                continue
    
    def process_websocket_payload(self,payload):
        # Process the payload of WebSocket data containing keywords here
        try:
            pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
            matches = re.findall(pattern, payload)
            results = []
            for match in matches:
                ip = match[0]
                port = int(match[1])
                results.append("{}:{}".format(ip, port))
            return results
        except Exception as e:
            return []

    def _udp_xunlei(self, payload):
        if len(payload) > 100:
            try:
                if payload[83] == 0 and all(
                        char.isalnum()
                        for char in payload[84:100].decode('utf-8')):
                    return [1, payload[84:100].decode('utf-8')]
                elif payload[8] == 0 and all(
                        char.isalnum()
                        for char in payload[9:25].decode('utf-8')):
                    return [1, payload[9:25].decode('utf-8')]
                else:
                    return [0]
            except:
                try:
                    if payload[8] == 0 and all(
                            char.isalnum()
                            for char in payload[9:25].decode('utf-8')):
                        return [1, payload[9:25].decode('utf-8')]
                    else:
                        return [0]
                except:
                    return [0]
        elif len(payload) > 25:
            try:
                if payload[8] == 0 and all(
                        char.isalnum()
                        for char in payload[9:25].decode('utf-8')):
                    return [1, payload[9:25].decode('utf-8')]
                else:
                    return [0]
            except:
                return [0]
        else:
            return [0]

    def _tcp_xunlei(self, payload):
        if len(payload) > 67:
            try:
                if payload[50] == 0 and all(
                        char.isalnum()
                        for char in payload[51:67].decode('utf-8')):
                    return [1, payload[51:67].decode('utf-8')]
                elif payload[13] == 0 and all(
                        char.isalnum()
                        for char in payload[14:30].decode('utf-8')):
                    return [1, payload[51:67].decode('utf-8')]
                else:
                    return [0]
            except:
                try:
                    if payload[13] == 0 and all(
                            char.isalnum()
                            for char in payload[14:30].decode('utf-8')):
                        return [1, payload[14:30].decode('utf-8')]
                    else:
                        return [0]
                except:
                    return [0]
        if len(payload) > 30:
            try:
                if payload[13] == 0 and all(
                        char.isalnum()
                        for char in payload[14:30].decode('utf-8')):
                    return [1, payload[14:30].decode('utf-8')]
                else:
                    return [0]
            except:
                return [0]
        else:
            return [0]

    def _udp_toutiao(self, payload):
        if b'toutiaovod.com' in payload[50:]:
            return [
                1, payload[50:].split(b'\x00', 1)[0].decode('utf-8', 'ignore'),50
            ]
        elif b'toutiaovod.com' in payload[30:]:
            return [
                1,payload[30:].split(b'\x00',1)[0].decode('utf-8','ignore'),30
            ]
        else:
            return [0]

    def _tcp_bittorrent(self, payload):
        if is_bittorrent_handshake(payload):
            parsed_data = parse_bittorrent_handshake(payload)
            return [1, parsed_data["peer_id"]]
        else:
            return [0]

    def _udp_bittorrent(self, payload):
        if is_bittorrent_protocol(payload):
            parsed_data = parse_bittorrent(payload)
            return [1, parsed_data["peer_id"]]
        else:
            return [0]

    def _http_connection(self, timestamp, ip_port_key, reverse_ip_port_key,
                         payload):
        if ip_port_key in self.tmp_http and self.tmp_http[
                ip_port_key].req is not None:  # Next request packet
            if self.tmp_http[ip_port_key].req.length_chunked_gzip[
                    "need_length"] > 0:
                if self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "gzip"] == 0:
                    self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "need_length"] -= len(payload)
                    self.tmp_http[ip_port_key].req.body += payload
                else:
                    self.tmp_http[ip_port_key].req.length_chunked_gzip[
                        "need_length"] -= len(payload)
                    try:
                        body = gzip.decompress(payload)
                        self.tmp_http[ip_port_key].req.body += body
                    except Exception:
                        self.tmp_http[ip_port_key].req.body += payload
            return [1]
        elif reverse_ip_port_key in self.tmp_http and self.tmp_http[
                reverse_ip_port_key].res is not None:  # Next response packet
            if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] > 0:  # first packet maybe have content-length
                self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] -= len(payload)
                if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                        "gzip"] == 0:
                    self.tmp_http[reverse_ip_port_key].res.body += payload
                else:  #gzip decompress
                    try:
                        body = gzip.decompress(payload)
                        self.tmp_http[reverse_ip_port_key].res.body += body
                    except:
                        self.tmp_http[ip_port_key].res.body += payload
            if self.tmp_http[reverse_ip_port_key].res.length_chunked_gzip[
                    "need_length"] == 0 or self.tmp_http[
                        reverse_ip_port_key].res.length_chunked_gzip[
                            "need_length"] > 5120:  # need log data,other type file such as video don't need
                self.http_list.append(self.tmp_http[reverse_ip_port_key])
                del self.tmp_http[reverse_ip_port_key]
            return [1]
        try:
            requestbody = Request(payload)
            reqresbody = ReqResBody()
            reqresbody.req = requestbody
            reqresbody.ip_port = ip_port_key
            reqresbody.req_time = timestamp
            self.tmp_http[ip_port_key] = reqresbody
            return [1, reqresbody.req_time, ip_port_key]
        except Exception:
            try:
                responsebody = Response(payload)
                if reverse_ip_port_key in self.tmp_http:
                    self.tmp_http[reverse_ip_port_key].res = responsebody
                    self.tmp_http[reverse_ip_port_key].res_time = timestamp
                    if self.tmp_http[
                            reverse_ip_port_key].req.length_chunked_gzip[
                                "need_length"] == 0 and self.tmp_http[
                                    reverse_ip_port_key].res.length_chunked_gzip[
                                        "need_length"] == 0:
                        self.http_list.append(
                            self.tmp_http[reverse_ip_port_key])
                        del self.tmp_http[reverse_ip_port_key]
                    return [1]
                else:
                    return [1]
            except Exception:
                return [0]

    def _dns_packet_parse(self, timestamp, udp):
        try:
            dns = dpkt.dns.DNS(udp.data)
        except Exception:
            return 0
        domain_ip = dpkt_methods.parse_dns_response(dns)
        if domain_ip:
            domain_ip["timestamp"] = timestamp
            self.ts_domain_ip.append(domain_ip)
        else:
            return 1
        return 1

    def _https_connection(self, timestamp, ip_port_key, payload):
        https_flag = 0
        try:
            is_tls_v2, version3 = check_tls_version(payload)
            if not (is_tls_v2 or version3):
                return [0]
            try:
                if is_tls_v2:
                    length = client_hello_ssl_v2(payload)
                    records, bytes_used = dpkt.ssl.tls_multi_factory(
                        payload[length:])
                else:
                    records, bytes_used = dpkt.ssl.tls_multi_factory(payload)
            except Exception:
                return [0]
            # https_flag = 1
            reslist = parse_client_records(records, https_flag)
            server_name = reslist[0]
            https_flag = reslist[1]
            if server_name != "1":
                jsonline = {
                    "sni_domain": server_name,
                    "sni_ip": ip_port_key.split("-")[2],
                    "timestamp": timestamp
                }
                self.SNI.append(jsonline)
                return [1, server_name, ip_port_key.split("-")[2], timestamp]
            else:  # maybe have certificate
                reslist = parse_certificate_records(records, https_flag)
                cert_fingerprint_domains_certs = reslist[0]
                https_flag = reslist[1]
                if len(cert_fingerprint_domains_certs) > 0:
                    for key in cert_fingerprint_domains_certs:
                        if key not in self.Certs:
                            self.Certs[key] = cert_fingerprint_domains_certs[
                                key][1]
                        jsonline = {
                            "sha256_fingerprint": key,
                            "domains":
                            list(cert_fingerprint_domains_certs[key][0]),
                            "timestamp": timestamp
                        }
                        #logging.info(jsonline)
                        self.Cert_domain_time.append(jsonline)
                        return [
                            1,
                            list(cert_fingerprint_domains_certs[key][0])[0],
                            ip_port_key.split("-")[0], timestamp, "cert"
                        ]
                return [https_flag]
        except Exception:
            return [https_flag]

    def _move_tmp_to_save(self, fin_flag_count=2):
        for ip_port_key in list(self.tmp_con.keys()):
            if self.tmp_con[ip_port_key].syn_flag >= 1 and (
                    self.tmp_con[ip_port_key].fin_flag >= fin_flag_count
                    or self.tmp_con[ip_port_key].rst_flag >= 1):
                self.savecon_list.append(self.tmp_con[ip_port_key])
                self.tmp_con.pop(ip_port_key)

    def tcp_rtt_values(self, ip_port_key, ack_num, ts):
        ip = ip_port_key.split("-")[0]  #
        tmp_RTT_dict = self.tmp_con[ip_port_key].RTT.get(ip, {})

        if ack_num in tmp_RTT_dict:
            sent_ts = tmp_RTT_dict[ack_num]
            rtt = ts - sent_ts
            try:
                self.tmp_con[ip_port_key].RTT_Results.setdefault(
                    ip, []).append(rtt)
                del tmp_RTT_dict[ack_num]
            except Exception as e:
                logging.info(e)
        else:
            ip = ip_port_key.split("-")[2]  #
            tmp_RTT_dict = self.tmp_con[ip_port_key].RTT.get(ip, {})
            if ack_num in tmp_RTT_dict:
                sent_ts = tmp_RTT_dict[ack_num]
                rtt = ts - sent_ts
                try:
                    self.tmp_con[ip_port_key].RTT_Results.setdefault(
                        ip, []).append(rtt)
                    del tmp_RTT_dict[ack_num]
                except Exception as e:
                    logging.info(e)

    def _assignment_values_to_con(self,ip_port_key, tcp_payload, httpflaglist,httpsflaglist,reverse):
        self.tmp_con[ip_port_key].byte_count += len(tcp_payload)
        self.tmp_con[ip_port_key].packet_count += 1
        if reverse == 0:
            self.tmp_con[ip_port_key].src_dst_byte_count += len(tcp_payload)
            self.tmp_con[ip_port_key].src_dst_packet_count += 1
        else:
            self.tmp_con[ip_port_key].dst_src_byte_count += len(tcp_payload)
            self.tmp_con[ip_port_key].dst_src_packet_count += 1
        if httpflaglist[0] == 1:
            if len(httpflaglist) == 1:
                self.tmp_con[ip_port_key].protocol_type = "http"
            else:
                self.tmp_con[ip_port_key].protocol_type = "http"
                self.tmp_con[ip_port_key].http_req_time = httpflaglist[1]
        else:
            if len(httpsflaglist) == 4:
                self.tmp_con[ip_port_key].protocol_type = "https"
                self.tmp_con[ip_port_key].https_SNI = httpsflaglist[1]
                self.tmp_con[ip_port_key].https_SNI_ip = httpsflaglist[2]
                self.tmp_con[ip_port_key].https_SNI_time = httpsflaglist[3]
            elif len(httpsflaglist) == 5:
                self.tmp_con[ip_port_key].protocol_type = "https"
                self.tmp_con[ip_port_key].https_Cert_domain = httpsflaglist[1]
                self.tmp_con[ip_port_key].https_Cert_ip = httpsflaglist[2]
                self.tmp_con[ip_port_key].https_Cert_time = httpsflaglist[3]
            elif httpsflaglist[0] == 1:
                self.tmp_con[ip_port_key].protocol_type = "https"
        return None
