import json
import os
import argparse
import sys
import logging
import json
from dpkt_connection_thread import ProcessPcapTT,ProcessPcapWXY
import datetime
from decimal import Decimal, ROUND_HALF_UP


def dict_to_list(tmpdict: dict):
    tmplist = []
    for key in tmpdict:
        tmplist.append(tmpdict[key])
    return tmplist


def line_write_to_files(datalist, file):
    with open(file, "w+") as fd:
        for line in datalist:
            jsonline = json.dumps(line)
            fd.write(jsonline + "\n")
    logger.info("{} has been write".format(file))


def con_write_to_files(conlist, file):
    conlist.sort(key=lambda con: con.start_timestamp)
    with open(file, "w+") as fd:
        for con in conlist:
            #every_rtt = {}
            first_rtt = {}
            need_rtt = [0.0000]
            for key, values in con.RTT_Results.items():
                rtt_all = 0
                rtt_list = []
                for value in values:
                    value_ms = value * 1000
                    rtt_list.append(value_ms)
                if len(rtt_list) > 0:
                    first_rtt[key] = rtt_list[0]
                    need_rtt.append(rtt_list[0])
                else:
                    first_rtt[key] = 0.0000
                    need_rtt.append(0.0000)

            jsonline = {
                "ip_port":
                con.ip_port,
                "start_timestamp":
                con.start_timestamp,
                "end_timestamp":
                con.end_timestamp,
                "packet_count":
                con.packet_count,
                "byte_count":
                con.byte_count,
                "src_dst_packet_count":
                con.src_dst_packet_count,
                "dst_src_packet_count":
                con.dst_src_packet_count,
                "src_dst_byte_count":
                con.src_dst_byte_count,
                "dst_src_byte_count":
                con.dst_src_byte_count,
                "protocol_type":
                con.protocol_type,
                "http_req_time":
                con.http_req_time,
                "https_SNI":
                con.https_SNI,
                "https_SNI_ip":
                con.https_SNI_ip,
                "https_SNI_time":
                con.https_SNI_time,
                "https_Cert_domain":
                con.https_Cert_domain,
                "https_Cert_ip":
                con.https_Cert_ip,
                "https_Cert_time":
                con.https_Cert_time,
                "bit_peer_ip_1":
                con.bit_peer_ip_1,
                "bit_peer_id_1":
                con.bit_peer_id_1 if len(con.bit_peer_id_1) > 0 else "",
                "bit_peer_ip_2":
                con.bit_peer_ip_2,
                "bit_peer_id_2":
                con.bit_peer_id_2 if len(con.bit_peer_id_2) > 0 else "",
                "xunlei_ip_1":
                con.xunlei_ip_1,
                "xunlei_id_1":
                con.xunlei_id_1,
                "xunlei_ip_2":
                con.xunlei_ip_2,
                "xunlei_id_2":
                con.xunlei_id_2,
                "syn_flag":
                con.syn_flag,
                "fin_flag":
                con.fin_flag,
                "rst_flag":
                con.rst_flag,
                "rtt/ms":max(need_rtt),
            }
            try:
                fd.write(json.dumps(jsonline) + "\n")
            except Exception as e:

                logging.info(jsonline)
                logging.info("this jsonline have Exception")
                logging.info(e)
    logger.info("{} is ok".format(file))


def try_to_json(line):
    try:
        return json.dumps(eval(str(line, encoding="utf-8", errors='ignore')))
    except:
        return str(line, encoding="utf-8", errors='ignore')


def con_list_to_dict(con_list):
    con_dict = {}
    for con in con_list:
        ip_port = con.ip_port
        con_dict[ip_port] = [
            con.start_timestamp, con.end_timestamp, con.src_dst_packet_count,
            con.dst_src_packet_count, con.src_dst_byte_count,
            con.dst_src_byte_count
        ]
    return con_dict


def http_write_to_files(savecon_dict, tmpcon_dict, httplist, file):
    with open(file, "w+") as fd:
        for line in httplist:
            try:
                req_body = str(line.req.body,
                               encoding="utf-8",
                               errors='ignore')
                req_data = str(line.req.data,
                               encoding="utf-8",
                               errors='ignore')
                res_body = str(line.res.body,
                               encoding="utf-8",
                               errors='ignore')
                res_data = str(line.res.data,
                               encoding="utf-8",
                               errors='ignore')
                ip_port = line.ip_port
                reverse_ip_port = ip_port.split("-")[1] + "-" + ip_port.split(
                    "-")[3] + "-" + ip_port.split(
                        "-")[0] + "-" + ip_port.split("-")[2]
                if ip_port in savecon_dict:
                    jsonline = {
                        "ip_port":
                        line.ip_port,
                        "start_timestamp":
                        savecon_dict[ip_port][0],
                        "end_timestamp":
                        savecon_dict[ip_port][1],
                        "req_time":
                        line.req_time,
                        "src_dst_packet_count":
                        savecon_dict[ip_port][2],
                        "dst_src_packet_count":
                        savecon_dict[ip_port][3],
                        "src_dst_byte_count":
                        savecon_dict[ip_port][4],
                        "dst_src_byte_count":
                        savecon_dict[ip_port][5],
                        "req_method":
                        line.req.method,
                        "req_uri":
                        line.req.uri,
                        "req_need_length":
                        line.req.length_chunked_gzip["need_length"],
                        "req_headers":
                        [(key, values)
                         for (key, values) in line.req.headers.items()],
                        "req_body":
                        req_body,
                        "req_data":
                        req_data,
                        "res_time":
                        line.res_time,
                        "res_status":
                        line.res.status,
                        "res_reason":
                        line.res.reason,
                        "res_need_length":
                        line.res.length_chunked_gzip["need_length"],
                        "res_headers":
                        [(key, values)
                         for (key, values) in line.res.headers.items()],
                        "res_body":
                        res_body,
                        "res_data":
                        res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif reverse_ip_port in savecon_dict:
                    jsonline = {
                        "ip_port":
                        line.ip_port,
                        "start_timestamp":
                        savecon_dict[reverse_ip_port][0],
                        "end_timestamp":
                        savecon_dict[reverse_ip_port][1],
                        "req_time":
                        line.req_time,
                        "src_dst_packet_count":
                        savecon_dict[reverse_ip_port][3],
                        "dst_src_packet_count":
                        savecon_dict[reverse_ip_port][2],
                        "src_dst_byte_count":
                        savecon_dict[reverse_ip_port][5],
                        "dst_src_byte_count":
                        savecon_dict[reverse_ip_port][4],
                        "req_method":
                        line.req.method,
                        "req_uri":
                        line.req.uri,
                        "req_need_length":
                        line.req.length_chunked_gzip["need_length"],
                        "req_headers":
                        [(key, values)
                         for (key, values) in line.req.headers.items()],
                        "req_body":
                        req_body,
                        "req_data":
                        req_data,
                        "res_time":
                        line.res_time,
                        "res_status":
                        line.res.status,
                        "res_reason":
                        line.res.reason,
                        "res_need_length":
                        line.res.length_chunked_gzip["need_length"],
                        "res_headers":
                        [(key, values)
                         for (key, values) in line.res.headers.items()],
                        "res_body":
                        res_body,
                        "res_data":
                        res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif ip_port in tmpcon_dict:
                    jsonline = {
                        "ip_port":
                        line.ip_port,
                        "start_timestamp":
                        tmpcon_dict[ip_port][0],
                        "end_timestamp":
                        tmpcon_dict[ip_port][1],
                        "req_time":
                        line.req_time,
                        "src_dst_packet_count":
                        tmpcon_dict[ip_port][2],
                        "dst_src_packet_count":
                        tmpcon_dict[ip_port][3],
                        "src_dst_byte_count":
                        tmpcon_dict[ip_port][4],
                        "dst_src_byte_count":
                        tmpcon_dict[ip_port][5],
                        "req_method":
                        line.req.method,
                        "req_uri":
                        line.req.uri,
                        "req_need_length":
                        line.req.length_chunked_gzip["need_length"],
                        "req_headers":
                        [(key, values)
                         for (key, values) in line.req.headers.items()],
                        "req_body":
                        req_body,
                        "req_data":
                        req_data,
                        "res_time":
                        line.res_time,
                        "res_status":
                        line.res.status,
                        "res_reason":
                        line.res.reason,
                        "res_need_length":
                        line.res.length_chunked_gzip["need_length"],
                        "res_headers":
                        [(key, values)
                         for (key, values) in line.res.headers.items()],
                        "res_body":
                        res_body,
                        "res_data":
                        res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif reverse_ip_port in tmpcon_dict:
                    jsonline = {
                        "ip_port":
                        line.ip_port,
                        "start_timestamp":
                        tmpcon_dict[reverse_ip_port][0],
                        "end_timestamp":
                        tmpcon_dict[reverse_ip_port][1],
                        "req_time":
                        line.req_time,
                        "src_dst_packet_count":
                        tmpcon_dict[reverse_ip_port][3],
                        "dst_src_packet_count":
                        tmpcon_dict[reverse_ip_port][2],
                        "src_dst_byte_count":
                        tmpcon_dict[reverse_ip_port][5],
                        "dst_src_byte_count":
                        tmpcon_dict[reverse_ip_port][4],
                        "req_method":
                        line.req.method,
                        "req_uri":
                        line.req.uri,
                        "req_need_length":
                        line.req.length_chunked_gzip["need_length"],
                        "req_headers":
                        [(key, values)
                         for (key, values) in line.req.headers.items()],
                        "req_body":
                        req_body,
                        "req_data":
                        req_data,
                        "res_time":
                        line.res_time,
                        "res_status":
                        line.res.status,
                        "res_reason":
                        line.res.reason,
                        "res_need_length":
                        line.res.length_chunked_gzip["need_length"],
                        "res_headers":
                        [(key, values)
                         for (key, values) in line.res.headers.items()],
                        "res_body":
                        res_body,
                        "res_data":
                        res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                else:
                    jsonline = {
                        "ip_port":
                        line.ip_port,
                        "start_timestamp":
                        None,
                        "end_timestamp":
                        None,
                        "req_time":
                        line.req_time,
                        "src_dst_packet_count":
                        None,
                        "dst_src_packet_count":
                        None,
                        "src_dst_byte_count":
                        None,
                        "dst_src_byte_count":
                        None,
                        "req_method":
                        line.req.method,
                        "req_uri":
                        line.req.uri,
                        "req_need_length":
                        line.req.length_chunked_gzip["need_length"],
                        "req_headers":
                        [(key, values)
                         for (key, values) in line.req.headers.items()],
                        "req_body":
                        req_body,
                        "req_data":
                        req_data,
                        "res_time":
                        line.res_time,
                        "res_status":
                        line.res.status,
                        "res_reason":
                        line.res.reason,
                        "res_need_length":
                        line.res.length_chunked_gzip["need_length"],
                        "res_headers":
                        [(key, values)
                         for (key, values) in line.res.headers.items()],
                        "res_body":
                        res_body,
                        "res_data":
                        res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
            except Exception as e:
                logger.info(e)
                logger.info(jsonline)
    logger.info("{} has been write".format(file))


def tmp_http_write_to_files(savecon_dict, tmpcon_dict, httplist, file):
    with open(file, "w+") as fd:
        for line in httplist:
            try:
                try:
                    req_body = str(line.req.body,
                                   encoding="utf-8",
                                   errors='ignore')
                except:
                    req_body = None
                try:
                    req_data = str(line.req.data,
                                   encoding="utf-8",
                                   errors='ignore')
                except:
                    req_data = None
                try:
                    res_body = str(line.res.body,
                                   encoding="utf-8",
                                   errors='ignore')
                except:
                    res_body = None
                try:
                    res_data = str(line.res.data,
                                   encoding="utf-8",
                                   errors='ignore')
                except:
                    res_data = None
                req_headers_list = []
                try:
                    for (key, values) in line.req.headers.items():
                        req_headers_list.append((key, values))
                except:
                    req_headers_list = []
                res_headers_list = []
                try:
                    for (key, values) in line.res.headers.items():
                        res_headers_list.append((key, values))
                except:
                    res_headers_list = []
                try:
                    req_time = line.req_time
                except:
                    req_time = None
                try:
                    method = line.req.method
                except:
                    method = None
                try:
                    req_uri = line.req.uri
                except:
                    req_uri = None
                try:
                    req_len = line.req.length_chunked_gzip["need_length"]
                except:
                    req_len = None
                try:
                    res_time = line.res_time
                except:
                    res_time = None
                try:
                    res_status = line.res.status
                except:
                    res_status = None
                try:
                    res_reason = line.res.reason
                except:
                    res_reason = None
                try:
                    res_len = line.res.length_chunked_gzip["need_length"]
                except:
                    res_len = None
                ip_port = line.ip_port
                reverse_ip_port = ip_port.split("-")[1] + "-" + ip_port.split(
                    "-")[3] + "-" + ip_port.split(
                        "-")[0] + "-" + ip_port.split("-")[2]
                if ip_port in savecon_dict:
                    jsonline = {
                        "ip_port": line.ip_port,
                        "start_timestamp": savecon_dict[ip_port][0],
                        "end_timestamp": savecon_dict[ip_port][1],
                        "req_time": req_time,
                        "src_dst_packet_count": savecon_dict[ip_port][2],
                        "dst_src_packet_count": savecon_dict[ip_port][3],
                        "src_dst_byte_count": savecon_dict[ip_port][4],
                        "dst_src_byte_count": savecon_dict[ip_port][5],
                        "req_method": method,
                        "req_uri": req_uri,
                        "req_need_length": req_len,
                        "req_headers": req_headers_list,
                        "req_body": req_body,
                        "req_data": req_data,
                        "res_time": res_time,
                        "res_status": res_status,
                        "res_reason": res_reason,
                        "res_need_length": res_len,
                        "res_headers": res_headers_list,
                        "res_body": res_body,
                        "res_data": res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif reverse_ip_port in savecon_dict:
                    jsonline = {
                        "ip_port": line.ip_port,
                        "start_timestamp": savecon_dict[reverse_ip_port][0],
                        "end_timestamp": savecon_dict[reverse_ip_port][1],
                        "req_time": req_time,
                        "src_dst_packet_count":
                        savecon_dict[reverse_ip_port][3],
                        "dst_src_packet_count":
                        savecon_dict[reverse_ip_port][2],
                        "src_dst_byte_count": savecon_dict[reverse_ip_port][5],
                        "dst_src_byte_count": savecon_dict[reverse_ip_port][4],
                        "req_method": method,
                        "req_uri": req_uri,
                        "req_need_length": req_len,
                        "req_headers": req_headers_list,
                        "req_body": req_body,
                        "req_data": req_data,
                        "res_time": res_time,
                        "res_status": res_status,
                        "res_reason": res_reason,
                        "res_need_length": res_len,
                        "res_headers": res_headers_list,
                        "res_body": res_body,
                        "res_data": res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif ip_port in tmpcon_dict:
                    jsonline = {
                        "ip_port": line.ip_port,
                        "start_timestamp": tmpcon_dict[ip_port][0],
                        "end_timestamp": tmpcon_dict[ip_port][1],
                        "req_time": req_time,
                        "src_dst_packet_count": tmpcon_dict[ip_port][2],
                        "dst_src_packet_count": tmpcon_dict[ip_port][3],
                        "src_dst_byte_count": tmpcon_dict[ip_port][4],
                        "dst_src_byte_count": tmpcon_dict[ip_port][5],
                        "req_method": method,
                        "req_uri": req_uri,
                        "req_need_length": req_len,
                        "req_headers": req_headers_list,
                        "req_body": req_body,
                        "req_data": req_data,
                        "res_time": res_time,
                        "res_status": res_status,
                        "res_reason": res_reason,
                        "res_need_length": res_len,
                        "res_headers": res_headers_list,
                        "res_body": res_body,
                        "res_data": res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                elif reverse_ip_port in tmpcon_dict:
                    jsonline = {
                        "ip_port": line.ip_port,
                        "start_timestamp": tmpcon_dict[reverse_ip_port][0],
                        "end_timestamp": tmpcon_dict[reverse_ip_port][1],
                        "req_time": req_time,
                        "src_dst_packet_count":
                        tmpcon_dict[reverse_ip_port][3],
                        "dst_src_packet_count":
                        tmpcon_dict[reverse_ip_port][2],
                        "src_dst_byte_count": tmpcon_dict[reverse_ip_port][5],
                        "dst_src_byte_count": tmpcon_dict[reverse_ip_port][4],
                        "req_method": method,
                        "req_uri": req_uri,
                        "req_need_length": req_len,
                        "req_headers": req_headers_list,
                        "req_body": req_body,
                        "req_data": req_data,
                        "res_time": res_time,
                        "res_status": res_status,
                        "res_reason": res_reason,
                        "res_need_length": res_len,
                        "res_headers": res_headers_list,
                        "res_body": res_body,
                        "res_data": res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
                else:
                    jsonline = {
                        "ip_port": line.ip_port,
                        "start_timestamp": None,
                        "end_timestamp": None,
                        "req_time": req_time,
                        "src_dst_packet_count": None,
                        "dst_src_packet_count": None,
                        "src_dst_byte_count": None,
                        "dst_src_byte_count": None,
                        "req_method": method,
                        "req_uri": req_uri,
                        "req_need_length": req_len,
                        "req_headers": req_headers_list,
                        "req_body": req_body,
                        "req_data": req_data,
                        "res_time": res_time,
                        "res_status": res_status,
                        "res_reason": res_reason,
                        "res_need_length": res_len,
                        "res_headers": res_headers_list,
                        "res_body": res_body,
                        "res_data": res_data
                    }
                    fd.write(json.dumps(jsonline) + "\n")
            except Exception as e:
                logger.info(e)
                logger.info(jsonline)
    logger.info("{} has been write".format(file))


def convert_to_tuple(obj):
    if isinstance(obj, dict):
        return tuple(
            (key, convert_to_tuple(value)) for key, value in obj.items())
    elif isinstance(obj, list):
        return tuple(convert_to_tuple(item) for item in obj)
    else:
        return obj


def udpcon_write_to_files(udpcon_list, file):
    with open(file, "w+") as fd:
        # for key in udp_sessions:
        for con in udpcon_list:
            ip_port = "{}-{}-{}-{}".format(con.ip_port[0], con.ip_port[1],
                                           con.ip_port[2], con.ip_port[3])
            my_tuple_list = []
            for value_dict in con.stun_values:
                value = convert_to_tuple(value_dict)
                my_tuple_list.append(value)
            if len(my_tuple_list) > 0:
                unique_tuples = set(my_tuple_list)

                unique_dict_list = []
                for item in unique_tuples:
                    unique_dict_list.append(dict(item))
            else:
                unique_dict_list = []
            try:
                new_dict = {
                    "ip_port":
                    ip_port,
                    "start_timestamp":
                    str(datetime.datetime.fromtimestamp(con.start_timestamp)),
                    "end_timestamp":
                    str(datetime.datetime.fromtimestamp(con.end_timestamp)),
                    "packet_count":
                    con.packet_count,
                    "byte_count":
                    con.byte_count,
                    "src_dst_packet_count":
                    con.src_dst_packet_count,
                    "dst_src_packet_count":
                    con.dst_src_packet_count,
                    "src_dst_byte_count":
                    con.src_dst_byte_count,
                    "dst_src_byte_count":
                    con.dst_src_byte_count,
                    "protocol_type":
                    con.protocol_type,
                    "bit_peer_ip_1":
                    con.bit_peer_ip_1,
                    "bit_peer_id_1":
                    con.bit_peer_id_1 if len(con.bit_peer_id_1) > 0 else "",
                    "bit_peer_ip_2":
                    con.bit_peer_ip_2,
                    "bit_peer_id_2":
                    con.bit_peer_id_2 if len(con.bit_peer_id_2) > 0 else "",
                    "toutiao_ip":
                    con.toutiao_ip,
                    "toutiao_value":
                    con.toutiao_value if len(con.toutiao_value) > 0 else "",
                    "toutiao_location":
                    con.toutiao_location,
                    "xunlei_ip_1":
                    con.xunlei_ip_1,
                    "xunlei_id_1":
                    con.xunlei_id_1,
                    "xunlei_ip_2":
                    con.xunlei_ip_2,
                    "xunlei_id_2":
                    con.xunlei_id_2,
                    "stun_values":
                    unique_dict_list
                }
            except:
                logging.info(con.bit_peer_id_1)
                logging.info(con.bit_peer_id_2)
            fd.write(json.dumps(new_dict) + "\n")
    logger.info("{} has been write".format(file))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-sf', '--src_file', type=str, default=None)
    parser.add_argument("-dd", '--dst_dir', type=str, default=None)
    parser.add_argument("-cp","--corporation",type=str, default=None)
    options = parser.parse_args()
    if not os.path.isfile(options.src_file):
        print("please input source file")
        sys.exit()
    if not os.path.isdir(options.dst_dir):
        print("please input result dirctory")
        sys.exit()
    print("ok")
    log_file = os.path.join(options.dst_dir, "logs")
    loggingFormat = "%(levelname)s-%(name)s-%(asctime)s-<%(message)s>"
    formatter = logging.Formatter(loggingFormat)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    logger = logging.getLogger("")
    logger.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.info("start process pcap")
    if options.corporation == "tt":
        pp = ProcessPcapTT(options.src_file, options.dst_dir)
    elif options.corporation == "wxy":
        pp = ProcessPcapWXY(options.src_file, options.dst_dir)
    file_data, ts_domain_ip_list, savecon_list, http_list, sni_list, tmp_con, tmp_http, Certs, Cert_domain_time_list, udpcon_list,xycdn_stun_ip_port_dict = pp.main()
    tmp_con_list = dict_to_list(tmp_con)
    tmp_http_list = dict_to_list(tmp_http)
    #tcp_con_dict = con_list_to_dict(savecon_list, tmp_con_list)
    savecon_dict = con_list_to_dict(savecon_list)
    tmpcon_dict = con_list_to_dict(tmp_con_list)
    line_write_to_files(Cert_domain_time_list,
                        os.path.join(options.dst_dir, "cert_domain_time.json"))
    line_write_to_files(ts_domain_ip_list,
                        os.path.join(options.dst_dir, "ts_domain_ip.json"))
    line_write_to_files(sni_list, os.path.join(options.dst_dir, "sni.json"))
    con_write_to_files(savecon_list,
                       os.path.join(options.dst_dir, "save_con.json"))
    con_write_to_files(tmp_con_list,
                       os.path.join(options.dst_dir, "tmp_con.json"))
    http_write_to_files(savecon_dict, tmpcon_dict, http_list,
                        os.path.join(options.dst_dir, "save_http.json"))
    tmp_http_write_to_files(savecon_dict, tmpcon_dict, tmp_http_list,
                            os.path.join(options.dst_dir, "tmp_http.json"))
    udpcon_write_to_files(udpcon_list,
                          os.path.join(options.dst_dir, "udp_con.json"))
    with open(os.path.join(options.dst_dir, "file_data.json"), "w+") as fd:
        fd.write(json.dumps(file_data) + "\n")
    logger.info("file_data.json is OK")
    with open(os.path.join(options.dst_dir, "xycdn_stun_ip_port.json"), "w+") as fd:
        for key in xycdn_stun_ip_port_dict:
            new_dict = {"key": key, "num": xycdn_stun_ip_port_dict[key]}
            fd.write(json.dumps(new_dict) + "\n")
    logger.info("xycdn_stun_ip_port.json is OK")
    if not os.path.isdir(os.path.join(options.dst_dir, "cert_file")):
        os.makedirs(os.path.join(options.dst_dir, "cert_file"))
    for key in Certs:
        with open(
                os.path.join(options.dst_dir, "cert_file",
                             "{}.crt".format(key)), "wb") as fd:
            fd.write(Certs[key])
    logger.info("cert is OK")
