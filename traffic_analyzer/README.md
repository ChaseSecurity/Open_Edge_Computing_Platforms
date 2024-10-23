# traffic_analyzer

**Traffic Analyzer for Open Edge Computing Platforms**

## Prerequisites  

Install the required package by running:

```
pip install dpkt==1.9.8
```
## Usage Introduction
### Handling a Single PCAP File
Use the following command to process a single PCAP file
```
python dpkt_main_single_file.py -sp src_pcap_path -dp dst_dir_path -cp [tt/wxy]
```
> `tt` means Tiptime and `wxy` stands for OneThing Cloud.
> 
> If a non-OECP pcap file is processed, you can chose any `-cp` for test, then OECP-specific features will not be normally exatracted, e.g., `xycdn_stun_ip_port` or `xunlei_ip`.

Example
```
python dpkt_main_single_file.py -sp 2023_0100.pcap -dp pcap_process_data_test -cp tt
python dpkt_main_single_file.py -sp 2023_0100.pcap -dp pcap_process_data_test -cp wxy
```
### Processing All PCAP Files on a Server
To process all PCAP files stored on a server
```
python dpkt_start.py -src_dir [path_to_pcap_files] -ip [server_ip] -cp [tt/wxy] -sd [start_date] -ed [end_date] -dst_dir [output_dir]
```
Example
```
python dpkt_start.py -src_dir ../secure_edge_computing/large_scale -ip 36.137.xxx.xxx -cp tt -sd 20230714 -ed 20230720 -dst_dir ../pcap_process_des_files
```
## Code Overview
### dpkt_connection_thread.py
This file contains the core logic for traffic processing.
#### Class: TCPConnection
Handles TCP connections, logging detailed data such as connection timestamps, byte counts, packet counts, protocol types, and more. A typical connection record looks like this:
```json
{"ip_port": "120.38.xxx.xx-55925-172.24.xx.xx-38435", "start_timestamp": "2023-06-30 02:00:01.114265", "end_timestamp": "2023-06-30 02:00:01.166715", "packet_count": 6, "byte_count": 68, "src_dst_packet_count": 3, "dst_src_packet_count": 3, "src_dst_byte_count": 68, "dst_src_byte_count": 0, "protocol_type": "BitTorrent", "http_req_time": null, "https_SNI": "", "https_SNI_ip": "", "https_SNI_time": null, "https_Cert_domain": "", "https_Cert_ip": "", "https_Cert_time": null, "bit_peer_ip_1": "120.38.xxx.xx", "bit_peer_id_1": "-BJ311-a9e5bxxxxxxxx", "bit_peer_ip_2": "", "bit_peer_id_2": "", "xunlei_ip_1": "", "xunlei_id_1": "", "xunlei_ip_2": "", "xunlei_id_2": "", "syn_flag": 2, "fin_flag": 0, "rst_flag": 1, "rtt/ms": 52.25515365600586}
```
- ip_port: Records the identifier of the connection, formatted as `src_ip-src_port-dst_ip-dst_port`. The `src_ip` represents the IP address that initiated the connection. The `src_dst_packet_count` not only indicates the number of packets but also reflects the direction of the packet flow, specifically from `src_ip` to `dst_ip`.
- start_timestamp: Records the start time of the connection.
- http_req_time: Records the time when an HTTP request was initiated, if the communication uses the HTTP protocol.
- https_SNI: Records the Server Name Indication (SNI) when communication occurs via HTTPS protocol.
- https_SNI_ip: Records the IP address corresponding to the SNI when communication occurs via HTTPS protocol.
- https_Cert_domain: Records the domain name in the returned certificate during HTTPS communication. The certificate domain can assist in analysis.
- https_Cert_ip: Records the IP address corresponding to the returned certificate during HTTPS communication.
- https_Cert_time: Records the time when the certificate was returned during HTTPS communication.
- bit_peer_ip_1: Records the IP address that sent the corresponding ID during BitTorrent communication (processed only for BitTorrent traffic in OneThingCloud).
- bit_peer_id_1: Records the peer ID sent during BitTorrent communication.
- xunlei_ip_1: Records the IP address that sent the corresponding ID during communication via an Xunlei protocol (processed only for Xunlei protocol traffic in OneThingCloud).
- xunlei_id_1: Records the peer ID sent during communication via an Xunlei protocol.
- rtt/ms: Records the round-trip time (RTT) between the connection, calculated using the three-way handshake.

    `Keys that are difficult to understand or ambiguous have been explained. Unlisted keys can be interpreted based on the explanations above.`

#### Class: UDPConnection
Handles UDP connections similarly to TCPConnection. A typical UDP connection record looks like this:
```json
{"ip_port": "192.168.xx.xxx-51299-117.143.xxx.xxx-12880", "start_timestamp": "2023-07-15 14:20:59.112154", "end_timestamp": "2023-07-15 14:21:08.460804", "packet_count": 417, "byte_count": 315222, "src_dst_packet_count": 260, "dst_src_packet_count": 157, "src_dst_byte_count": 311463, "dst_src_byte_count": 3759, "protocol_type": "toutiao", "bit_peer_ip_1": "", "bit_peer_id_1": "", "bit_peer_ip_2": "", "bit_peer_id_2": "", "toutiao_ip": "117.143.xxx.xxx", "toutiao_value": "xxx.toutiaovod.com", "toutiao_location": 30, "xunlei_ip_1": "", "xunlei_id_1": "", "xunlei_ip_2": "", "xunlei_id_2": "", "stun_values": []}
```
- toutiao_ip: Records the IP address that sends `xxxx.toutiaovod.com` during communication via the Toutiao protocol (processed only for Toutiao traffic in Tiantang).
- toutiao_value: Records the domain name `xxxx.toutiaovod.com` sent during communication via the Toutiao protocol.
- toutiao_location: Records the location of the domain name in the traffic packet when using the Toutiao protocol, which helps with further analysis.
- stun_values: Records plaintext information during communication via the STUN protocol. Each item in the list corresponds to a value sent:
    - `data_ip`: Records which IP sent the value.
    - `device_type`: Records the device type corresponding to the IP that sent the value. A `device_type` of `0` indicates an iOS device, `1` indicates an Android device, etc.
    - `resource_id`: Records the content ID being transmitted.
    - `device_id`: Records the ID of the corresponding device.
#### class ReqResBody
Handles HTTP connection data, logging details such as request/response headers, request URI, and status codes.

Example
```json
{"ip_port": "192.168.xx.xxx-60620-111.62.xx.xx-80", "start_timestamp": "2023-07-14 21:20:23.179154", "end_timestamp": "2023-07-14 21:20:23.415477", "req_time": "2023-07-14 21:20:23.187289", "src_dst_packet_count": 7, "dst_src_packet_count": 6, "src_dst_byte_count": 227, "dst_src_byte_count": 379, "req_method": "GET", "req_uri": "/testcdn.htm", "req_need_length": 0, "req_headers": [["accept", "*/*"], ["accept-language", "xxx"], ["connection", "close"], ["host", "xxx"], ["user-agent", "xxx"]], "req_body": "", "req_data": "", "res_time": "2023-07-14 21:20:23.195987", "res_status": "200", "res_reason": "OK", "res_need_length": 0, "res_headers": [["date", "Fri, 14 Jul 2023 13:20:23 GMT"], ["content-type", "text/html"], ["content-length", "8"], ["connection", "close"]], "res_body": "TestCDN\n", "res_data": ""}
```
- req_time: Records the time when the HTTP connection sent the request.
- req_method: Records the method used by the HTTP connection to send the request, whether it's GET or POST.
- req_uri: Records the URI sent by the HTTP connection, which often contains information identifying a file.
- req_need_length: Records the length of the content that needs to be saved. The maximum value is set to 5120. If the value is 0, it means either the entire content is saved or 5120 bytes have been saved but there is too much plaintext information left unsaved.
- req_headers: Records the headers sent in the request of the HTTP connection, where the ["host":"xxxxx"] header often holds valuable information.
- req_body: Records the actual content sent in the request of the HTTP connection.
- res_status: Records the status code returned in the response of the HTTP connection, such as 200, 302, etc.
- res_headers: Records the headers returned in the response of the HTTP connection, where the ["content":"xxxx"] header often holds valuable information.
- res_body: Records the actual content returned in the response of the HTTP connection.
- req_data/res_data: Reserved fields, currently unused.

### Other Key Files
- dpkt_methods.py: A collection of utility functions used for traffic processing.
- dpkt_http_methods.py: Utility functions specifically for handling HTTP traffic.
- dpkt_main.py: Processes a single PCAP file and writes results to the designated folder.
- dpkt_start.py: Entry point for batch processing all PCAP files from a deployment node.
- dpkt_main_single_file.py: Entry point for processing a single PCAP file.

## Processed File Outputs
### save_con.json & tmp_con.json
 Logs completed and incomplete TCP connections, respectively.
### save_http.json & tmp_http.json
 Logs completed and incomplete HTTP connections.
### udp_con.json
 Logs processed UDP connections.
### file_data.json
 Summarizes the PCAP file’s overall statistics.
Example 
```json
{"noip_packets": 1891, "packets_count": 471242, "tcp_packets": 454848, "tcp_packets_len": 67173610, "tcp_payload_len": 40094214, "udp_packets": 13701, "udp_packets_len": 1657870, "udp_payload_len": 1055026, "icmp_packets": 802, "other_ip_protocol_packets": 0}
```
- noip_packets: Non-IP layer protocol packets.
- packets_count: The total number of packets across all protocols.
- tcp_packets: The total number of TCP protocol packets.
- tcp_packets_len: The total size of all TCP packets.
- tcp_payload_len: The total size of TCP payloads.
- udp_packets: The total number of UDP packets.
- udp_packets_len: The total size of all UDP packets.
- udp_payload_len: The total size of UDP payloads.
- icmp_packets: The total number of ICMP packets.
- other_ip_protocol_packets: The number of packets belonging to unrecognized IP protocols.

### xycdn_stun_ip_port.json
 Logs STUN server IP and port information
### sni.json
 Records Server Name Indication (SNI) details in HTTPS communications.
### cert_domain_time.json
 Records HTTPS certificate details and domains.
### ts_domain_ip.json
 Logs DNS response information.
### cert_file/
 Directory containing certificate files extracted from traffic and each file is saved under its corresponding SHA-256 value as the filename.
### save_file/
 Reserved folder for saving other extracted content files from the pcap file.

