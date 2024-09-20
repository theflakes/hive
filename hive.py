#!/usr/bin/python3

"""
    requires NMAP be installed if using active intel gathering

    REQUIRED:
        sudo pip3 install python-nmap
        on ubuntu you may need to use apt to install python-nmap
        sudo apt install python-nmap
        sudo pip3 install netifaces
        sudo pip3 install ipaddress
        sudo pip3 install ipcalc
"""

import os
import sys
import json
import time
import logging
from logging.config import dictConfig
import threading
import socketserver
from optparse import OptionParser
import socket
import netifaces
import nmap
from datetime import datetime
import ipaddress
import ipcalc

# GLOBAL
netinfo = None

class NetInfo(object):
    """
        Initialize variables used across classes.
    """
    def __init__(self, conf):
        # this appliance's hostname
        self.local_hostname = socket.gethostname()
        # this appliance's default gateway interface
        self.dfgw_int = netifaces.gateways()['default'][netifaces.AF_INET][1]
        # this appliances default gateway IP
        self.dfgw_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
        # the IP associated with the interface used as the default gateway
        self.local_ip = netifaces.ifaddresses(self.dfgw_int)[netifaces.AF_INET][0]['addr']
        # interface IP subnet mask
        self.local_subnet_mask = netifaces.ifaddresses(self.dfgw_int)[netifaces.AF_INET][0]['netmask']
        # network ID
        self.net = ipcalc.IP(self.local_ip, self.local_subnet_mask)
        self.net_id = str(self.net.guess_network()).split('/')[0]
        self.net_id_mask = self.net_id + '/' + self.local_subnet_mask
        # cache conns to limit log creation
        self.conns = []
        # Do reverse dns lookup on source?
        self.rdns, self.l2 = conf['reverse_dns'], conf['l2_attribution']
        self.tcp_bcast, self.udp_bcast = self.get_ll_mcast(conf)
        self.timeout = conf['timeout']
        # set field names
        self.data_type = conf['field_names']['data_type']['name']
        self.data_type_value = conf['field_names']['data_type']['default']
        self.default_gateway = conf['field_names']['default_gateway']['name']
        self.device_name = conf['field_names']['device_name']['name']
        self.dst_ip = conf['field_names']['dst_ip']['name']
        self.dst_port = conf['field_names']['dst_port']['name']
        self.hostname = conf['field_names']['hostname']['name']
        self.interface_name = conf['field_names']['interface_name']['name']
        self.ip_proto = conf['field_names']['ip_proto']['name']
        self.message = conf['field_names']['message']['name']
        self.src_ip = conf['field_names']['src_ip']['name']
        self.src_mac = conf['field_names']['src_mac']['name']
        self.src_port = conf['field_names']['src_port']['name']
        self.subnet_mask = conf['field_names']['subnet_mask']['name']
        self.src_vendor = conf['field_names']['src_vendor']['name']
        self.timestamp = conf['field_names']['timestamp']['name']

    def get_ll_mcast(self, conf):
        for i in conf['ll_mcast']:
            if i['protocol'] == 'tcp':
                tcp_ports = i['ports']
            else:
                udp_ports = i['ports']
        return tcp_ports, udp_ports


class Nmap(object):
    def __init__(self, ip):
        self.ip = ip

    def get_mac(self):
        nm = nmap.PortScanner()
        try:
            return nm.scan(self.ip, arguments='-sP')
        except: 
            return None


class Conn(object):
    def __init__(self, conn, proto, server):
        # logic to ensure we do not generate a ton of logs for the same conn attempts
        if self.is_ignored(conn.client_address[0], conn.server.server_address[1], proto):
            return
        if self.is_already_logged(conn, proto):
            return
        self.server = server
        self.conn_data = {}
        self.conn_data[netinfo.data_type] = netinfo.data_type_value
        self.conn_data[netinfo.timestamp] = (datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
        self.conn_data[netinfo.device_name] = netinfo.local_hostname
        self.conn_data[netinfo.src_ip] = conn.client_address[0]
        self.conn_data[netinfo.src_port] = conn.client_address[1]
        self.conn_data[netinfo.dst_ip] = netinfo.local_ip
        self.conn_data[netinfo.dst_port] = conn.server.server_address[1]
        self.conn_data[netinfo.message] = self.get_packet_data(conn)
        self.conn_data[netinfo.ip_proto] = proto
        self.conn_data[netinfo.default_gateway] = netinfo.dfgw_ip
        self.conn_data[netinfo.interface_name] = netinfo.dfgw_int
        self.conn_data[netinfo.subnet_mask] = netinfo.local_subnet_mask
        self.conn_data[netinfo.src_mac], self.conn_data[netinfo.src_vendor] = self.get_l2()
        self.conn_data[netinfo.hostname] = self.get_reverse_dns()
        self.log()

    def is_ignored(self, src_ip, dst_port, proto):
        """
            Is the traffic common broadcast traffic expected to be seen
            on the same network as the interface that Hive is listening on?

            If so, ignore it.
        """
        if ((proto == 'udp' and dst_port in netinfo.udp_bcast) or 
            (proto == 'tcp' and dst_port in netinfo.tcp_bcast)):
            if ipaddress.IPv4Address(src_ip) in ipaddress.IPv4Network(netinfo.net_id_mask):
                return True
        return False

    def is_already_logged(self, conn, proto):
        for c in netinfo.conns:
            if (netinfo.src_ip, conn.client_address[0]) in c.items():
                if (netinfo.dst_port, conn.server.server_address[1]) in c.items():
                    if (netinfo.ip_proto, proto) in c.items():
                        return True
        return False

    def get_packet_data(self, conn):
        if conn.data:
            return repr(conn.data)
        return None

    def get_l2(self):
        mac = vendor = None
        if netinfo.l2:
            nm = Nmap(self.conn_data[netinfo.src_ip])
            info = nm.get_mac()
            try:
                mac = info['scan'][self.conn_data[netinfo.src_ip]]['addresses']['mac']
            except:
                mac = None
            try:
                vendor = info['scan'][self.conn_data[netinfo.src_ip]]['vendor'][info['scan'][self.conn_data[netinfo.src_ip]]['addresses']['mac']]
            except:
                vendor = None
        return mac, vendor

    def get_reverse_dns(self):
        hostname = None
        if netinfo.rdns:
            try:
                hostname = socket.gethostbyaddr(self.conn_data[netinfo.src_ip])
            except:
                hostname = None
        return hostname

    def log(self):
        netinfo.conns.append(self.conn_data)
        self.server.logger.info(json.dumps(self.conn_data))


#
# TCP Listener
#
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(self.server.banner + b'\n')
            self.request.settimeout(netinfo.timeout)
            self.data = self.request.recv(2048).strip()
        except:
            pass
        finally:
            if not hasattr(self, 'data'):
                self.data = None
            if hasattr(self.server, 'logger'):
                c = Conn(self, "tcp", self.server)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    pass


#
# UDP Listener
#
class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.data = self.request[0].strip()
            socket = self.request[1]
            socket.sendto(self.server.banner + b'\n', self.client_address)
            self.request.settimeout(netinfo.timeout)
        except:
            pass
        finally:
            if not hasattr(self, 'data'):
                self.data = None
            if hasattr(self.server, 'logger'):
                c = Conn(self, "udp", self.server)

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    pass


class Listener(object):
    def __init__(self, port, protocol, banner):
        self.port = port
        self.protocol = protocol
        self.banner = banner


class Honey(object):
    def __init__(self, listeners, *args, **kwargs):
        self.listeners = listeners
        self.logger = kwargs.pop("logger", None)

    def start(self):
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            return
        for l in self.listeners:
            if l.protocol == "tcp":
                server = ThreadedTCPServer(('', l.port), ThreadedTCPRequestHandler)
            elif l.protocol == "udp":
                server = ThreadedUDPServer(('', l.port), ThreadedUDPRequestHandler)
            if self.logger:
                server.logger = logging.getLogger(self.logger)
            server.banner = bytes(l.banner, 'ascii')
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

    @classmethod
    def load_from_file(cls, config, default_logger):
        with open(config, "r") as f:
            c = json.load(f)

        if "logger" in config:
            c["logger"] = config["logger"]
            if not os.path.exists(c["logger"]["logging"]["directory"]):
                os.makedirs(c["logger"]["logging"]["directory"])
        else:
            c["logger"] = default_logger

        listeners = []
        for l in c["listeners"]:
            listeners.append(Listener(**l))
        c["listeners"] = listeners

        return cls(**c)


def main(args):
    global netinfo
    with open(options.config, "r") as f:
        conf = json.load(f)

    dictConfig(conf["logging"])

    logger = logging.getLogger(conf['default_logger'])
    logger.info("Loading the honey: {0}".format(", ".join([h["config"] for h in conf["honey"]])))

    honey = []

    netinfo = NetInfo(conf)

    for h in conf["honey"]:
        honey.append(Honey.load_from_file(h["config"], h["logger"]))

    for h in honey:
        h.start()

    while True:
        time.sleep(1)


def get_parser():
    parser = OptionParser()
    parser.add_option("-c", "--conf", "--config",
                        action="store",
                        dest="config",
                        help="JSON config file for service.")
    return parser


if __name__ == "__main__":
    parser = get_parser()
    (options, args) = parser.parse_args()
    if not options.config:
        sys.stderr.write("Config file required to run (see --config)\n")
        sys.exit(-1)

    main(options)
