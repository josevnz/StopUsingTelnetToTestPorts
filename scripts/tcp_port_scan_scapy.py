#!/usr/bin/env -S sudo python3
"""
VERY simple port TCP port check, using Scapy
* https://scapy.readthedocs.io/en/latest/usage.html
* https://scapy.readthedocs.io/en/latest/api/scapy.html
* https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html
* Please check out the original script: https://thepacketgeek.com/scapy/building-network-tools/part-10/
Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
"""
import os
import sys
import traceback
from enum import IntEnum
from pathlib import Path
from random import randint
from typing import Dict, List
from argparse import ArgumentParser
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

NON_PRIVILEGED_LOW_PORT = 1025
NON_PRIVILEGED_HIGH_PORT = 65534
ICMP_DESTINATION_UNREACHABLE = 3


class TcpFlags(IntEnum):
    """
    https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    """
    SYNC_ACK = 0x12
    RST_PSH = 0x14


class IcmpCodes(IntEnum):
    """
    ICMP codes, to decide
    https://www.ibm.com/docs/en/qsip/7.4?topic=applications-icmp-type-code-ids
    """
    Host_is_unreachable = 1
    Protocol_is_unreachable = 2
    Port_is_unreachable = 3
    Communication_with_destination_network_is_administratively_prohibited = 9
    Communication_with_destination_host_is_administratively_prohibited = 10
    Communication_is_administratively_prohibited = 13


FILTERED_CODES = [x.value for x in IcmpCodes]


class RESPONSES(IntEnum):
    """
    Customized responses for our port check
    """
    FILTERED = 0
    CLOSED = 1
    OPEN = 2
    ERROR = 3


def load_machines_port(the_data_file: Path) -> Dict[str, List[int]]:
    port_data = {}
    with open(the_data_file, 'r') as d_scan:
        for line in d_scan:
            host, ports = line.split()
            port_data[host] = [int(p) for p in ports.split(',')]
    return port_data


def test_port(
        address: str,
        dest_ports: int,
        verbose: bool = False
) -> RESPONSES:
    """
    Test the address + port combination
    :param address:  Host to check
    :param dest_ports: Ports to check
    :return: Answer and Unanswered packets (filtered)
    """
    src_port = randint(NON_PRIVILEGED_LOW_PORT, NON_PRIVILEGED_HIGH_PORT)
    ip = IP(dst=address)
    ports = TCP(sport=src_port, dport=dest_ports, flags="S")
    reset_tcp = TCP(sport=src_port, dport=dest_ports, flags="S")
    packet: Packet = ip / ports
    verb_level = 0
    if verbose:
        verb_level = 99
        packet.show()
    try:
        answered = sr1(
            packet,
            verbose=verb_level,
            retry=1,
            timeout=1,
            threaded=True
        )
        if not answered:
            return RESPONSES.FILTERED
        elif answered.haslayer(TCP):
            if answered.getlayer(TCP).flags == TcpFlags.SYNC_ACK:
                rst_packet = ip / reset_tcp
                sr(rst_packet, timeout=1, verbose=verb_level)
                return RESPONSES.OPEN
            elif answered.getlayer(TCP).flags == TcpFlags.RST_PSH:
                return RESPONSES.CLOSED
        elif answered.haslayer(ICMP):
            icmp_type = answered.getlayer(ICMP).type
            icmp_code = int(answered.getlayer(ICMP).code)
            if icmp_type == ICMP_DESTINATION_UNREACHABLE and icmp_code in FILTERED_CODES:
                return RESPONSES.FILTERED
    except TypeError:
        traceback.print_exc(file=sys.stdout)
        return RESPONSES.ERROR


if __name__ == "__main__":
    if os.getuid() != 0:
        raise EnvironmentError(f"Sorry, you need to be root to run this program!")
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument("--verbose", action="store_true", help="Toggle verbose mode on/ off")
    PARSER.add_argument("scan_file", type=Path, help="Scan file with list of hosts and ports")
    ARGS = PARSER.parse_args()
    data = load_machines_port(ARGS.scan_file)
    for machine in data:
        m_ports = data[machine]
        for dest_port in m_ports:
            ans = test_port(address=machine, dest_ports=dest_port, verbose=ARGS.verbose)
            print(f"{ans.name} -> {machine}:{dest_port}")
