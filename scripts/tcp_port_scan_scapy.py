#!/usr/bin/env -S sudo python3
"""
VERY simple port TCP port check, using Scapy
* https://scapy.readthedocs.io/en/latest/usage.html
* https://scapy.readthedocs.io/en/latest/api/scapy.html
* https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html
Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
"""
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Tuple
from argparse import ArgumentParser
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.plist import PacketList, SndRcvList
from scapy.sendrecv import sr


def load_machines_port(the_data_file: Path) -> Dict[str, List[int]]:
    port_data = {}
    with open(the_data_file, 'r') as d_scan:
        for line in d_scan:
            host, ports = line.split()
            port_data[host] = [int(p) for p in ports.split(',')]
    return port_data


def test_port(
        address: str,
        dest_ports: List[int],
        verbose: bool = False
) -> Tuple[SndRcvList, PacketList]:
    """
    Test the address + port combination
    :param address:  Host to check
    :param dest_ports: Ports to check
    :return: Answer and Unanswered packets (filtered)
    """
    ip = IP(dst=address)
    ports = TCP(dport=dest_ports)
    packet: Packet = ip / ports
    verb_level = 0
    if verbose:
        verb_level = 99
        packet.show()
    try:
        answered, not_answered = sr(
            packet,
            verbose=verb_level,
            retry=0,
            threaded=True,
            chainCC=True,
            timeout=10  # Don't set this value too low, or you will get false positives
        )

    except TypeError as ex:
        traceback.print_exc(file=sys.stdout)
        return SndRcvList(), PacketList()
    return answered, not_answered


if __name__ == "__main__":
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument("--verbose", action="store_true", help="Toggle verbose mode on/ off")
    PARSER.add_argument("scan_file", type=Path, help="Scan file with list of hosts and ports")
    ARGS = PARSER.parse_args()
    data = load_machines_port(ARGS.scan_file)
    for machine in data:
        m_ports = data[machine]
        (ans, not_ans) = test_port(address=machine, dest_ports=m_ports, verbose=ARGS.verbose)
        ans.summary(prn=lambda s, r: f"OK -> {s.dst}:{s.dport}")
        not_ans.summary(prn=lambda s: f"ERROR -> {s.dst}:{s.dport}")
