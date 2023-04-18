# Stop using telnet to test ports

Most of you know telnet. It was the most common way to access remote systems before more robust and secure alternatives like SSH showed up.

Telnet protocol is not encrypted and that is the reason nobody uses it to provide access to a server anymore. Instead, people use it to check if a service
is listening on a given port like this: ```telnet $machine $port```:

```shell

[josevnz@dmaf5 Downloads]$ telnet raspberrypi 8086
Trying fd22:4e39:e630:1:dea6:32ff:fef9:4748...
Connected to raspberrypi.
Escape character is '^]'.
  
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad RequestConnection closed by foreign host.
```

You then press Ctrl-D to exit the session or press a key to force the server to close the connection.

This [is perfectly fine assuming you are only testing one service](https://www.redhat.com/sysadmin/telnet-troubleshoot-mail-system) and one port, but what if you need to perform automatic 
checks on a large combination of hosts and ports?

I prefer to let the computer do the boring stuff for me, specially when it comes to test [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)/ IP basic 
connectivity like open ports.

On this article I will show you how to perform the following tasks:

* Improve your usage of Telnet with Expect
* How you can do the same with Bash
* How to use Netcat as a replacement of a tcp check
* Using NMAP to perform more complex checks
* Writing your port check program with Scapy

We will focus on TCP connectivity testing as opposed to UDP.

## Knowing what to Expect (at least with automation)

[Expect](https://en.wikipedia.org/wiki/Expect) is an extension of the programming [language TCL](https://tcl.tk/man/tcl8.5/tutorial/Tcl0.html)
that can be used to automate external processes.

With Expect you can then read the list of hosts and ports from a file and use Telnet to check if a TCP port is responding or not.

So say you have the following [configuration file](data/port_scan.csv):
```csv
google.com 80
amazon.com 80
raspberrypi 22,9090,8086,21
dmaf5 22,80
```

Then with a bit of expect magic you could automate the process like this [using this script](scripts/tcp_port_scan.exp):

```text
#!/usr/bin/env -S expect -f
# Poor man TCP port scanner with Telnet and Expect
# Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
if { $argc == 0 } {
        send_user "Please provide the data file with machine port, one per line!"
        exit 100
}
set timeout 5
set f [open [lindex $argv 0]]
foreach host [split [read $f] "\n"] {
    set pairs [split $host " "];
    set machine [lindex $pairs 0]
    set ports [lindex $pairs 1]
    foreach port [split $ports ","] {
        log_user 0
        spawn /bin/telnet -e ! $machine $port
        expect {
            log_user 1
            "Connection refused" { catch {exp_close}; exp_wait; send_user "ERROR: $machine -> $port\n" }
            "Escape character is '!'." { send_user "OK: $machine -> $port\n"; send "!\r" }
        }
    }
}
close $f
```

For example, your output could like this:

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ ./tcp_port_scan.exp data/port_scan.csv 
OK: google.com -> 80
OK: amazon.com -> 80
OK: raspberrypi -> 22
OK: raspberrypi -> 9090
OK: raspberrypi -> 8086
ERROR: raspberrypi -> 21
OK: dmaf5 -> 22
ERROR: dmaf5 -> 80
```

So when you should use this? This is a good alternative is you already have both Expect and Telnet installed on one of your
machines (if not a ```sudo dnf install -y expect telnet``` will do the trick), but it is not efficient as you have to fork 
a telnet session with every port that is checked.

You have to account for all the possible responses from the Telnet command and subtle issues like your timeout being too small (what if the port is being filtered?)

To make things worst, Our script is not getting more complicated ... 

## You can do it in Bash too

Then of course you decide is OK to write a TCP port check in [Bash](scripts/tcp_port_scan.sh) because you can:

```shell
#!/bin/bash -e
# Poor man TCP port scanner with Bash
# Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
if [ -n "$1" ] && [ -f "$1" ]; then
  while read -r line; do
    machine=$(echo "$line"| /bin/cut -d' ' -f1)|| exit 100
    ports=$(echo "$line"| /bin/cut -d' ' -f2)|| exit 101
    OLD_IFS=$OLD_IFS
    IFS=","
    for port in $ports; do
      if  (echo >/dev/tcp/"$machine"/"$port") >/dev/null 2>&1; then
        echo "OK: $machine -> $port"
      else
        echo "ERROR: $machine -> $port"
      fi
    done
    IFS=$OLD_IFS
  done < "$1"
else
  echo "ERROR: Invalid or missing data file!"
  exit 103
fi
```

The [pure Bash script](scripts/tcp_port_scan.sh) works pretty much the same as out Expect version:
```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ ./tcp_port_scan.sh data/port_scan.csv 
OK: google.com -> 80
OK: amazon.com -> 80
OK: raspberrypi -> 22
OK: raspberrypi -> 9090
OK: raspberrypi -> 8086
ERROR: raspberrypi -> 21
OK: dmaf5 -> 22
ERROR: dmaf5 -> 80
```

It is faster than the Except version (no Telnet forking) but error handling is complicated, also it doesn't deal well with filtered ports.

Any other options? For example, what you can do if you want to check connectivity with a host that is behind a firewall?

## Concatenate on the net with Netcat

[Netcat](https://en.wikipedia.org/wiki/Netcat) is another versatile program that can use proxies to connect to other machines. It is also one of those programs with several implementations.

So for sake of example, let's assume you want to check if port 22 is open on raspberrypi.home:

```shell
[josevnz@dmaf5 Documents]$ nc -z -v -w 5 raspberrypi 22
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to fd22:4e39:e630:1:dea6:32ff:fef9:4748:22.
Ncat: 0 bytes sent, 0 bytes received in 0.06 seconds.
# Trying a closed port like 222
[josevnz@dmaf5 Documents]$ nc -z -v -w 5 raspberrypi 222
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connection to fd22:4e39:e630:1:dea6:32ff:fef9:4748 failed: Connection refused.
Ncat: Trying next address...
Ncat: Connection refused.
```

With that in mind let's see how we can automate scanning a bunch of hosts using a [Netcat wrapper](scripts/tcp_port_scanner_nc.sh):

```shell
# Port check with Netcat
# Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
if [ -n "$1" ] && [ -f "$1" ]; then
  while read -r line; do
    machine=$(echo "$line"| /bin/cut -d' ' -f1)|| exit 100
    ports=$(echo "$line"| /bin/cut -d' ' -f2)|| exit 101
    OLD_IFS=$OLD_IFS
    IFS=","
    for port in $ports; do
      if  /usr/bin/nc -z -v -w 5 "$machine" "$port" > /dev/null 2>&1; then
        echo "OK: $machine -> $port"
      else
        echo "ERROR: $machine -> $port"
      fi
    done
    IFS=$OLD_IFS
  done < "$1"
else
  echo "ERROR: Invalid or missing data file!"
  exit 103
fi
```

So why you would want to use nc over the previous script written in Bash? Let me give you a few reasons:

### You can use a SOCKS proxy
* You can use a [Socks](https://en.wikipedia.org/wiki/SOCKS) proxy to scan servers with '-x'. For example, start a SOCKS proxy like this on port 2080:
```shell
josevnz@raspberrypi:~$ ssh -f -g -D 2080 -C -q -N josevnz@192.168.1.27
```

And then access the servers behind your firewall like this:

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ nc --proxy 192.168.1.27:2080 --proxy-type socks5 -z -v -w 5 redhat.com 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to proxy 192.168.1.27:2080
Ncat: No authentication needed.
Ncat: Host redhat.com will be resolved by the proxy.
Ncat: connection succeeded.
Ncat: 0 bytes sent, 0 bytes received in 0.12 seconds.
```

### Start a simple server

NC can also be used [to start a server to help you test basic connectivity](https://www.redhat.com/sysadmin/setting-tcp-listener), in case you don't have a server handy.

On the receiving side, we start a server:

```shell
josevnz@raspberrypi:~$ nc -l 2080
```

And then on the client:

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ nc --verbose 192.168.1.27 2080
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.1.27:2080.
Hello
Hi
```

And now you can write and receive messages on both sides, a bidirectional chat.

There are other features and use cases for nc, feel free to read the documentation to learn more.

## Nmap is the swiss army knife of the network tools

Netcat is pretty handy for TCP connectivity testing, but when it comes with a CLI tool with a powerful array of options you cannot beat [Nmap](https://nmap.org/).

Nmap offers a higher grade of automation than Necat. For example, we can provide a [data file on the format that Nmap understands](data/port_scan_nmap.csv):

```csv
google.com
amazon.com
raspberrypi.home
dmaf5.home
```

So say you want to check all these hosts for just port 80 and 443 (```nmap -iL port_scan_nmap.csv -p80,443```):

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ nmap -iL data/port_scan_nmap.csv -p80,443
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-19 20:18 EDT
Nmap scan report for google.com (142.250.72.110)
Host is up (0.014s latency).
Other addresses for google.com (not scanned): 2607:f8b0:4006:81c::200e
rDNS record for 142.250.72.110: lga34s32-in-f14.1e100.net

PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap scan report for amazon.com (54.239.28.85)
Host is up (0.019s latency).
Other addresses for amazon.com (not scanned): 52.94.236.248 205.251.242.103

PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap scan report for raspberrypi.home (192.168.1.27)
Host is up (0.00062s latency).
Other addresses for raspberrypi.home (not scanned): fd22:4e39:e630:1:dea6:32ff:fef9:4748

PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https

Nmap scan report for dmaf5.home (192.168.1.30)
Host is up (0.00041s latency).
Other addresses for dmaf5.home (not scanned): fd22:4e39:e630:1:67b8:6c9e:14f0:5d6c fd22:4e39:e630:1:dd80:f446:ff6c:aa4a 192.168.1.31

PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https
```

If you notice, this gives you more freedom with the IP address or network ranges but no much choice if you want to use different port combinations.

A way to deal with this is either iterate to each machine and port combination from an external script and then call NMap or let NMap check also those non-existing ports and then analyze the results:

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ nmap -iL data/port_scan_nmap.csv -p80,22,9090,8086,21 --open -oG -| /bin/rg -v -e 'Status: Up|^#'
Host: 142.250.72.110 (lga34s32-in-f14.1e100.net)	Ports: 80/open/tcp//http///	Ignored State: filtered (4)
Host: 205.251.242.103 (s3-console-us-standard.console.aws.amazon.com)	Ports: 80/open/tcp//http///	Ignored State: closed (4)
Host: 192.168.1.27 (raspberrypi.home)	Ports: 22/open/tcp//ssh///, 8086/open/tcp//d-s-n///, 9090/open/tcp//zeus-admin///	Ignored State: closed (2)
Host: 192.168.1.30 (dmaf5.home)	Ports: 22/open/tcp//ssh///	Ignored State: closed (4)
```

### Can Nmap use SOCK5 proxies?

Yes it does but _not the way you think_. NMap distribution also comes with its own Netcat called '[ncat](https://nmap.org/book/ncat-man.html#ncat-man-proxy-options)'.
Which one to use? It depends on your use case, I normally deal with whichever version is installed.

## When an open TCP Socket test is not enough 

Checking just to see if a port is open is not an indication than a service is healthy. The server may be accepting connection and yet, there could be more subttle problems.

For example, checking if a webserver SSL works and the digital certificates look correct:

```shell
# You may have to do a `sudo dnf install -y openssl.x86_6`
[josevnz@dmaf5 ~]$ openssl s_client -tls1_2 -connect solomon.stupidzombie.com:443
CONNECTED(00000003)
depth=2 C = US, O = Internet Security Research Group, CN = ISRG Root X1
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = R3
verify return:1
depth=0 CN = solomon.stupidzombie.com
verify error:num=10:certificate has expired
notAfter=Mar 11 14:38:06 2023 GMT
verify return:1
depth=0 CN = solomon.stupidzombie.com
notAfter=Mar 11 14:38:06 2023 GMT
verify return:1
---
...
```

You can see here the socket connection worked but the SSL certificate has expired!

Let me show you another way to test the same webserver:
```shell
[josevnz@dmaf5 ~]$ curl --fail --verbose https://solomon.stupidzombie.com:443
*   Trying 132.145.176.191:443...
* Connected to solomon.stupidzombie.com (132.145.176.191) port 443 (#0)
* ALPN: offers h2
* ALPN: offers http/1.1
*  CAfile: /etc/pki/tls/certs/ca-bundle.crt
*  CApath: none
* TLSv1.0 (OUT), TLS header, Certificate Status (22):
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS header, Certificate Status (22):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS header, Finished (20):
* TLSv1.2 (IN), TLS header, Supplemental data (23):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.2 (IN), TLS header, Supplemental data (23):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS header, Unknown (21):
* TLSv1.3 (OUT), TLS alert, certificate expired (557):
* SSL certificate problem: certificate has expired
* Closing connection 0
curl: (60) SSL certificate problem: certificate has expired
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

This time curl is telling us than the certificate expired. Webserver is working as expected but there is a problem with the digital certificates. 

Every HTTP application can be tested the same way? Not true, take a look how Grafana can tell you if is OK or not:

```shell
[josevnz@dmaf5 ~]$ curl --fail --silent http://raspberrypi:3000/api/health && printf "\nLook, I'm OK\n"
{
  "commit": "21c1d14e91",
  "database": "ok",
  "version": "9.3.2"
}
Look, I'm OK
```

Or InfluxDB database:

```shell
[josevnz@dmaf5 ~]$ curl --fail http://raspberrypi:8086/ping && printf "Look, I'm OK"
Look, I'm OK
```

I have a nice surprise for you: Nmap can also call '[scripts](https://www.redhat.com/sysadmin/nmap-scripting-engine)' to perform high level checks on applications, like webservers:

```shell
[josevnz@dmaf5 ~]$ nmap -p443 -PS443 --open --script http-fetch --script-args 'maxpagecount=1,destination=/tmp/files' solomon.stupidzombie.com
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 20:48 EDT
Nmap scan report for solomon.stupidzombie.com (132.145.176.191)
Host is up (0.023s latency).

PORT    STATE SERVICE
443/tcp open  https
|_http-fetch: Successfully Downloaded Everything At: /tmp/files/132.145.176.191/443/

Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds

[josevnz@dmaf5 ~]$ find /tmp/files/132.145.176.191/443/
/tmp/files/132.145.176.191/443/
/tmp/files/132.145.176.191/443/index.html
```

What about a MySQL database? Imap server? You get the idea, there are many ways to tackle this problem.

## DIY with Python and Scapy

There is another option when you want the ultimate control and flexibility: Do it Yourself (DIY). Programming languages like Python offer socket programming API and access to sophisticated frameworks like [Scapy](https://scapy.net/) to accomplish that.

But first, a simple TCP port check in Python:

```python
#!/usr/bin/env python3
"""
VERY simple port TCP port check
https://docs.python.org/3/library/socket.html
Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
"""
import socket
from pathlib import Path
from typing import Dict, List
from argparse import ArgumentParser


def load_machines_port(the_data_file: Path) -> Dict[str, List[int]]:
    port_data = {}
    with open(the_data_file, 'r') as d_scan:
        for line in d_scan:
            host, ports = line.split()
            port_data[host] = [int(p) for p in ports.split(',')]
    return port_data


def test_port(address: str, dest_port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex((address, dest_port)) == 0:
                return True
        return False
    except (OSError, ValueError):
        return False


if __name__ == "__main__":
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument("scan_file", type=Path, help="Scan file with list of hosts and ports")
    ARGS = PARSER.parse_args()
    data = load_machines_port(ARGS.scan_file)
    for machine in data:
        for port in data[machine]:
            try:
                results = test_port(machine, port)
            except (OSError, ValueError):
                results = False
            if results:
                print(f"{machine}:{port}: OK")
            else:
                print(f"{machine}:{port}: ERROR")
```

We open the socket, assume than any error means the port is closed, or filtered. If you run it (```./scripts/tcp_port_scan.py data/port_scan.csv```):

```shell
google.com:80: OK
amazon.com:80: OK
raspberrypi:22: OK
raspberrypi:9090: OK
raspberrypi:8086: OK
raspberrypi:21: ERROR
dmaf5:22: OK
dmaf5:80: ERROR
```

Works as expected. What if we could use a framework that could allow us to skip all the boilerplate while doing more complex stuff?

### What is Scapy?

The [project document page](https://scapy.readthedocs.io/en/latest/introduction.html) does a pretty good job explaining what the tool can and cannot do:
> Scapy is a Python program that enables the user to send, sniff and dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack networks.

Most Linux distributions have a package for it, on Fedora it is pretty easy to install like this:
```shell
[josevnz@dmaf5 ~]$ sudo dnf install -y python3-scapy.noarch
```

Scapy require elevated privileges to run, if you decide to use a pip then you may do the following:

```shell
sudo -i
python3 -m venv /usr/local/scapy
. /usr/local/scapy/bin/activate
pip install --upgrade pip
pip install wheel
pip install scapy
```

Just remember to activate your virtual environment before calling Scapy if you install it that way.

Scapy can be used as a library and also as an interactive shell, I'll show you next a few applications.

### A simple interactive TCP port scanner

In the interactive mode, we call Scapy terminal as root, as it requires elevated privileges. 

For that we will add layers:
* An IP network layer (```IP(dst="raspberrypi.home")```)
* Then TCP ports (```TCP(dport=[22,3000,8086]```)
* We send the packets and capture answered, unanswered results (```(ans, notanws) = sr(*)```) 
* Then we analyze the answered results, filter only open ports (```ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))```)

```shell
[josevnz@dmaf5 ~]$ sudo scapy3 -H
>>> (ans, notanws) = sr(IP(dst="raspberrypi.home")/TCP(dport=[22,3000,8086]))
Begin emission:
Finished sending 3 packets.

Received 5 packets, got 3 answers, remaining 0 packets

>>> ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))
ssh is open
hbci is open
d_s_n is open
```
Not bad for just two lines of code versus forty-six from our first Python script. 

This time will try to create an automated port scanner, using what we learned before.

### Our custom port check, Scapy flavor

The interactive shell is nice when you are exploring and trying things to see what is the best way to tackle a problem, but once you come with a solution we can just make it a script:

```python
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
```

This script is more complex but also offers a more detailed explanation of the analyzed ports. You can run it like this: ```./tcp_port_scan_scapy.py data/port_scan.csv```:

```shell
[josevnz@dmaf5 StopUsingTelnetToTestPorts]$ ./scripts/tcp_port_scan_scapy.py data/port_scan.csv 
OPEN -> google.com:80
OPEN -> amazon.com:80
OPEN -> raspberrypi:22
OPEN -> raspberrypi:9090
OPEN -> raspberrypi:8086
CLOSED -> raspberrypi:21
FILTERED -> dmaf5:22
FILTERED -> dmaf5:80
```

One connection closed and 2 of them possibly filtered.

The real power of Scapy is the level of customization you now have from a familiar language like Python. The shell mode is particular important as you can troubleshoot network problems with ease while doing some exploration work.

## Wrapping up, what to learn next

* Expect is an extension of TCL, so [you should read more](https://wiki.tcl-lang.org/page/Tcl+Tutorial+Lesson+0) if you want to get familiar with what the language can do.
* Bash can also be used to do UDP checks. [This excellent guide](https://www.xmodulo.com/tcp-udp-socket-bash-shell.html) can show you how to do that and much more.
* Netcat and NMap are powerful tools that deserve time to be studied. You will be surprised [the amount of things](https://www.redhat.com/sysadmin/ansible-dynamic-inventories) they can do for you besides basic TCP port checks.
* Nmap can be extended with [LUA scripts](https://nmap.org/book/nse-language.html) to perform more complex checks.
* In the case of NMap you can eve use scripts to test at the protocol level, not just opening the port.
* Scapy which will allow you to [perform complex packet manipulations](https://scapy.readthedocs.io/en/latest/usage.html). Do yourself a favor and [read this tutorial](https://guedou.github.io/talks/2022_GreHack/Scapy%20in%200x30%20minutes.slides.html#/52), you'll be amazed what you can do with it.
* Telnet client may not be installed in your Linux distribution anymore as the server [is considered insecure](https://www.redhat.com/sysadmin/replace-telnet-ssh-ftp-sftp), so it is a good idea to learn other tools.
* Finally, we didn't cover UDP or Multicast testing. This deserves to be explored separately with more detail.