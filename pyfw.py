#!/usr/bin/env python3
# author: Michael Niewöhner (c0d3z3r0) <mniewoeh@stud.hs-offenburg.de>

# Links ... just that I don't forget them ...
## https://github.com/chifflier/nfqueue-bindings/blob/master/examples/example.py
## https://github.com/kti/python-netfilterqueue/network
## http://wiki.UbuntuUsers.de/Skripte/anfd

import os
import re
import glob
import socket
import struct
#import nfqueue


def readFile(file, lines=True):
    with open(file, "r") as f:
        if lines:
            return f.readlines()
        return f.read()


def hex2ip(hex_ip):
    return socket.inet_ntoa(struct.pack("<L", int(hex_ip, 16)))


# Match connection to program
def con2prog(src_ip, src_port, dst_ip, dst_port, proto):
    proc_tcp = readFile("/proc/net/%s" % proto)[1:]
    inode = None
    for p in proc_tcp:
        con = p.split()
        src = con[1].split(":")
        dst = con[2].split(":")
        if hex2ip(src[0]) == src_ip and int(src[1], 16) == src_port and \
           hex2ip(dst[0]) == dst_ip and int(dst[1], 16) == dst_port:
            inode = con[9]

    if not inode:
        return None

    pids = glob.glob("/proc/[0-9]*")
    for pid in pids:
        fds = glob.glob("%s/fd/*" % pid)
        for fd in fds:
            try:
                fdlink = os.readlink(fd)
                if re.match("socket:\[%s\]" % inode, fdlink):
                    prog = os.readlink("%s/exe" % pid)
                    cmd = readFile("%s/cmdline" % pid, lines=False).\
                        replace("\x00", " ").strip()
                    return pid, prog, cmd
            except OSError:
                pass

    return None
