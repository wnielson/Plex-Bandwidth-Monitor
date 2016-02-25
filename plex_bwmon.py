#!/usr/bin/env python
import logging
import os
import re
import socket
import struct
import threading
import time
import urllib

try:
    from xml.etree import cElementTree as ET
except:
    from xml.etree import ElementTree as ET

import pcap

# TODO: Get this programatically
PLEX_TOKEN = ""

# TODO: Add support for transcoded streams
STREAM_RE = re.compile(r"(Request|Completed): \[([\d\.]+)\:(\d+)\] GET \/library\/parts")

# TODO: Use the correct file depending on the current platform
LOG_FILE = "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log"

# Ethernet header length.  Used for packet header parsing
ETH_LENGTH = 14

log = logging.getLogger(__name__)

def tail_f(file_name, interval=0.2):
    """
    Opens file ``file_name`` and yields lines from the end of the file as the
    file is written to.  The result is similar to "tail -f" on *nix systems.
    """
    fh = open(file_name)

    # Keep track of the file's inode.  When this changes, we know the file has
    # changed (been deleted or renamed) as well
    inode = os.fstat(fh.fileno()).st_ino

    fh.seek(0, 2)
    while True:
        where = fh.tell()
        line  = fh.readline()
        if not line:
            time.sleep(interval)
            fh.seek(where)
        else:
            yield line
        
        # If the file that we're interested in has a new inode, then we need to
        # stop to signal that the file needs to be re-opened
        if os.stat(file_name).st_ino != inode:
            log.info("File was removed: %s" % file_name)
            break

def etree_to_dict(t):
    """
    Convert an ElementTree node ``t`` into a ``dict``.  Attributes are prefaced
    with the "@" symbol.
    """
    d = {t.tag : map(etree_to_dict, t.getchildren())}
    d.update(('@' + k, v) for k, v in t.attrib.iteritems())
    d['text'] = t.text
    return d

def get_session(part_id):
    """

    """
    res = urllib.urlopen("http://localhost:32400/status/sessions?X-Plex-Token=%s" % PLEX_TOKEN)
    dom = ET.parse(res)
    nodes = dom.findall(".//Video/Media/Part[@id='%s']" % part_id)
    log.info("Found nodes: %s" % nodes)
    if len(nodes) == 1:
        return etree_to_dict(nodes[0])
    return None


class BandwidthMonitorThread(threading.Thread):
    daemon = True

    def __init__(self, iface=None, auto_start=True):
        threading.Thread.__init__(self)

        self.__halt    = False
        self.__iface   = iface
        self._counters = {}
        
        if auto_start:
            self.start()

    def get_packet(self, i, pkt):
        ip_header = pkt[ETH_LENGTH:20+ETH_LENGTH]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        counter = self._counters.get(d_addr, None)
        if counter is None:
            return

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        t = iph_length + ETH_LENGTH
        tcp_header = pkt[t:t+20]
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

        dest_port = int(tcph[1])

        counter = counter.get(dest_port, None)
        if counter is None:
            return

        counter['count'] += len(pkt)
        delta = time.time()-counter['since']
        if delta >= 1:
            #logger.debug("[%15s] %5.2f Mbps", d_addr, counter['count']/delta*8e-6)
            name = ""
            if counter["data"]:
                name = "file='%s'" % os.path.basename(counter["data"]["@file"])
            print "[%15s:%s] %5.2f Mbps %s" % (d_addr, dest_port, counter['count']/delta*8e-6, name)
            counter['count'] = 0
            counter['since'] = time.time()

    def add_address(self, address, port, data=None):
        self._counters.setdefault(address,{})[int(port)] = {
            'count': 0,
            'since': time.time(),
            'data':  data
        }

    def remove_address(self, address, port):
        counter = self._counters.get(address, {})
        counter.pop(int(port), None)
        if len(counter) == 0:
            self._counters.pop(address, None)

    def run(self):
        #logger.info("Starting BandwidthMonitorThread")
        pc = pcap.pcap(self.__iface)
        while not self.__halt:
            try:
                pc.dispatch(cnt=256, callback=self.get_packet)
            except Exception, e:
                #logger.error("Error: %s", str(e))
                print "Error: %s", str(e)
                time.sleep(2)
        #logger.debug("Quitting")
        print "Quitting"

def run():
    monitor = BandwidthMonitorThread()
    streams = {}
    while True:
        print "Opening log file: %s" % LOG_FILE
        for line in tail_f(LOG_FILE):
            m = STREAM_RE.search(line)
            if m:
                groups = m.groups()
                media  = line.split("GET /library/parts/")[-1].split("/")[0]
                key    = "%s:%s" % (groups[1], groups[2])
                if groups[0] == "Request":
                    streams[key] = media
                    session = get_session(media) 
                    monitor.add_address(groups[1], groups[2], session)
                    get_session(media)
                    print "Start stream [%d]: %s:%s %s" % (len(streams), groups[1], groups[2], media)
                else:
                    streams.pop(key, None)
                    monitor.remove_address(groups[1], groups[2])
                    print "End stream [%d]:   %s:%s %s" % (len(streams), groups[1], groups[2], media)

                
if __name__ == "__main__":
    run()
