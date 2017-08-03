#!/usr/bin/env python
import argparse
import logging
import os
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
import traceback
import urllib
import urlparse

try:
    from xml.etree import cElementTree as ET
except:
    from xml.etree import ElementTree as ET

try:
    import pcap
except:
    pcap = None

# 
# TODO: Get this programatically
# 
PLEX_TOKEN = ""
PLEX_HOST  = ""
DATABASE = 'data.db'

# Ethernet header length.  Used for packet header parsing
ETH_LENGTH  = 14
ETH_P_ALL   = 3
MTU         = 0xffff


__version__ = "0.2.0"


SCHEMA = """
CREATE TABLE `sessions` (
    `id` TEXT,
    `user_id` INTEGER,
    `user_title` TEXT,
    `player_address` TEXT,
    `player_device` TEXT,
    `player_platform` TEXT,
    `video_key` TEXT,
    `part_decision` TEXT,
    `video_title` TEXT,
    `video_type` TEXT,
    `bytes` INTEGER,
    `bps`   REAL,
    PRIMARY KEY(`id`)
)"""

log = logging.getLogger(__name__)


class PacketSniffer:
    """
    Interface to sniff packets.  If libpcap is available, it will be used.
    If libpcap isn't available, then we fallback to Linux-only AF_PACKET.
    """
    def __init__(self, iface):
        self.ins = None
        self.pc  = None

        if pcap is None:
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
            self.ins.bind((iface, ETH_P_ALL))
        else:
            self.pc = pcap.pcap(iface)

    def sniff(self, callback):
        if self.ins:
            pkt, sa_ll = self.ins.recvfrom(MTU)
            callback(0, pkt)
        else:
            self.pc.dispatch(cnt=256, callback=callback)

def update_sessions(sessions):
    """
    Updates `sessions` to only include current sessions.  Returns a `dict` of
    sessions that were removed (old sessions).
    """
    res = urllib.urlopen(urlparse.urljoin(PLEX_HOST, "/status/sessions?X-Plex-Token=%s" % PLEX_TOKEN))
    dom = ET.parse(res)
    nodes = dom.findall(".//Video")
    log.info("Found nodes: %s" % nodes)

    current_session_ids = []

    for node in nodes:
        player = node.find("Player")
        sesh   = node.find("Session")
        user   = node.find("User")
        part   = node.find("Media/Part")
        trans  = node.find("TranscodeSession")

        session_id = sesh.attrib.get('id')

        if session_id not in sessions:
            # New session
            try:
                sessions[session_id] = {
                    'count':        0,
                    'total_bytes':  0,
                    'start':        time.time(),
                    'averages':     [],
                    'since':        time.time(),
                    'data':         {
                        "id":               sesh.attrib.get('id'),
                        "user_id":          user.attrib.get('id'),
                        "user_title":       user.attrib.get('title'),
                        "player_address":   player.attrib.get('address'),
                        "player_device":    player.attrib.get('device'),
                        "player_platform":  player.attrib.get('platform'),
                        "video_key":        node.attrib.get('key'),
                        "part_decision":    part.attrib.get('decision'),
                        "video_title":      node.attrib.get('title'),
                        "video_type":       node.attrib.get('type')
                    }
                }
            except Exception, e:
                print "Error creating session:", e
                continue

        current_session_ids.append(session_id)

    expired_sessions = {}
    for sid in sessions.keys():
        if sid not in current_session_ids:
            expired_sessions[sid] = sessions.pop(sid)

    return expired_sessions


class BandwidthMonitorThread(threading.Thread):
    daemon = True

    def __init__(self, iface='eth0', auto_start=True):
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

        #print s_addr, d_addr

        counter = self._counters.get(d_addr, None)
        if counter is None:
            return

        counter['total_bytes'] += len(pkt)
        counter['count'] += len(pkt)

        delta = time.time()-counter['since']
        if delta >= 60:
            avg = counter['count']/delta
            
            if len(counter['averages']) >= 10:
                counter['averages'].pop()
            counter['averages'].insert(0, avg)

            #logger.debug("[%15s] %5.2f Mbps", d_addr, counter['count']/delta*8e-6)

            print "[%15s] [%s] [%s] [%5.2f, %5.2f, %5.2f Mbps] [%s: %s]" % (
                d_addr,
                counter["data"]["part_decision"],
                counter["data"]["user_title"],
                (avg*8e-6),
                sum(counter["averages"][:5])*8e-6/(len(counter["averages"][:5])),
                sum(counter["averages"])*8e-6/(len(counter["averages"])),
                counter["data"]["video_type"],
                counter["data"]["video_title"])
            
            counter['count'] = 0
            counter['since'] = time.time()

    def add_address(self, address, data):
        if not address in self._counters:
            self._counters[address] = data
            return True
        return False

    def remove_address(self, address):
        self._counters.pop(address, None)

    def get_addresses(self):
        return self._counters.keys()

    def run(self):
        sniffer = PacketSniffer(self.__iface)

        while not self.__halt:
            try:
                sniffer.sniff(self.get_packet)
            except KeyboardInterrupt, e:
                break
            except Exception, e:
                #exc_type, exc_value, exc_traceback = sys.exc_info()
                #traceback.print_tb(exc_traceback, file=sys.stdout)
                #logger.error("Error: %s", str(e))
                print "Error: %s", str(e)
                time.sleep(1)

        #logger.debug("Quitting")
        print "Quitting"


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db_conn():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = dict_factory

    try:
        conn.execute("SELECT COUNT(*) FROM sessions")
    except:
        conn.execute(SCHEMA)
        conn.commit()

    return conn

def update_or_create_session(conn, session):
    if session['count'] > 0:
        data = session['data']
        data.update({
            'bytes': session.get('total_bytes', 0),
            'bps':   session.get('total_bytes', 0)/((time.time()-session.get('start')) or 1),
        })

        keys         = data.keys()
        fields       = ",".join(["`%s`" % f for f in keys])
        placeholders = ",".join("?" for f in keys)
        data         = [data[k] for k in keys]

        conn.execute("REPLACE INTO sessions (%s) VALUES (%s)" % (fields, placeholders), data)
        conn.commit()

def run():
    monitor = BandwidthMonitorThread()
    
    conn = get_db_conn()

    sessions = {}
    while True:

        expired_sessions = update_sessions(sessions)
        for session in sessions.values():
            monitor.add_address(session['data']['player_address'], session)
            update_or_create_session(conn, session)

        for session in expired_sessions.values():
            print "Removing address", session['data']['player_address']
            monitor.remove_address(session['data']['player_address'])

        time.sleep(5)
        continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor bandwidth usage of Plex')
    
    args = parser.parse_args()

    try:
        run()
    except KeyboardInterrupt:
        print "Bye!"

