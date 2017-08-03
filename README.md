# Plex-Bandwidth-Monitor
Monitor bandwidth utilization on a per-stream basis.

## Install
Packets are captured via one of the following routes:

  1. `pcap`, if it is installed, or
  2. `AF_PACKET`

`AF_PACKET` is only available on Linux (as far as I know), so if you are running on a different platform, try installing `pcap`.  On Ubuntu, the following should do it:

```
sudo apt-get install python-pypcap libpcap0.8
```

You also need to open ``plex_bwmon.py`` and set your ``PLEX_TOKEN``,
which should be a valid ``X-Plex-Token``.

Now you can run ``python plex_bwmon.py`` and view real-time bandwidth
data about your streams.


## Known Limitations

  1. ~~Does not recognize transcoded streams yet (only direct play/stream
     works at the moment).  This is a simple fix that will be addressed.~~
  2. If two clients from the same network (i.e. with the same public IP
     address) request the same file at the same time, then they will not
     be identified as separate streams.  This is due to the limited data
     available in the `PMS` logs.  I'm still working on a solution to
     this.
  3. ~~Occasionally the stream metadata lookup fails to grab the metadata
     due to a race condition between when the stream is detected and when
     Plex reports the stream metadata (at the `/status/sessions` endpoint).
     This should be pretty easy to fix.~~
  4. Only tested on Linux.  However, `libpcap` is available on
     most platforms (including Windows via `WinPcap`), so cross-platform
     support should be fairly easily doable.


## Technical Details

This works by listening to all outbound TCP traffic.  When a new stream request is observed on the Plex server the destination IP address is used to create a packet filter.
As packets are sent to the client at that IP address, the bytes are counted and used to calculate the effective bandwidth.

Example output:

```
[xxx.xxx.xxx.xxx] [directplay] [username] [ 3.31,  4.11,  4.34 Mbps] [movie: Movie Name]
```

The three sets of numbers before the `Mbps` are the average bandwidths for the last minute, 5 minutes and 10 minutes, respectively.