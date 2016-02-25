# Plex-Bandwidth-Monitor
Monitor bandwidth utilization on a per-stream basis.

Currently, this is a working proof of concept but not really
usable in its current form.  To test it out, read the install
section below.


## Install
You need to install ``pcap`` and the Python bindings.  On Ubuntu,
the following should do it:

```
sudo apt-get install libpcap0.8
sudo pip install pcap
```

You also need to open ``plex_bwmon.py`` and set your ``PLEX_TOKEN``,
which should be a valid ``X-Plex-Token``.

Now you can run ``python plex_bwmon.py`` and view real-time bandwidth
data about your streams.


## Known Limitations

  1. Does not recognize transcoded streams yet (only direct play/stream
     works at the moment).  This is a simple fix that will be addressed.
  2. If two clients from the same network (i.e. with the same public IP
     address) request the same file at the same time, then they will not
     be identified as separate streams.  This is due to the limited data
     available in the `PMS` logs.  I'm still working on a solution to
     this.
  3. Occasionally the stream metadata lookup fails to grab the metadata
     due to a race condition between when the stream is detected and when
     Plex reports the stream metadata (at the `/status/sessions` endpoint).
     This should be pretty easy to fix.
  4. Currently only works on Linux.  However, `libpcap` is available on
     most platforms (including Windows via `WinPcap`), so cross-platform
     support should be fairly easily doable.


## Technical Details

This works by listening to all outbound TCP traffic (using the `pcap`
library).  When a new stream request is observed in the `PMS` logs, the
destiation IP address **and port** are used to create a packet filter.
As packest are sent to the client at that IP address and port, the bytes
are counted and used to calculate the effective bandwidth every second.
