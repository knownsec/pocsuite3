# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions to send and receive packets.
"""

# from __future__ import absolute_import, print_function
from threading import Thread
import time

from pocsuite3.thirdparty.scapy.data import ETH_P_ALL
from pocsuite3.thirdparty.scapy.config import conf
from pocsuite3.thirdparty.scapy.error import warning
from pocsuite3.thirdparty.scapy.packet import Packet
from pocsuite3.thirdparty.scapy.utils import get_temp_file, tcpdump, wrpcap, PcapReader
from pocsuite3.thirdparty.scapy.error import Scapy_Exception
from pocsuite3.thirdparty.scapy import six
from pocsuite3.thirdparty.scapy.sessions import DefaultSession
# if conf.route is None:
#     # unused import, only to initialize conf.route
#     import route  # noqa: F401

#################
#  Debug class  #
#################


class debug:
    recv = []
    sent = []
    match = []
    crashed_on = None


class AsyncSniffer(object):
    def __init__(self, *args, **kwargs):
        # Store keyword arguments
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.results = None

    def _setup_thread(self):
        # Prepare sniffing thread
        self.thread = Thread(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs
        )
        self.thread.setDaemon(True)

    def _run(self,
             count=0, store=True, offline=None,
             quiet=False, prn=None, lfilter=None,
             L2socket=None, timeout=None, opened_socket=None,
             stop_filter=None, iface=None, started_callback=None,
             session=None, session_args=[], session_kwargs={},
             *arg, **karg):
        self.running = True
        # Start main thread
        # instantiate session
        if not isinstance(session, DefaultSession):
            session = session or DefaultSession
            session = session(prn=prn, store=store,
                              *session_args, **session_kwargs)
        else:
            session.prn = prn
            session.store = store
        # sniff_sockets follows: {socket: label}
        sniff_sockets = {}
        if opened_socket is not None:
            if isinstance(opened_socket, list):
                sniff_sockets.update(
                    (s, "socket%d" % i)
                    for i, s in enumerate(opened_socket)
                )
            elif isinstance(opened_socket, dict):
                sniff_sockets.update(
                    (s, label)
                    for s, label in six.iteritems(opened_socket)
                )
            else:
                sniff_sockets[opened_socket] = "socket0"
        if offline is not None:
            flt = karg.get('filter')

            if isinstance(offline, list) and \
                    all(isinstance(elt, str) for elt in offline):
                sniff_sockets.update((PcapReader(
                    fname if flt is None else
                    tcpdump(fname, args=["-w", "-"], flt=flt, getfd=True)
                ), fname) for fname in offline)
            elif isinstance(offline, dict):
                sniff_sockets.update((PcapReader(
                    fname if flt is None else
                    tcpdump(fname, args=["-w", "-"], flt=flt, getfd=True)
                ), label) for fname, label in six.iteritems(offline))
            else:
                # Write Scapy Packet objects to a pcap file
                def _write_to_pcap(packets_list):
                    filename = get_temp_file(autoext=".pcap")
                    wrpcap(filename, offline)
                    return filename, filename

                if isinstance(offline, Packet):
                    tempfile_written, offline = _write_to_pcap([offline])
                elif isinstance(offline, list) and \
                        all(isinstance(elt, Packet) for elt in offline):
                    tempfile_written, offline = _write_to_pcap(offline)

                sniff_sockets[PcapReader(
                    offline if flt is None else
                    tcpdump(offline,
                            args=["-w", "-"],
                            flt=flt,
                            getfd=True,
                            quiet=quiet)
                )] = offline
        if not sniff_sockets or iface is not None:
            if L2socket is None:
                L2socket = conf.L2listen
            if isinstance(iface, list):
                sniff_sockets.update(
                    (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg),
                     ifname)
                    for ifname in iface
                )
            elif isinstance(iface, dict):
                sniff_sockets.update(
                    (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg),
                     iflabel)
                    for ifname, iflabel in six.iteritems(iface)
                )
            else:
                sniff_sockets[L2socket(type=ETH_P_ALL, iface=iface,
                                       *arg, **karg)] = iface

        # Get select information from the sockets
        _main_socket = next(iter(sniff_sockets))
        select_func = _main_socket.select
        _backup_read_func = _main_socket.__class__.recv
        nonblocking_socket = _main_socket.nonblocking_socket
        # We check that all sockets use the same select(), or raise a warning
        if not all(select_func == sock.select for sock in sniff_sockets):
            warning("Warning: inconsistent socket types ! "
                    "The used select function "
                    "will be the one of the first socket")

        if nonblocking_socket:
            # select is non blocking
            def stop_cb():
                self.continue_sniff = False
            self.stop_cb = stop_cb
            close_pipe = None
        else:
            # select is blocking: Add special control socket
            from pocsuite3.thirdparty.scapy.automaton import ObjectPipe
            close_pipe = ObjectPipe()
            sniff_sockets[close_pipe] = "control_socket"

            def stop_cb():
                if self.running:
                    close_pipe.send(None)
                self.continue_sniff = False
            self.stop_cb = stop_cb

        try:
            if started_callback:
                started_callback()
            self.continue_sniff = True

            # Start timeout
            if timeout is not None:
                stoptime = time.time() + timeout
            remain = None

            while sniff_sockets and self.continue_sniff:
                if timeout is not None:
                    remain = stoptime - time.time()
                    if remain <= 0:
                        break
                sockets, read_func = select_func(sniff_sockets, remain)
                read_func = read_func or _backup_read_func
                dead_sockets = []
                for s in sockets:
                    if s is close_pipe:
                        break
                    try:
                        p = read_func(s)
                    except EOFError:
                        # End of stream
                        try:
                            s.close()
                        except Exception:
                            pass
                        dead_sockets.append(s)
                        continue
                    except Exception as ex:
                        msg = " It was closed."
                        try:
                            # Make sure it's closed
                            s.close()
                        except Exception as ex:
                            msg = " close() failed with '%s'" % ex
                        warning(
                            "Socket %s failed with '%s'." % (s, ex) + msg
                        )
                        dead_sockets.append(s)
                        if conf.debug_dissector >= 2:
                            raise
                        continue
                    if p is None:
                        continue
                    if lfilter and not lfilter(p):
                        continue
                    p.sniffed_on = sniff_sockets[s]
                    # on_packet_received handles the prn/storage
                    session.on_packet_received(p)
                    # check
                    #print("stop_filter and stop_filter(p) is ",stop_filter and stop_filter(p))
                    if (stop_filter and stop_filter(p)) or \
                            (0 < count <= session.count):
                        self.continue_sniff = False
                        break
                # Removed dead sockets
                for s in dead_sockets:
                    del sniff_sockets[s]
        except KeyboardInterrupt:
            pass
        self.running = False
        if opened_socket is None:
            for s in sniff_sockets:
                s.close()
        elif close_pipe:
            close_pipe.close()
        self.results = session.toPacketList()

    def start(self):
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        self.thread.start()

    def stop(self, join=True):
        """Stops AsyncSniffer if not in async mode"""
        if self.running:
            try:
                self.stop_cb()
            except AttributeError:
                raise Scapy_Exception(
                    "Unsupported (offline or unsupported socket)"
                )
            if join:
                self.join()
                return self.results
        else:
            raise Scapy_Exception("Not started !")

    def join(self, *args, **kwargs):
        if self.thread:
            self.thread.join(*args, **kwargs)


@conf.commands.register
def sniff(*args, **kwargs):
    sniffer = AsyncSniffer()
    sniffer._run(*args, **kwargs)
    return sniffer.results


sniff.__doc__ = AsyncSniffer.__doc__

