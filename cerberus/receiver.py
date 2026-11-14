"""Syslog listeners: UDP, and TCP with both RFC 6587 framings."""
from __future__ import annotations

import asyncio
import logging
import socket

from .syslog_parser import MAX_MESSAGE

log = logging.getLogger("cerberus.receiver")



def _peer_ip(addr) -> str:
    ip = addr[0] if addr else "unknown"
    return ip[7:] if ip.startswith("::ffff:") else ip


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, submit):
        self.submit = submit

    def datagram_received(self, data: bytes, addr) -> None:
        if data:
            self.submit(data, _peer_ip(addr))

    def error_received(self, exc) -> None:  # ICMP errors etc. are not our problem
        pass


class SyslogReceiver:
    def __init__(self, submit, bind: str, udp_port: int, tcp_port: int, max_tcp_clients: int = 1000):
        self.submit = submit
        self.max_tcp_clients = max_tcp_clients
        self.refused = 0  # TCP connections turned away at the limit
        self.bind = bind
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self._udp = None
        self._tcp = None
        self._clients = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.udp_port:
            self._udp, _ = await loop.create_datagram_endpoint(
                lambda: _UDP(self.submit), local_addr=(self.bind, self.udp_port)
            )
            sock = self._udp.get_extra_info("socket")
            try:  # a bigger buffer rides out bursts; the OS may cap it
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            log.info("syslog UDP listening on %s:%d", self.bind, self.udp_port)
        if self.tcp_port:
            self._tcp = await asyncio.start_server(self._client, self.bind, self.tcp_port, limit=MAX_MESSAGE * 2)
            log.info("syslog TCP listening on %s:%d", self.bind, self.tcp_port)

    async def stop(self) -> None:
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = _peer_ip(writer.get_extra_info("peername"))
        if self._clients >= self.max_tcp_clients:
            self.refused += 1
            if self.refused == 1 or self.refused % 1000 == 0:
                log.warning("refused a syslog TCP connection from %s: %d already open "
                            "(raise CERBERUS_MAX_TCP_CLIENTS)", ip, self._clients)
            writer.close()
            return
        self._clients += 1
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:  # so connections from devices that vanished are eventually noticed and freed
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
        try:
            while True:
                head = await reader.read(1)
                if not head:
                    break
                if head.isdigit():
                    # Octet counting: "<length> <message>"
                    digits = head
                    while len(digits) < 6:
                        ch = await reader.readexactly(1)
                        if ch == b" ":
                            break
                        digits += ch
                    if not digits.isdigit() or not 0 < int(digits) <= MAX_MESSAGE:
                        break  # not a framing we understand; drop the connection
                    self.submit(await reader.readexactly(int(digits)), ip)
                else:
                    # Non-transparent framing: one message per line.
                    try:
                        line = head + await reader.readuntil(b"\n")
                    except asyncio.LimitOverrunError:
                        break
                    if line.strip():
                        self.submit(line, ip)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            self._clients -= 1
            writer.close()
