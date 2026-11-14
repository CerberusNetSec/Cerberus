"""Syslog listeners: UDP; TCP with both RFC 6587 framings; TLS (RFC 5425).

TCP and TLS connections from addresses listed in CERBERUS_PROXY_PROTOCOL_FROM
must begin with a PROXY protocol header (v1 or v2), sent by a load balancer
such as HAProxy; the device's own address is taken from it. From anywhere
else the header is not trusted, because any sender could claim any address.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
import struct

from .syslog_parser import MAX_MESSAGE

log = logging.getLogger("cerberus.receiver")

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


class ProxyHeaderError(ValueError):
    pass


def _peer_ip(addr) -> str:
    ip = addr[0] if addr else "unknown"
    return ip[7:] if ip.startswith("::ffff:") else ip


async def read_proxy_header(reader: asyncio.StreamReader) -> str | None:
    """Read a PROXY protocol v1 or v2 header. Returns the original source address,
    or None for a connection the proxy made itself (v2 LOCAL, v1 UNKNOWN: health checks)."""
    first = await reader.readexactly(5)
    if first == b"PROXY":  # v1: "PROXY TCP4 src dst sport dport\r\n", at most 107 bytes
        line = first + await reader.readuntil(b"\r\n")
        if len(line) > 107:
            raise ProxyHeaderError("v1 header too long")
        parts = line[:-2].decode("ascii", "replace").split(" ")
        if parts[1:2] == ["UNKNOWN"]:
            return None
        if len(parts) != 6 or parts[1] not in ("TCP4", "TCP6"):
            raise ProxyHeaderError("malformed v1 header")
        return str(ipaddress.ip_address(parts[2]))
    rest = await reader.readexactly(len(V2_SIGNATURE) - 5)
    if first + rest != V2_SIGNATURE:
        raise ProxyHeaderError("no PROXY header")
    version_command, family, length = struct.unpack("!BBH", await reader.readexactly(4))
    body = await reader.readexactly(length)
    if version_command >> 4 != 2:
        raise ProxyHeaderError("unsupported PROXY version")
    if version_command & 0x0F == 0:  # LOCAL
        return None
    if family >> 4 == 1 and length >= 12:  # AF_INET
        return str(ipaddress.IPv4Address(body[:4]))
    if family >> 4 == 2 and length >= 36:  # AF_INET6
        return _peer_ip((str(ipaddress.IPv6Address(body[:16])),))
    raise ProxyHeaderError("unsupported PROXY address family")


def tls_context(cert: str, key: str, client_ca: str = "") -> ssl.SSLContext:
    """Server context for syslog over TLS; with client_ca, devices must present a
    certificate it signed (mutual TLS)."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    if client_ca:
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, submit):
        self.submit = submit

    def datagram_received(self, data: bytes, addr) -> None:
        if data:
            self.submit(data, _peer_ip(addr))

    def error_received(self, exc) -> None:  # ICMP errors etc. are not our problem
        pass


class SyslogReceiver:
    def __init__(self, submit, bind: str, udp_port: int, tcp_port: int, max_tcp_clients: int = 1000,
                 tls_port: int = 0, tls: ssl.SSLContext | None = None, proxy_from: list | tuple = ()):
        self.submit = submit
        self.max_tcp_clients = max_tcp_clients
        self.refused = 0  # TCP connections turned away at the limit
        self.bad_proxy = 0  # connections from a trusted proxy without a valid header
        self.bind = bind
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.tls_port = tls_port
        self.tls = tls
        self.proxy_from = [ipaddress.ip_network(n, strict=False) for n in proxy_from]
        self._servers: list = []
        self._clients = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.udp_port:
            udp, _ = await loop.create_datagram_endpoint(
                lambda: _UDP(self.submit), local_addr=(self.bind, self.udp_port)
            )
            self._servers.append(udp)
            sock = udp.get_extra_info("socket")
            try:  # a bigger buffer rides out bursts; the OS may cap it
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            log.info("syslog UDP listening on %s:%d", self.bind, self.udp_port)
        if self.tcp_port:
            self._servers.append(await asyncio.start_server(self._client, self.bind, self.tcp_port,
                                                            limit=MAX_MESSAGE * 2))
            log.info("syslog TCP listening on %s:%d", self.bind, self.tcp_port)
        if self.tls_port and self.tls:
            self._servers.append(await asyncio.start_server(self._client, self.bind, self.tls_port,
                                                            limit=MAX_MESSAGE * 2, ssl=self.tls,
                                                            ssl_handshake_timeout=15))
            log.info("syslog TLS listening on %s:%d%s", self.bind, self.tls_port,
                     " (client certificates required)" if self.tls.verify_mode == ssl.CERT_REQUIRED else "")
        if self.proxy_from:
            log.info("PROXY protocol expected from %s", ", ".join(map(str, self.proxy_from)))

    async def stop(self) -> None:
        for server in self._servers:
            server.close()

    def _trusted_proxy(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.proxy_from)

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
            if self.proxy_from and self._trusted_proxy(ip):
                try:
                    original = await asyncio.wait_for(read_proxy_header(reader), 10)
                except (ProxyHeaderError, ValueError, asyncio.TimeoutError, asyncio.LimitOverrunError):
                    self.bad_proxy += 1
                    if self.bad_proxy == 1 or self.bad_proxy % 1000 == 0:
                        log.warning("connection from proxy %s without a valid PROXY header; closed", ip)
                    return
                if original is None:
                    return  # the proxy's own health check
                ip = original
            while True:
                head = await reader.read(1)
                if not head:
                    break
                if head.isdigit():
                    # Octet counting: "<length> <message>" (the only framing RFC 5425 allows)
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
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            self._clients -= 1
            writer.close()
