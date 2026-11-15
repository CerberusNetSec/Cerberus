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


def _bind_error(exc: OSError, port: int) -> str:
    import errno
    if exc.errno in (errno.EADDRINUSE, 10048):
        return f"port {port} is already in use"
    if exc.errno in (errno.EACCES, 10013):
        return f"not permitted to listen on port {port}"
    return str(exc.strerror or exc)


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
        self._servers: dict[str, object] = {}  # "udp", "tcp", "tls" -> its open listener
        self.errors: dict[str, str] = {}  # the last failure to open each listener
        self._clients = 0

    def port(self, kind: str) -> int:
        return {"udp": self.udp_port, "tcp": self.tcp_port, "tls": self.tls_port}[kind]

    async def _open(self, kind: str, port: int):
        if kind == "udp":
            udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _UDP(self.submit), local_addr=(self.bind, port))
            sock = udp.get_extra_info("socket")
            try:  # a bigger buffer rides out bursts; the OS may cap it
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            log.info("syslog UDP listening on %s:%d", self.bind, port)
            return udp
        if kind == "tcp":
            server = await asyncio.start_server(self._client, self.bind, port, limit=MAX_MESSAGE * 2)
            log.info("syslog TCP listening on %s:%d", self.bind, port)
            return server
        server = await asyncio.start_server(self._client, self.bind, port, limit=MAX_MESSAGE * 2, ssl=self.tls,
                                            ssl_handshake_timeout=15)
        log.info("syslog TLS listening on %s:%d%s", self.bind, port,
                 " (client certificates required)" if self.tls.verify_mode == ssl.CERT_REQUIRED else "")
        return server

    async def start(self) -> None:
        """Open the listeners that have a port. One that cannot open (port in use, not
        permitted) is logged and reported by status(); the others still run."""
        for kind in ("udp", "tcp", "tls"):
            port = self.port(kind)
            if not port or (kind == "tls" and not self.tls):
                continue
            try:
                self._servers[kind] = await self._open(kind, port)
                self.errors.pop(kind, None)
            except OSError as exc:
                self.errors[kind] = _bind_error(exc, port)
                log.error("syslog %s listener on port %d could not start: %s", kind.upper(), port, self.errors[kind])
        if self.proxy_from:
            log.info("PROXY protocol expected from %s", ", ".join(map(str, self.proxy_from)))

    async def reconfigure(self, wanted: dict[str, int]) -> dict[str, str]:
        """Change listeners while running: {kind: port, or 0 for off}. A new port is opened
        before the old one closes, so a port that cannot be opened leaves the listener as it
        was. Returns {kind: error} for those that could not change. Connections already open
        on a closed listener carry on until the device disconnects."""
        failed: dict[str, str] = {}
        for kind, port in wanted.items():
            if kind not in ("udp", "tcp", "tls"):
                continue
            current = self._servers.get(kind)
            if port == self.port(kind) and (current is not None or not port):
                continue
            if port and kind == "tls" and not self.tls:
                failed[kind] = "no certificate configured (CERBERUS_SYSLOG_TLS_CERT and _KEY)"
                continue
            if port:
                try:
                    opened = await self._open(kind, port)
                except OSError as exc:
                    failed[kind] = _bind_error(exc, port)
                    continue
            else:
                opened = None
            if current is not None:
                current.close()
                log.info("syslog %s listener on port %d closed", kind.upper(), self.port(kind))
            if opened is None:
                self._servers.pop(kind, None)
            else:
                self._servers[kind] = opened
            setattr(self, f"{kind}_port", port)
            self.errors.pop(kind, None)
        return failed

    def status(self) -> dict[str, dict]:
        return {kind: {"port": self.port(kind), "listening": kind in self._servers, "error": self.errors.get(kind, "")}
                for kind in ("udp", "tcp", "tls")}

    async def stop(self) -> None:
        for server in self._servers.values():
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
