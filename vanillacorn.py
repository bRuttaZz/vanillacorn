#!/usr/bin/env python

# Copyright (C) 2025 Agraj P Das (@bRuttaZz)
#
# This file is part of Vanillacorn
#
# Vanillacorn is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# Vanillacorn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


__version__ = "0.1.0"

import argparse
import asyncio
import importlib
import logging
import multiprocessing
import os
import socket
import ssl
import struct
import sys
from base64 import b64encode
from enum import Enum
from hashlib import sha1
from itertools import chain
from sys import exit, stdout
from time import time
from typing import Callable, Coroutine, Iterable, Literal, Tuple, TypedDict, Union
from urllib.parse import unquote

_logger = logging.getLogger("pycorn")

ASGI_VERSION = (
    "2.5"  # https://asgi.readthedocs.io/en/latest/specs/www.html#spec-versions
)
SERVER_NAME = "vanillacorn"


class LifeSpan(Enum):
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    IDLE = "idle"
    READY = "ready"


class WSOpcode(Enum):
    # https://datatracker.ietf.org/doc/html/rfc6455#section-5.5
    CONTINUE = 0x0
    TXT = 0x1
    BYTES = 0x2

    # control codes
    PING = 0x9
    PONG = 0xA
    CLOSE = 0x8


class ASGIScopeType(str, Enum):
    LIFESPAN = "lifespan"
    HTTP = "http"
    WEBSOCKET = "websocket"


class StatusMessages(Enum):
    status_100 = "Continue"
    status_101 = "Switching Protocols"
    status_200 = "OK"
    status_201 = "Created"
    status_202 = "Accepted"
    status_204 = "No Content"
    status_301 = "Moved Permanently"
    status_302 = "Found"
    status_304 = "Not Modified"
    status_400 = "Bad Request"
    status_401 = "Unauthorized"
    status_403 = "Forbidden"
    status_404 = "Not Found"
    status_405 = "Method Not Allowed"
    status_429 = "Too Many Requests"
    status_500 = "Internal Server Error"
    status_501 = "Not Implemented"
    status_502 = "Bad Gateway"
    status_503 = "Service Unavailable"
    status_504 = "Gateway Timeout"
    default = "Unavailable"


class WSStatusMessages(Enum):
    # docs: https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1
    status_1000 = "Normal closure"
    status_1001 = "Going away"
    status_1002 = "Protocol error"
    status_1003 = "Data not acceptable"
    status_1007 = "Inconsitant data"
    status_1008 = "Policy violation"
    status_1009 = "Entity too large"
    status_1010 = "Extension negotiation error"
    status_1011 = "Unexpected error"


class ASGISendArg(TypedDict, total=False):
    type: str
    status: int
    headers: Iterable[Tuple[bytes, bytes]]
    trailers: bool
    body: bytes
    more_body: bool


class WSASGISendArg(TypedDict, total=False):
    type: str
    subprotocol: str
    headers: Iterable[Tuple[bytes, bytes]]
    text: str
    bytes: bytes
    code: int
    reason: str


class WSASGIMsg(TypedDict, total=False):
    type: Literal[
        "websocket.receive",
        "websocket.send",
        "websocket.connect",
        "websocket.disconnect",
    ]
    bytes: Union[bytes, None]
    text: Union[str, None]
    code: int
    reason: Union[str, None]


class ASGIScopeBase(TypedDict):
    type: Union[ASGIScopeType, None]
    asgi: dict
    state: Union[dict, None]


class ASGIScope(ASGIScopeBase):
    http_version: Union[Literal["1.0", "1.1", "2"], None]
    method: str
    scheme: Union[Literal["http", "https", "ws", "wss"], None]
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: Union[Iterable[Tuple[bytes, bytes]], None]
    client: Union[Tuple[str, int], None]
    server: Union[Tuple, None]
    subprotocols: Union[Iterable[str], None]


HTTP_VERSIONS = ("1.0", "1.1", "2")

HTTP_HEADER_ENCODING = "iso-8859-1"
WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

WS_MAX_PAYLOAD_SIZE_PER_FRAME = 2**16 - 1  # 64kb
WS_MAX_LAST_ACTIVE_TIME = 60  # seconds
WS_MAX_PING_RESPONSE_TIME = 10  # seconds
WS_PING_INTERVEL = 30  # seconds

# TODO: implement limits
# TODO: implement http timeout
WS_MAX_READ_LIMIT_FRAME = 5 * 100 * 100  # 1mb
WS_MAX_READ_LIMIT_MESSAGE = 10 * WS_MAX_READ_LIMIT_FRAME
WS_MAX_READ_LIMIT_MESSAGE_BUFFER = 10 * WS_MAX_READ_LIMIT_MESSAGE

READ_MAX_BYTES = 2**16  # 64kb
DEFAULT_SCOPE_PARAMS = {
    "asgi": {
        "version": ASGI_VERSION,
        "spec_version": ASGI_VERSION,
    }
}
DEFAULT_RESPONSE_HEADERS = [(b"Server", SERVER_NAME.encode(HTTP_HEADER_ENCODING))]

CUSTOM_WS_STATUS_CODES = [  # range of customisable range of ws status codes
    (3000, 3999),
    (4000, 4999),
]


# Exceptions
class _OSError(OSError):
    """Vaillacorn Custom OSError"""


class SockObj:
    def __init__(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader):
        self.writer = writer
        self.reader = reader

        self.scope: ASGIScope = {
            "type": None,
            "asgi": {
                **DEFAULT_SCOPE_PARAMS["asgi"],
            },
            "http_version": None,
            "method": "",
            "scheme": None,
            "path": "",
            "raw_path": b"",
            "query_string": b"",
            "root_path": "",
            "headers": None,
            "client": None,
            "server": None,
            "subprotocols": None,
            "state": None,
        }

        self.content_length: Union[int, None] = None
        self.chunked_encoding: bool = False
        self.req_addr: str = ""
        self.http_version_str: str = ""
        self.sec_webSocket_key: str = ""
        self.sec_webSocket_version: int = 0
        self.header_upgrade: str = ""
        self.header_connection: str = ""

        # ws specific
        self.recv_queue = asyncio.Queue()
        self.sock_connected: bool = False
        self.listen_task: Union[asyncio.Task, None] = None
        self._closing_reason: Union[str, None] = None
        self._closing_code: Union[int, None] = None
        self._last_active: float = 0
        self._last_ping_send: float = 0
        self._last_pong: float = 0
        self._client_closeframe: bool = False
        self._server_closeframe: bool = False


class Server:
    _asgi_version = ASGI_VERSION

    def __init__(
        self,
        app: Union[
            Callable[[Union[ASGIScopeBase, ASGIScope], Callable, Callable], Coroutine],
            str,
        ],
        port: int = 8075,
        host: str = "localhost",
        ssl_key: str = "",
        ssl_cert: str = "",
        ssl_context: Union[ssl.SSLContext, None] = None,
    ):
        self.id: Union[int, None] = None
        self.host: str = host
        self.port: int = port

        if isinstance(app, str):
            self.app = self.load_app(app)
        else:
            self.app = app

        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.ssl_context: Union[ssl.SSLContext, None] = ssl_context
        self.tls_enabled = True if ssl_context or (ssl_key and ssl_cert) else False

        self.life_span: LifeSpan = LifeSpan.IDLE
        self.life_span_state = dict()
        self._addr = (None, None)

    @classmethod
    def load_app(cls, ref_path: str) -> Callable:
        _module, _callable = "", ""
        try:
            if ":" in ref_path:
                _module, _callable = ref_path.split(":")
            elif "." in ref_path:
                path_mods = ref_path.split(".")
                if len(path_mods) < 2:
                    raise ValueError()
                _module = ".".join(path_mods[:-1])
                _callable = path_mods[-1]
            else:
                raise ValueError()
        except:
            raise ValueError(f"Invalid ASGI app identifier: {ref_path}")
        try:
            sys.path.append(os.getcwd())
            module = importlib.import_module(_module)
        except:
            raise ImportError(f"Error importing module: {_module}")
        try:
            app = getattr(module, _callable)
        except:
            raise ImportError(
                f"Attribute '{_callable}' not found in module '{_module}'"
            )
        if not callable(app):
            raise ValueError(f"ASGI app is not callable: {ref_path}")
        return app

    @classmethod
    def load_ssl(cls, ssl_key: str, ssl_cert: str) -> ssl.SSLContext:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
        return ssl_context

    def run(self, id: int = 0):
        """Start server on an eventloop"""
        self.id = id
        asyncio.run(self.start_server())

    # lifespan specs
    async def lifespan_recv(self):
        await asyncio.sleep(0)
        return {"type": f"lifespan.{self.life_span.value}"}

    async def lifespan_send(self, msg, **kwargs):
        await asyncio.sleep(0)
        msg_type = msg.get("type")
        if msg_type == f"lifespan.{self.life_span.value}.complete":
            self.life_span = LifeSpan.READY
        elif msg_type == f"lifespan.{self.life_span.value}.failed":
            _logger.warning(
                f"[lifespan] Error in app {self.life_span.value}: {msg.get('message', '')}"
            )
            return exit(1)
        else:
            _logger.error(
                f"[lifespan] Protocol error, server at type:'${self.life_span.value}' state. Got type:'{msg['type']}'!"
            )
            return exit(1)

    async def wait_ready_state(self):
        while True:
            await asyncio.sleep(0)
            if self.life_span == LifeSpan.READY:
                return

    async def start_server(self):
        """Start server"""
        _kwargs = {
            "host": self.host,
            "port": self.port,
            "family": socket.AF_UNSPEC,
            "reuse_address": True,
            "reuse_port": True,
        }
        if self.tls_enabled:
            if not self.ssl_context:
                self.ssl_context = self.load_ssl(self.ssl_key, self.ssl_cert)
            _kwargs["ssl"] = self.ssl_context

        server = await asyncio.start_server(self.handle_cli, **_kwargs)
        _logger.info(f"Started server process [{self.id}]")

        self._addr = server.sockets[0].getsockname()[:2]
        async with server:
            self.life_span = LifeSpan.STARTUP
            # lifespan
            _logger.info("Waiting for application startup.")
            asyncio.create_task(
                self.app(
                    ASGIScopeBase(
                        type=ASGIScopeType.LIFESPAN,
                        asgi={
                            **DEFAULT_SCOPE_PARAMS["asgi"],
                        },
                        state=self.life_span_state,
                    ),
                    self.lifespan_recv,
                    self.lifespan_send,
                )
            )
            await self.wait_ready_state()
            _logger.info("Application startup completed.")

            try:
                _logger.info(
                    f"{SERVER_NAME.title()} listening on "
                    f"http{'s' if self.tls_enabled else ''}://{self._addr[0]}:{self._addr[1]} "
                    "(Press CTRL+C to quit)"
                )
                await server.serve_forever()
            except BaseException as exp:
                self.life_span = LifeSpan.SHUTDOWN
                _logger.error(f"Interrupt received! Shutting down: {exp}")
                _logger.info("Waiting for application shutdown.")
                await self.wait_ready_state()
                _logger.info("Application shutdown complete.")
                _logger.info(f"Finished server process [{self.id}]")

    # parsers
    async def _parse_header_line(self, sock_obj: SockObj):
        # as of now not respecting any pseudo headers
        header_line = await sock_obj.reader.readline()
        header_line = header_line.decode(HTTP_HEADER_ENCODING).strip().rstrip("\r")
        header_line_comps = header_line.split(" ")
        if len(header_line_comps) != 3:
            _logger.debug("Invalid request headerline!")
            return
        http_version = header_line_comps[2].split("/")[-1]
        if http_version not in HTTP_VERSIONS:
            _logger.debug("Invalid http protocol!")
            return
        sock_obj.http_version_str = header_line_comps[2].upper()
        sock_obj.scope["method"] = header_line_comps[0].upper()
        sock_obj.scope["http_version"] = http_version
        sock_obj.scope["path"] = header_line_comps[1]
        return True

    async def _parse_headers(self, sock_obj: SockObj):
        _headers = []
        while True:
            line = await sock_obj.reader.readline()
            line = line.decode(HTTP_HEADER_ENCODING).strip().rstrip("\r")
            if not line:
                break
            h_key, *h_val = line.split(": ")
            h_val = ": ".join(h_val).lstrip()
            if h_key.startswith(":"):
                if h_key == ":authority":
                    _headers.insert(0, (b"host", h_val.encode("utf-8")))
                continue  # ignore all pseudo headers as per spec : https://asgi.readthedocs.io/en/latest/specs/www.html
            _headers.append((h_key.lower().encode("utf-8"), h_val.encode("utf-8")))
        sock_obj.scope["headers"] = tuple(_headers)
        return True

    def _parse_pathname(self, sock_obj: SockObj):
        org_path = sock_obj.scope["path"]
        path, *query = org_path.split("?")
        query = "?".join(query)

        sock_obj.scope["path"] = unquote(path)
        sock_obj.scope["query_string"] = query.encode("utf-8")
        sock_obj.scope["raw_path"] = path.encode("utf-8")
        sock_obj.scope["root_path"] = ""

    def _parse_info(self, sock_obj: SockObj):
        sock_obj.scope["type"] = ASGIScopeType.HTTP
        sock_obj.scope["scheme"] = "https" if self.tls_enabled else "http"

        if not sock_obj.scope["headers"]:
            raise RuntimeError("headers appear as None in _parse_info")
        refined_headers = []
        for key, val in sock_obj.scope["headers"]:
            if key == b"upgrade":
                _val = val.decode("utf-8").lower()
                if _val == "websocket":
                    sock_obj.scope["type"] = ASGIScopeType.WEBSOCKET
                    sock_obj.scope["scheme"] = "wss" if self.tls_enabled else "ws"
                sock_obj.header_upgrade = _val
            elif key == b"connection":
                sock_obj.header_connection = val.decode("utf-8").lower()
            elif key == b"sec-websocket-version":
                sock_obj.sec_webSocket_version = int(val)
            elif key == b"sec-websocket-key":
                sock_obj.sec_webSocket_key = val.decode("utf-8")
            elif key == b"sec-websocket-protocol":
                sock_obj.scope["subprotocols"] = [
                    proto.strip() for proto in val.decode("utf-8").split(",")
                ]
                refined_headers.append((b"subprotocol", val))
                continue
            elif key == b"content-length":
                sock_obj.content_length = int(val)
            elif key == b"transfer-encoding" and val == b"chunked":
                sock_obj.chunked_encoding = True
            refined_headers.append((key, val))
        sock_obj.scope["headers"] = refined_headers

    async def _parse_scope(self, sock_obj: SockObj):
        if not await self._parse_header_line(sock_obj):
            raise ValueError("parserError in headerline")
        if not await self._parse_headers(sock_obj):
            raise ValueError("parserError in headerline")
        self._parse_pathname(sock_obj)
        self._parse_info(sock_obj)
        sock_obj.scope["server"] = self._addr
        sock_obj.scope["state"] = self.life_span_state

    def _write_response_header(
        self,
        sock_obj: SockObj,
        status: int,
        headers: Iterable[Tuple[bytes, bytes]],
        content_len: Union[int, None] = None,
    ) -> bool:
        _found_content_len = False
        msg = StatusMessages.default
        if f"status_{status}" in StatusMessages.__members__:
            msg = StatusMessages[f"status_{status}"]

        sock_obj.writer.write(
            (f"{sock_obj.http_version_str} {status} {msg.value}\r\n").encode(
                HTTP_HEADER_ENCODING
            )
        )

        for key, val in headers:
            if key.decode("utf-8").lower() == "content-length":
                _found_content_len = True
            sock_obj.writer.write(key + b": " + val + b"\r\n")

        if not _found_content_len and content_len is not None:
            sock_obj.writer.write(
                f"Content-Length: {content_len}\r\n".encode(HTTP_HEADER_ENCODING)
            )
        _logger.info(
            f"{sock_obj.req_addr} - "
            f"\"{sock_obj.scope['method'].upper()} {sock_obj.scope['path']} {sock_obj.http_version_str}\" "
            f"- {status} {msg.value}"
        )
        return _found_content_len

    # http specs
    def compose_http_recv(self, sock_obj: SockObj):
        remaining: bool = True
        remaining_len: int = 0
        fixed_content: bool = False
        if sock_obj.content_length is not None:
            remaining_len = sock_obj.content_length
            fixed_content = True

        async def http_recv(*args, **kwargs):
            nonlocal remaining, remaining_len
            payload = b""

            try:
                if not remaining:
                    pass

                elif sock_obj.chunked_encoding:  # read type: transfer-encoding: chunked
                    size_line = await sock_obj.reader.readline()
                    if not size_line:
                        remaining = False
                    chunk_size = int(size_line.strip(), 16)
                    if not chunk_size:
                        await sock_obj.reader.readline()  # for trailing CRLF
                        remaining = False
                    payload = await sock_obj.reader.readexactly(chunk_size)
                    await sock_obj.reader.readline()  # again for trailing CRLF

                elif fixed_content:  # read fixed fixed_content
                    _len = (
                        READ_MAX_BYTES
                        if remaining_len > READ_MAX_BYTES
                        else remaining_len
                    )
                    payload = await sock_obj.reader.read(_len)
                    remaining_len -= _len
                    if not remaining_len:
                        remaining = False

                else:  # read all till null
                    payload = await sock_obj.reader.read(READ_MAX_BYTES)
                    if not payload:
                        remaining = False
            except Exception as exp:
                _logger.debug(f"Error reading from server: {exp}")
                _logger.warning("Error reading from server.")
                raise _OSError("Client Error: Error reading from server!")

            return {
                "type": "http.request",
                "body": payload,
                "more_body": remaining,
            }

        return http_recv

    def compose_http_send(self, sock_obj: SockObj):
        _headers = [*DEFAULT_RESPONSE_HEADERS]
        _status = 200
        _trailers = False
        _body = bytearray()
        _header_send = False
        _chunked_encoding = False

        async def http_send(msg: ASGISendArg):
            if sock_obj.writer.is_closing():
                raise _OSError(
                    "[pycorn] Attempt to write on a closed client-connection!"
                )

            nonlocal _headers, _status, _trailers, _body, _header_send, _chunked_encoding
            type = msg.get("type")
            status = msg.get("status", 200)
            headers = msg.get("headers", [])
            trailers = msg.get("trailers", False)
            body = msg.get("body", b"")
            more_body = msg.get("more_body", False)

            # TODO test cases for all
            if type == "http.response.start":
                _headers = chain(_headers, headers)
                _status = status
                _trailers = trailers

            elif type == "http.response.body":
                if _trailers:
                    _body.extend(body)
                    return
                if not _header_send:
                    if not self._write_response_header(sock_obj, _status, _headers):
                        if not more_body:
                            sock_obj.writer.write(
                                f"Content-Length: {len(body)}\r\n".encode(
                                    HTTP_HEADER_ENCODING
                                )
                            )
                        else:
                            _chunked_encoding = True
                            sock_obj.writer.write(
                                "Transfer-Encoding: chunked\r\n".encode(
                                    HTTP_HEADER_ENCODING
                                )
                            )
                    sock_obj.writer.write(b"\r\n")
                    _header_send = True
                if _chunked_encoding:
                    size_line = f"{len(body):X}\r\n".encode(
                        HTTP_HEADER_ENCODING
                    )  # size in hex
                    sock_obj.writer.write(size_line)
                    sock_obj.writer.write(body + b"\r\n")
                else:
                    sock_obj.writer.write(body)
                await sock_obj.writer.drain()
                if not more_body:
                    sock_obj.writer.close()
                    await sock_obj.writer.wait_closed()

            elif type == "http.response.trailers":
                _body.extend(body)
                t_body = bytes(_body)
                self._write_response_header(sock_obj, _status, _headers, len(t_body))
                sock_obj.writer.write(b"\r\n")
                sock_obj.writer.write(t_body)
                await sock_obj.writer.drain()
                sock_obj.writer.close()
                await sock_obj.writer.wait_closed()

            else:
                raise NotImplementedError(
                    f"ASGI send msg.type '{type}' is Not implemented! ASGI version :{self._asgi_version}"
                )

        return http_send

    async def write_errors(self, sock_obj: SockObj, status: int, message: str = ""):
        if sock_obj.writer.is_closing():
            raise _OSError("[pycorn] Attempt to write on a closed client-connection!")

        if not message:
            if f"status_{status}" in StatusMessages.__members__:
                message = StatusMessages[f"status_{status}"].value
            else:
                message = StatusMessages.default.value
        msg = message.encode("utf-8")

        self._write_response_header(
            sock_obj,
            status,
            [
                *DEFAULT_RESPONSE_HEADERS,
                (b"Content-Type", b"text/plain"),
            ],
            content_len=len(msg),
        )
        sock_obj.writer.write(b"\r\n")
        sock_obj.writer.write(msg)
        await sock_obj.writer.drain()
        sock_obj.writer.close()
        await sock_obj.writer.wait_closed()

    # ws specs
    async def _validate_ws_req(self, sock_obj: SockObj) -> bool:
        """Validate ws connection req"""
        if (
            not sock_obj.sec_webSocket_key
            or not sock_obj.sec_webSocket_version
            or sock_obj.header_connection != "upgrade"
            or sock_obj.header_upgrade != "websocket"
        ):
            await self.write_errors(sock_obj, 400, "Bad Request")
            return False
        return True

    async def _upgrade_ws_conn(
        self,
        sock_obj: SockObj,
        headers: Iterable[Tuple[bytes, bytes]],
    ):
        accept_key = b64encode(
            sha1((sock_obj.sec_webSocket_key + WS_MAGIC_STRING).encode()).digest()
        )
        self._write_response_header(
            sock_obj,
            101,
            [
                *DEFAULT_RESPONSE_HEADERS,
                (b"Upgrade", b"websocket"),
                (b"Connection", b"Upgrade"),
                (b"Sec-WebSocket-Accept", accept_key),
            ],
        )
        for key, val in headers:
            if key == b"subprotocol":
                continue
            if key.decode("utf-8").lower() not in [
                "upgrade",
                "connection",
                "sec-websocket-accept",
                "sec-websocket-protocol",
            ]:
                sock_obj.writer.write(key + b": " + val + b"\r\n")
        sock_obj.writer.write(b"\r\n")
        await sock_obj.writer.drain()

    async def _read_ws_frame(
        self, reader: asyncio.StreamReader
    ) -> Tuple[int, WSOpcode, bytes]:
        """
        WS framing.
        Spec : https://www.rfc-editor.org/rfc/rfc6455 .
        Human readable docs : https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers

        parse a frame from the socket and return , FIN, OPCODE and unmasked-payload from the frame
        """
        byte1 = ord(await reader.readexactly(1))
        byte2 = ord(await reader.readexactly(1))

        fin = (byte1 >> 7) & 1

        # ignoring the ws extension handling | Bit 1–3 RSV1, RSV2, RSV3

        try:
            opcode = WSOpcode(byte1 & 0x0F)
        except:
            raise ValueError("Invalid opcode received from frame!")

        masked = (byte2 >> 7) & 1  # bit 8 (masked)
        if (
            not masked
        ):  # according to RFC 6455 section 5.1, reject with status code 1002 for umasked client frames
            # spec: https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1
            raise ValueError("Not masked client frame in ws. Should raise 1002")

        # calc length
        length = byte2 & 0x7F  # bit 9-15
        if length == 126:
            length = struct.unpack("!H", await reader.readexactly(2))[
                0
            ]  # unsigned short (2 bytes)
        elif length == 127:
            length = struct.unpack("!Q", await reader.readexactly(8))[
                0
            ]  # unsigned long long (8 bytes)

        mask = await reader.readexactly(4)  # mask key
        _data = await reader.readexactly(length)
        unmasked = bytes(b ^ mask[i % 4] for i, b in enumerate(_data))

        return fin, opcode, unmasked

    async def _read_message_fragment(
        self, reader: asyncio.StreamReader
    ) -> Tuple[WSOpcode, bytes]:
        """Read a message fragment from client"""
        data: bytes = b""
        opcode: Union[WSOpcode, None] = None
        while True:
            _fin, _opcode, _data = await self._read_ws_frame(reader)

            if opcode is None:
                if _opcode == WSOpcode.CONTINUE:
                    raise ValueError("Initial opcode cannot be 0x0 in ws fragmentaion")
                opcode = _opcode
                data = _data
            else:
                if _opcode != WSOpcode.CONTINUE:
                    raise ValueError(
                        "Non 0x0 opcode found in sequent frame in fragment"
                    )
                data += _data

            if _fin:  # fin=1 for last message
                break
        return opcode, data

    async def _write_ws_frame(
        self, fin: int, opcode: WSOpcode, payload: bytes, writer: asyncio.StreamWriter
    ):
        """Write a ws frame to socket"""

        # First byte: FIN + RSV1–3 (0) + OPCODE
        byte1 = (fin << 7) | opcode.value

        length = len(payload)

        # Second byte: MASK = 0 for server-to-client
        if length <= 125:
            header = struct.pack("!BB", byte1, length)  # uc uc
        elif length <= 0xFFFF:  # 16-bit extended payload
            header = struct.pack("!BBH", byte1, 126, length)  # uc uc us
        else:  # 64-bit extended payload
            header = struct.pack("!BBQ", byte1, 127, length)  # uc uc ull

        writer.write(header)
        writer.write(payload)
        await writer.drain()

    async def _write_message_fragment(
        self, opcode: WSOpcode, message: bytes, writer: asyncio.StreamWriter
    ):
        """Write a message as frame(s) to socket"""
        while True:
            msg = b""
            if len(message) > WS_MAX_PAYLOAD_SIZE_PER_FRAME:
                msg = message[:WS_MAX_PAYLOAD_SIZE_PER_FRAME]
                message = message[WS_MAX_PAYLOAD_SIZE_PER_FRAME:]
            else:
                msg = message
                message = b""

            fin = 0 if message else 1
            await self._write_ws_frame(fin, opcode, msg, writer)
            if fin:
                break
            opcode = WSOpcode.CONTINUE

    async def wait_for_ws_grace_closure(self, sock_obj: SockObj, timeout: float = 5):
        _time = time()
        while True:
            await asyncio.sleep(0)
            if sock_obj._client_closeframe or time() - _time > timeout:
                return

    async def write_ws_closeframe(
        self, sock_obj: SockObj, status: int = 1000, reason: str = ""
    ):
        if sock_obj.writer.is_closing():
            raise _OSError("Try calling write_ws_closeframe on closed connection!")
        if (
            sock_obj._server_closeframe
        ):  # if server already sent closeframe close the conn
            sock_obj.writer.close()
            await sock_obj.writer.wait_closed()
            return

        _code = 1000  # fallback according to ASGI spec
        if f"status_{status}" in WSStatusMessages.__members__:
            _code = status
            if not reason:
                reason = WSStatusMessages[f"status_{status}"].value
        elif any(start <= status <= end for start, end in CUSTOM_WS_STATUS_CODES):
            _code = status
        else:
            _logger.warning(f"Not a valid ws code : {status}")

        payload = struct.pack("!H", _code) + reason.encode(  # first two bytes (us)
            "utf-8"
        )
        await self._write_ws_frame(1, WSOpcode.CLOSE, payload, sock_obj.writer)

        sock_obj._server_closeframe = True
        if not sock_obj._client_closeframe:
            await self.wait_for_ws_grace_closure(
                sock_obj, WS_MAX_PING_RESPONSE_TIME / 2
            )
        sock_obj.writer.close()
        return await sock_obj.writer.wait_closed()
        _logger.debug(f"Closed ws connection : /{_code}/{reason}/.")

    async def _process_opcode(
        self, sock_obj: SockObj, opcode: WSOpcode, data: bytes
    ) -> bool:
        if opcode in [WSOpcode.TXT, WSOpcode.BYTES]:
            try:
                await sock_obj.recv_queue.put(
                    WSASGIMsg(
                        type="websocket.receive",
                        text=(data.decode("utf-8") if opcode == WSOpcode.TXT else None),
                        bytes=data if opcode == WSOpcode.BYTES else None,
                    )
                )
            except UnicodeDecodeError:
                await self.write_ws_closeframe(sock_obj, 1002)
                return False

        elif opcode == WSOpcode.CLOSE:
            if len(data) < 2:
                sock_obj._closing_code = 1005  # asgi spec default
            else:
                sock_obj._closing_code = struct.unpack("!H", data[:2])[0]
                try:
                    if data[2:]:
                        sock_obj._closing_reason = data[2:].decode("utf-8")
                except UnicodeDecodeError:
                    sock_obj._closing_reason = "<Invalid UTF-8>"
            _logger.debug(f"Client closed ws connection : {sock_obj._closing_code}")
            sock_obj._client_closeframe = True
            await self.write_ws_closeframe(sock_obj, 1001)
            return False

        elif opcode == WSOpcode.PING:
            await self._write_ws_frame(1, WSOpcode.PONG, data, sock_obj.writer)
            sock_obj._last_pong = time()

        elif opcode == WSOpcode.PONG:
            sock_obj._last_ping_send = 0
            sock_obj._last_pong = time()

        else:
            raise NotImplementedError("Invalid opcode in ws_conn_listener")

        return True

    async def _keep_ws_conn_alive(self, sock_obj: SockObj):
        try:
            while True:
                await asyncio.sleep(5)
                if sock_obj.writer.is_closing():
                    break

                time_now = time()

                # check timeouts
                if time_now - sock_obj._last_active > WS_MAX_LAST_ACTIVE_TIME or (
                    sock_obj._last_ping_send
                    and time_now - sock_obj._last_ping_send > WS_MAX_PING_RESPONSE_TIME
                ):
                    sock_obj._closing_code = 1001
                    sock_obj._closing_reason = "Going Away"
                    await self.write_ws_closeframe(sock_obj, 1001)
                    break

                # send ping
                if time_now - sock_obj._last_pong > WS_PING_INTERVEL:
                    await self._write_ws_frame(
                        1, WSOpcode.PING, b"vanillacorn", sock_obj.writer
                    )
                    sock_obj._last_ping_send = time()
        except asyncio.CancelledError:
            ...

    async def ws_conn_listener(self, sock_obj: SockObj):
        """Responsible for handling control codes"""
        sub_task = asyncio.create_task(self._keep_ws_conn_alive(sock_obj))
        try:
            while True:
                await asyncio.sleep(0)
                if sock_obj.writer.is_closing():
                    break

                try:
                    opcode, data = await self._read_message_fragment(sock_obj.reader)
                    sock_obj._last_active = time()
                except ValueError:
                    await self.write_ws_closeframe(sock_obj, 1002)
                    break

                if not await self._process_opcode(sock_obj, opcode, data):
                    break
        except asyncio.CancelledError:
            ...
        finally:
            try:
                sub_task.cancel()
            except:
                ...

    def compose_ws_recv(self, sock_obj: SockObj):
        def _get_disconnect_info_if():
            if sock_obj.writer.is_closing():
                try:
                    if sock_obj.listen_task:
                        sock_obj.listen_task.cancel()
                except:
                    ...
                return WSASGIMsg(
                    type="websocket.disconnect",
                    code=sock_obj._closing_code or 1005,
                    reason=sock_obj._closing_reason or "",
                )
            return

        async def ws_recv():
            dis_res = _get_disconnect_info_if()
            if dis_res:
                return dis_res

            if not sock_obj.sock_connected:
                return WSASGIMsg(type="websocket.connect", text=None, bytes=None)

            while True:
                dis_res = _get_disconnect_info_if()
                if dis_res:
                    return dis_res
                try:
                    return await asyncio.wait_for(sock_obj.recv_queue.get(), 1)
                except asyncio.TimeoutError:
                    continue

        return ws_recv

    def compose_ws_send(self, sock_obj: SockObj):
        async def ws_send(msg: WSASGISendArg):
            _type = msg.get("type")

            if sock_obj.writer.is_closing():
                try:
                    if sock_obj.listen_task:
                        sock_obj.listen_task.cancel()
                except:
                    ...
                raise _OSError("Socket closed!")

            elif _type == "websocket.accept":
                # ignoring ws subprotocol from msg["subprotocol"]
                await self._upgrade_ws_conn(sock_obj, msg.get("headers", []))
                _now = time()
                sock_obj.sock_connected = True
                sock_obj._last_active = _now
                sock_obj._last_ping_send = 0
                sock_obj._last_pong = _now
                sock_obj.listen_task = asyncio.create_task(
                    self.ws_conn_listener(sock_obj)
                )

            elif _type == "websocket.close" and not sock_obj.sock_connected:
                await self.write_errors(sock_obj, 403)

            elif _type == "websocket.close":
                await self.write_ws_closeframe(
                    sock_obj,
                    status=int(msg.get("code", 1000)),
                    reason=msg.get("reason", ""),
                )

            elif _type == "websocket.send":
                _text = msg.get("text")
                _bytes = msg.get("bytes")

                if _text is not None:
                    await self._write_message_fragment(
                        WSOpcode.TXT, _text.encode("utf-8"), sock_obj.writer
                    )
                elif _bytes is not None:
                    await self._write_message_fragment(
                        WSOpcode.BYTES, _bytes, sock_obj.writer
                    )
                else:
                    await self.write_ws_closeframe(sock_obj, status=1011)
                    raise ValueError(
                        "send type='websocket.send' should contain either 'text' or 'bytes'"
                    )

        return ws_send

    def compose_asgi_callables(self, sock_obj: SockObj) -> Tuple[Callable, Callable]:
        _type = sock_obj.scope["type"]
        if _type == ASGIScopeType.HTTP:
            return self.compose_http_recv(sock_obj), self.compose_http_send(sock_obj)
        if _type == ASGIScopeType.WEBSOCKET:
            return self.compose_ws_recv(sock_obj), self.compose_ws_send(sock_obj)
        else:
            raise NotImplementedError(f"Invalid asgi scope! scope['type']={_type}")

    async def handle_cli(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        sock_obj = SockObj(writer, reader)
        req_addr = writer.get_extra_info("peername")[:2]
        sock_obj.scope["client"] = req_addr
        sock_obj.req_addr = req_addr

        try:
            try:
                await self._parse_scope(sock_obj)
            except Exception as exp:
                _logger.debug(f"Error parsing request: {exp}")
                return await self.write_errors(sock_obj, 400, "Bad Request!")

            _type = sock_obj.scope["type"]
            if _type == ASGIScopeType.WEBSOCKET:
                if not await self._validate_ws_req(sock_obj):
                    return

            try:
                await self.app(sock_obj.scope, *self.compose_asgi_callables(sock_obj))
            except (NotImplementedError, _OSError) as exp:
                raise exp
            except Exception as exp:
                _logger.exception(f"ASGI applicatoin error on handling request: {exp}")
                if _type == ASGIScopeType.HTTP:
                    return await self.write_errors(
                        sock_obj, 500, "Internal Server Error!"
                    )
                # ws
                return await self.write_ws_closeframe(sock_obj, 1011)

        except _OSError:
            ...
        except ConnectionResetError:
            ...
        finally:
            if sock_obj.listen_task:
                sock_obj.listen_task.cancel()
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()


def setup_logger(
    verbose: bool = False,
    log_file: Union[str, None] = None,
    console_logging: bool = True,
):
    level = logging.DEBUG if verbose else logging.INFO

    if console_logging:
        cfmtr = logging.Formatter(
            "\033[1;96m%(levelname)s:\033[0m \033[1;94m%(asctime)s\033[0m \033[1m[%(process)d]\033[0m %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            validate=True,
        )
        ch = logging.StreamHandler(stream=stdout)
        ch.setFormatter(cfmtr)
        ch.setLevel(level)
        _logger.addHandler(ch)

    if log_file:
        ffmtr = logging.Formatter(
            "%(levelname)s: %(asctime)s [%(process)d] :: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            validate=True,
        )
        fh = logging.FileHandler(filename=log_file)
        fh.setFormatter(ffmtr)
        fh.setLevel(level)
        _logger.addHandler(fh)

    _logger.setLevel(level)


def spin_server(
    app_ref: str,
    workers: int = 1,
    host="localhost",
    port=8075,
    ssl_key: str = "",
    ssl_cert: str = "",
):
    """Spin server in worker pool"""

    try:
        app = Server.load_app(app_ref)
    except Exception as exp:
        _logger.critical(f"Error loading ASGI app. {exp}")
        exit(2)

    # ensure ssl availability
    if ssl_key and ssl_cert:
        try:
            Server.load_ssl(ssl_key, ssl_cert)
        except FileNotFoundError as exp:
            _logger.critical(f"Error loading SSL certs. {exp}")
            exit(2)

    server = Server(app, host=host, port=port, ssl_key=ssl_key, ssl_cert=ssl_cert)

    with multiprocessing.Pool(workers) as pool:
        try:
            pool.map(server.run, range(workers))
        except:
            _logger.info("Server shutdown complete.")


def cli():
    parser = argparse.ArgumentParser(
        prog="vanillacorn",
        description="A simple ASGI server: a basic implementation of the ASGI specification using pure Python and asyncio.",
        add_help=True,
        allow_abbrev=True,
        exit_on_error=True,
    )
    parser.add_argument("asgi_app", nargs="?", default=None, help="ASGI app module")
    parser.add_argument("-v", "--version", action="store_true", help="App version")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8075,
        help="Bind socket to this port (default: 8075)",
    )
    parser.add_argument(
        "-b",
        "--host",
        type=str,
        default="localhost",
        help="Bind socket to this host. (default: localhost)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=1, help="Number of worker processes"
    )
    parser.add_argument(
        "-s", "--silent", action="store_true", help="Suppress console logging"
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed logging")
    parser.add_argument(
        "-l",
        "--log-file",
        type=str,
        default="",
        metavar="FILE",
        help="Write server logs into log file",
    )
    parser.add_argument(
        "--ssl-keyfile",
        type=str,
        default="",
        metavar="FILE",
        help="SSL key file for TLS",
    )
    parser.add_argument(
        "--ssl-certfile",
        type=str,
        default="",
        metavar="FILE",
        help="SSL certfile for TLS",
    )

    args = parser.parse_args()

    if args.version:
        sys.stdout.write(f"v{__version__}\n")
        sys.stdout.flush()
        exit(0)

    setup_logger(args.verbose, log_file=args.log_file, console_logging=not args.silent)
    if args.asgi_app is None:
        sys.stderr.write(
            f"{parser.format_usage()}"
            f"{parser.prog}: error: argument required: asgi_app"
        )
        sys.stdout.flush()
        exit(1)
    else:
        spin_server(
            args.asgi_app,
            workers=args.workers,
            host=args.host,
            port=args.port,
            ssl_key=args.ssl_keyfile,
            ssl_cert=args.ssl_certfile,
        )


if __name__ == "__main__":
    cli()
