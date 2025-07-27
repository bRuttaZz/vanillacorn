__version__ = "0.0.2"

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
from sys import stdout, exit
from time import time
from typing import Callable, Coroutine, TypedDict, Tuple, Iterable, Literal, NotRequired
from urllib.parse import unquote

_logger = logging.getLogger("pycorn")

ASGI_VERSION = (
    "2.5"  # https://asgi.readthedocs.io/en/latest/specs/www.html#spec-versions
)
SERVER_NAME = "vanillacorn"


class ASGIScopeType(Enum):
    LIFESPAN = "lifespan"
    HTTP = "http"
    WEBSOCKET = "websocket"


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


class ParserInfo(TypedDict):
    content_length: str | int
    chunked_encoding: bool
    http_version_str: str
    req_path: str
    req_addr: str
    req_method: str
    sec_webSocket_key: str
    sec_webSocket_version: int
    header_upgrade: str
    header_connection: str


class ASGISendArg(TypedDict):
    type: str
    status: NotRequired[int]
    headers: NotRequired[Iterable[Tuple[bytes, bytes]]]
    trailers: NotRequired[bool]
    body: NotRequired[bytes]
    more_body: NotRequired[bool]


class WSASGISendArg(TypedDict):
    type: str
    subprotocol: NotRequired[str]
    headers: NotRequired[Iterable[Tuple[bytes, bytes]]]
    text: str
    bytes: bytes
    code: NotRequired[int]
    reason: NotRequired[str]


class WSASGIMsg(TypedDict):
    type: Literal[
        "websocket.receive",
        "websocket.send",
        "websocket.connect",
        "websocket.disconnect",
    ]
    bytes: NotRequired[bytes | None]
    text: NotRequired[str | None]
    code: NotRequired[int]
    reason: NotRequired[str | None]


class WSConnParams(TypedDict):
    recv_queue: asyncio.Queue
    sock_connected: bool
    _closing_reason: str | None
    _closing_code: int | None
    _last_active: float
    _last_ping_send: float
    _last_pong: float
    listen_task: asyncio.Task | None


HTTP_VERSIONS = ("1.0", "1.1", "2")

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
DEFAULT_RESPONSE_HEADERS = [(b"Server", SERVER_NAME.encode("ascii"))]

CUSTOM_WS_STATUS_CODES = [  # range of customisable range of ws status codes
    (3000, 3999),
    (4000, 4999),
]


# Exceptions
class _OSError(OSError):
    """Vaillacorn Custom OSError"""


class Server:
    _asgi_version = ASGI_VERSION

    def __init__(
        self,
        app: Callable[[dict, Callable, Callable], Coroutine] | str,
        port: int = 8075,
        host: str = "localhost",
        ssl_key: str = "",
        ssl_cert: str = "",
        ssl_context: ssl.SSLContext | None = None,
    ):
        self.id: int | None = None
        self.host: str = host
        self.port: int = port

        self.app: Callable[[dict, Callable, Callable], Coroutine]
        if isinstance(app, str):
            self.app = self.load_app(app)
        else:
            self.app = app

        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.ssl_context: ssl.SSLContext | None = ssl_context
        self.tls_enabled = True if ssl_context or (ssl_key and ssl_cert) else False

        self.life_span: LifeSpan = LifeSpan.IDLE
        self.life_span_state = dict()
        self._common_scopes = {
            "state": self.life_span_state,
            **DEFAULT_SCOPE_PARAMS,
        }
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
                    {"type": ASGIScopeType.LIFESPAN.value, **self._common_scopes},
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
    async def _parse_header_line(
        self, reader: asyncio.StreamReader, spec: dict, parser_info: ParserInfo
    ):
        # as of now not respecting any pseudo headers
        header_line = await reader.readline()
        header_line = header_line.decode("ascii").strip().rstrip("\r")
        header_line_comps = header_line.split(" ")
        if len(header_line_comps) != 3:
            _logger.debug("Invalid request headerline!")
            return
        http_version = header_line_comps[2].split("/")[-1]
        if http_version not in HTTP_VERSIONS:
            _logger.debug("Invalid http protocol!")
            return
        parser_info["http_version_str"] = header_line_comps[2].upper()
        spec["method"] = header_line_comps[0].upper()
        spec["http_version"] = http_version
        spec["path"] = header_line_comps[1]
        return True

    async def _parse_headers(self, reader: asyncio.StreamReader, spec: dict):
        _headers = []
        while True:
            line = await reader.readline()
            line = line.decode("ascii").strip().rstrip("\r")
            if not line:
                break
            h_key, *h_val = line.split(": ")
            h_val = ": ".join(h_val).lstrip()
            if h_key.startswith(":"):
                if h_key == ":authority":
                    _headers.insert(0, (b"host", h_val.encode("utf-8")))
                continue  # ignore all pseudo headers as per spec : https://asgi.readthedocs.io/en/latest/specs/www.html
            _headers.append((h_key.lower().encode("utf-8"), h_val.encode("utf-8")))
        spec["headers"] = tuple(_headers)
        return True

    def _parse_pathname(self, spec: dict):
        org_path = spec.get("path", "/")
        path, *query = org_path.split("?")
        query = "?".join(query)

        spec["path"] = unquote(path)
        spec["query_string"] = query.encode("utf-8")
        spec["raw_path"] = path.encode("utf-8")
        spec["root_path"] = ""

    def _parse_info(self, spec: dict, parser_info: ParserInfo):
        spec["type"] = ASGIScopeType.HTTP.value
        spec["scheme"] = "https" if self.tls_enabled else "http"
        refined_headers = []
        for key, val in spec["headers"]:
            if key == b"upgrade":
                _val = val.decode("utf-8").lower()
                if _val == "websocket":
                    spec["type"] = ASGIScopeType.WEBSOCKET.value
                    spec["scheme"] = "wss" if self.tls_enabled else "ws"
                parser_info["header_upgrade"] = _val
            elif key == b"connection":
                parser_info["header_connection"] = val.decode("utf-8").lower()
            elif key == b"sec-websocket-version":
                parser_info["sec_webSocket_version"] = int(val)
            elif key == b"sec-websocket-key":
                parser_info["sec_webSocket_key"] = val.decode("utf-8")
            elif key == b"sec-websocket-protocol":
                spec["subprotocols"] = [
                    proto.strip() for proto in val.decode("utf-8").split(",")
                ]
                refined_headers.append((b"subprotocol", val))
                continue
            elif key == b"content-length":
                parser_info["content_length"] = val.decode("utf-8")
            elif key == b"transfer-encoding" and val == b"chunked":
                parser_info["chunked_encoding"] = True
            refined_headers.append((key, val))
        spec["headers"] = refined_headers
        parser_info["req_method"] = spec["method"]
        parser_info["req_path"] = spec["path"]

    async def _parse_scope(
        self, reader: asyncio.StreamReader, _spec: dict, _parser_info: ParserInfo
    ):
        if not await self._parse_header_line(reader, _spec, _parser_info):
            raise ValueError("parserError in headerline")
        if not await self._parse_headers(reader, _spec):
            raise ValueError("parserError in headerline")
        self._parse_pathname(_spec)
        self._parse_info(_spec, _parser_info)
        _spec["server"] = self._addr
        _spec["state"] = self.life_span_state
        _parser_info["req_addr"] = _spec["client"][0]

    def _write_response_header(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        parser_info: ParserInfo,
        headers: Iterable[Tuple[bytes, bytes]],
        content_len: int | None = None,
    ) -> bool:
        _found_content_len = False
        msg = StatusMessages.default
        if f"status_{status}" in StatusMessages.__members__:
            msg = StatusMessages[f"status_{status}"]

        writer.write(
            (f"{parser_info['http_version_str']} {status} {msg.value}\r\n").encode(
                "ascii"
            )
        )

        for key, val in headers:
            if key.decode("utf-8").lower() == "content-length":
                _found_content_len = True
            writer.write(key + b": " + val + b"\r\n")

        if not _found_content_len and content_len is not None:
            writer.write(f"Content-Length: {content_len}\r\n".encode("ascii"))
        _logger.info(
            f"{parser_info['req_addr']} - "
            f"\"{parser_info['req_method'].upper()} {parser_info['req_path']} {parser_info['http_version_str']}\" "
            f"- {status} {msg.value}"
        )
        return _found_content_len

    # http specs
    def compose_http_recv(self, reader: asyncio.StreamReader, parser_info: ParserInfo):
        remaining = True
        remaining_len = 0
        fixed_content = False
        if str(parser_info["content_length"]).isdigit():
            remaining_len = int(parser_info["content_length"])
            fixed_content = True

        async def http_recv(*args, **kwargs):
            nonlocal remaining, remaining_len
            payload = b""

            try:
                if not remaining:
                    pass

                elif parser_info[
                    "chunked_encoding"
                ]:  # read type: transfer-encoding: chunked
                    size_line = await reader.readline()
                    if not size_line:
                        remaining = False
                    chunk_size = int(size_line.strip(), 16)
                    if not chunk_size:
                        await reader.readline()  # for trailing CRLF
                        remaining = False
                    payload = await reader.readexactly(chunk_size)
                    await reader.readline()  # again for trailing CRLF

                elif fixed_content:  # read fixed fixed_content
                    _len = (
                        READ_MAX_BYTES
                        if remaining_len > READ_MAX_BYTES
                        else remaining_len
                    )
                    payload = await reader.read(_len)
                    remaining_len -= _len
                    if not remaining_len:
                        remaining = False

                else:  # read all till null
                    payload = await reader.read(READ_MAX_BYTES)
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

    def compose_http_send(self, writer: asyncio.StreamWriter, parser_info: ParserInfo):
        _headers = [*DEFAULT_RESPONSE_HEADERS]
        _status = 200
        _trailers = False
        _body = bytearray()
        _header_send = False
        _chunked_encoding = False

        async def http_send(msg: ASGISendArg):
            if writer.is_closing():
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
                    if not self._write_response_header(
                        writer, _status, parser_info, _headers
                    ):
                        if not more_body:
                            writer.write(
                                f"Content-Length: {len(body)}\r\n".encode("ascii")
                            )
                        else:
                            _chunked_encoding = True
                            writer.write(
                                "Transfer-Encoding: chunked\r\n".encode("ascii")
                            )
                    writer.write(b"\r\n")
                    _header_send = True
                if _chunked_encoding:
                    size_line = f"{len(body):X}\r\n".encode("ascii")  # size in hex
                    writer.write(size_line)
                    writer.write(body + b"\r\n")
                else:
                    writer.write(body)
                await writer.drain()
                if not more_body:
                    writer.close()
                    await writer.wait_closed()

            elif type == "http.response.trailers":
                _body.extend(body)
                t_body = bytes(_body)
                self._write_response_header(
                    writer, _status, parser_info, _headers, len(t_body)
                )
                writer.write(b"\r\n")
                writer.write(t_body)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            else:
                raise NotImplementedError(
                    f"ASGI send msg.type '{type}' is Not implemented! ASGI version :{self._asgi_version}"
                )

        return http_send

    async def write_errors(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        _parser_info: ParserInfo,
        message: str = "",
    ):
        if writer.is_closing():
            raise _OSError("[pycorn] Attempt to write on a closed client-connection!")

        if not message:
            if f"status_{status}" in StatusMessages.__members__:
                message = StatusMessages[f"status_{status}"].value
            else:
                message = StatusMessages.default.value
        msg = message.encode("ascii")

        self._write_response_header(
            writer,
            status,
            _parser_info,
            [
                *DEFAULT_RESPONSE_HEADERS,
                (b"Content-Type", b"text/plain"),
            ],
            content_len=len(msg),
        )
        writer.write(b"\r\n")
        writer.write(msg)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    # ws specs
    async def _validate_ws_req(
        self, writer: asyncio.StreamWriter, parser_info: ParserInfo
    ) -> bool:
        """Validate ws connection req"""
        if (
            not parser_info["sec_webSocket_key"]
            or not parser_info["sec_webSocket_version"]
            or parser_info["header_connection"] != "upgrade"
            or parser_info["header_upgrade"] != "websocket"
        ):
            await self.write_errors(writer, 400, parser_info, "Bad Request")
            return False
        return True

    async def _upgrade_ws_conn(
        self,
        writer: asyncio.StreamWriter,
        parser_info: ParserInfo,
        headers: Iterable[Tuple[bytes, bytes]],
    ):
        accept_key = b64encode(
            sha1((parser_info["sec_webSocket_key"] + WS_MAGIC_STRING).encode()).digest()
        )
        self._write_response_header(
            writer,
            101,
            parser_info,
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
                writer.write(key + b": " + val + b"\r\n")
        writer.write(b"\r\n")
        await writer.drain()

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
        opcode: WSOpcode | None = None
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

    async def write_ws_error(
        self,
        writer: asyncio.StreamWriter,
        status: int = 1000,
        reason: str = "",
    ):
        if writer.is_closing():
            raise _OSError("Try calling write_ws_error on closed connection!")

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
        await self._write_ws_frame(1, WSOpcode.CLOSE, payload, writer)

        async def close_after_timeout():
            """Ideally should wait for client's response to complete a handshake. Fallback for client taking too much response time"""
            await asyncio.sleep(5)
            writer.close()
            await writer.wait_closed()
            _logger.debug("Server side closure confirmed")

        asyncio.create_task(close_after_timeout())
        _logger.debug(f"Closed ws connection : /{_code}/{reason}/.")

    async def ws_conn_listener(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ws_conn_info: WSConnParams,
    ):
        """Responsible for handling control codes"""

        async def _keep_connection():
            try:
                while True:
                    await asyncio.sleep(5)
                    if writer.is_closing():
                        break

                    time_now = time()

                    # check timeouts
                    if time_now - ws_conn_info[
                        "_last_active"
                    ] > WS_MAX_LAST_ACTIVE_TIME or (
                        ws_conn_info["_last_ping_send"]
                        and time_now - ws_conn_info["_last_ping_send"]
                        > WS_MAX_PING_RESPONSE_TIME
                    ):
                        ws_conn_info["_closing_code"] = 1001
                        ws_conn_info["_closing_reason"] = "Going Away"
                        await self.write_ws_error(writer, 1001)
                        break

                    # send ping
                    if time_now - ws_conn_info["_last_pong"] > WS_PING_INTERVEL:
                        await self._write_ws_frame(
                            1, WSOpcode.PING, b"vanillacorn", writer
                        )
                        ws_conn_info["_last_ping_send"] = time()
            except asyncio.CancelledError:
                ...

        sub_task = asyncio.create_task(_keep_connection())
        try:
            while True:
                await asyncio.sleep(0)
                if writer.is_closing():
                    break

                try:
                    opcode, data = await self._read_message_fragment(reader)
                    ws_conn_info["_last_active"] = time()
                except ValueError:
                    await self.write_ws_error(writer, 1002)
                    break

                match opcode:
                    case WSOpcode.TXT | WSOpcode.BYTES:
                        try:
                            await ws_conn_info["recv_queue"].put(
                                WSASGIMsg(
                                    type="websocket.receive",
                                    text=(
                                        data.decode("utf-8")
                                        if opcode == WSOpcode.TXT
                                        else None
                                    ),
                                    bytes=data if opcode == WSOpcode.BYTES else None,
                                )
                            )
                        except UnicodeDecodeError:
                            await self.write_ws_error(writer, 1002)
                            break
                    case WSOpcode.CLOSE:
                        if len(data) < 2:
                            ws_conn_info["_closing_code"] = 1005  # asgi spec default
                        else:
                            ws_conn_info["_closing_code"] = struct.unpack(
                                "!H", data[:2]
                            )[0]
                            try:
                                if data[2:]:
                                    ws_conn_info["_closing_reason"] = data[2:].decode(
                                        "utf-8"
                                    )
                            except UnicodeDecodeError:
                                ws_conn_info["_closing_reason"] = "<Invalid UTF-8>"
                        _logger.debug(
                            f"Client closed ws connection : {ws_conn_info['_closing_code']}"
                        )
                        # await self.write_ws_error(writer, ws_conn_info["_closing_code"]) response is not required from server it seems
                        writer.close()
                        await writer.wait_closed()
                        break

                    case WSOpcode.PING:
                        await self._write_ws_frame(
                            1,
                            WSOpcode.PONG,
                            data,
                            writer,
                        )
                        ws_conn_info["_last_pong"] = time()
                    case WSOpcode.PONG:
                        ws_conn_info["_last_ping_send"] = 0
                        ws_conn_info["_last_pong"] = time()
                    case _:
                        raise NotImplementedError("Invalid opcode in ws_conn_listener")
        except asyncio.CancelledError:
            ...
        finally:
            try:
                sub_task.cancel()
            except:
                ...

    def compose_ws_recv(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        parser_info: ParserInfo,
        ws_conn_info: WSConnParams,
    ):
        def _get_disconnect_info_if():
            if writer.is_closing():
                try:
                    if ws_conn_info["listen_task"]:
                        ws_conn_info["listen_task"].cancel()
                except:
                    ...
                return WSASGIMsg(
                    type="websocket.disconnect",
                    code=ws_conn_info["_closing_code"] or 1005,
                    reason=ws_conn_info["_closing_reason"] or "",
                )
            return

        async def ws_recv():
            dis_res = _get_disconnect_info_if()
            if dis_res:
                return dis_res

            if not ws_conn_info["sock_connected"]:
                return WSASGIMsg(type="websocket.connect", text=None, bytes=None)

            while True:
                dis_res = _get_disconnect_info_if()
                if dis_res:
                    return dis_res
                try:
                    return await asyncio.wait_for(ws_conn_info["recv_queue"].get(), 1)
                except asyncio.TimeoutError:
                    continue

        return ws_recv

    def compose_ws_send(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        parser_info: ParserInfo,
        ws_conn_info: WSConnParams,
    ):
        async def ws_send(msg: WSASGISendArg):
            if writer.is_closing():
                try:
                    if ws_conn_info["listen_task"]:
                        ws_conn_info["listen_task"].cancel()
                except:
                    ...
                raise _OSError("Socket closed!")

            elif msg["type"] == "websocket.accept":
                # ignoring ws subprotocol from msg["subprotocol"]
                await self._upgrade_ws_conn(writer, parser_info, msg.get("headers", []))
                _now = time()
                ws_conn_info["sock_connected"] = True
                ws_conn_info["_last_active"] = _now
                ws_conn_info["_last_ping_send"] = 0
                ws_conn_info["_last_pong"] = _now
                ws_conn_info["listen_task"] = asyncio.create_task(
                    self.ws_conn_listener(reader, writer, ws_conn_info)
                )

            elif (
                msg["type"] == "websocket.close" and not ws_conn_info["sock_connected"]
            ):
                await self.write_errors(writer, 403, parser_info)

            elif msg["type"] == "websocket.close":
                await self.write_ws_error(
                    writer,
                    status=int(msg.get("code", 1000)),
                    reason=msg.get("reason", ""),
                )

            elif msg["type"] == "websocket.send":
                if msg.get("text") is not None:
                    await self._write_message_fragment(
                        WSOpcode.TXT, msg["text"].encode("utf-8"), writer  #
                    )
                elif msg.get("bytes") is not None:
                    await self._write_message_fragment(
                        WSOpcode.BYTES, msg["bytes"], writer
                    )
                else:
                    await self.write_ws_error(writer, status=1011)
                    raise ValueError(
                        "send type='websocket.send' should contain either 'text' or 'bytes'"
                    )

        return ws_send

    # client handlers
    async def handle_http_cli(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        _spec: dict,
        _parser_info: ParserInfo,
    ):
        try:
            await self.app(
                _spec,
                self.compose_http_recv(reader, _parser_info),
                self.compose_http_send(writer, _parser_info),
            )
        except _OSError:
            ...
        except Exception as exp:
            _logger.exception(f"ASGI applicatoin error on handling request: {exp}")
            try:
                await self.write_errors(
                    writer, 500, _parser_info, "Internal Server Error!"
                )
            except:
                ...

    async def handle_ws_cli(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        _spec: dict,
        _parser_info: ParserInfo,
    ):
        if await self._validate_ws_req(writer, _parser_info):
            _ws_conn_info: WSConnParams = {
                "recv_queue": asyncio.Queue(),
                "sock_connected": False,
                "_closing_reason": None,
                "_closing_code": None,
                "_last_active": 0,
                "_last_ping_send": 0,
                "_last_pong": 0,
                "listen_task": None,
            }
            try:
                await self.app(
                    _spec,
                    self.compose_ws_recv(reader, writer, _parser_info, _ws_conn_info),
                    self.compose_ws_send(reader, writer, _parser_info, _ws_conn_info),
                )
            except _OSError:
                ...
            except Exception as exp:
                _logger.exception(f"Error in ASGI app. closing ws connection : {exp}")
                try:
                    await self.write_ws_error(writer, 1011)
                except:
                    ...
            finally:
                try:
                    if _ws_conn_info["listen_task"]:
                        _ws_conn_info["listen_task"].cancel()
                except:
                    ...

    async def handle_cli(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        _spec = dict()
        _spec["client"] = writer.get_extra_info("peername")[:2]
        _parser_info: ParserInfo = {
            "content_length": "",
            "chunked_encoding": False,
            "http_version_str": "HTTP/1.1",
            "req_path": "",
            "req_addr": "",
            "req_method": "",
            "sec_webSocket_key": "",
            "sec_webSocket_version": 0,
            "header_upgrade": "",
            "header_connection": "",
        }
        try:
            await self._parse_scope(reader, _spec, _parser_info)
        except Exception as exp:
            _logger.debug(f"Error parsing request: {exp}")
            await self.write_errors(writer, 400, _parser_info, "Bad Request!")

        try:
            if _spec["type"] == ASGIScopeType.HTTP.value:
                await self.handle_http_cli(reader, writer, _spec, _parser_info)
            elif _spec["type"] == ASGIScopeType.WEBSOCKET.value:
                await self.handle_ws_cli(reader, writer, _spec, _parser_info)
            else:
                NotImplementedError(
                    f"Invalid asgi scope! scope['type']={_spec['type']}"
                )
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()


def setup_logger(
    verbose: bool = False, log_file: str | None = None, console_logging: bool = True
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
