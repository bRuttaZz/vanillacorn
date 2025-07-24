__version__ = "0.0.1"

import argparse
import asyncio
import importlib
import logging
import multiprocessing
import os
import sys
import socket
from enum import Enum
from itertools import chain
from sys import stdout, exit
from typing import Callable, Coroutine, TypedDict, Tuple, Iterable
from urllib.parse import unquote

_logger = logging.getLogger("pycorn")
_logger.setLevel(logging.DEBUG)
_logger.addHandler(logging.StreamHandler(stream=stdout))

ASGI_VERSION = "2.0"  # (2019-03-20)
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


class ParserInfo(TypedDict):
    content_length: str | int
    chunked_encoding: bool
    http_version_str: str
    req_path: str
    req_addr: str
    req_method: str


class ASGISendArg(TypedDict):
    type: str
    status: int
    headers: Iterable[Tuple[bytes, bytes]]
    trailers: bool
    body: bytes
    more_body: bool


HTTP_VERSIONS = ("1.0", "1.1", "2")
READ_MAX_BYTES = 2**16  # 64kb
DEFAULT_SCOPE_PARAMS = {
    "asgi": {
        "version": ASGI_VERSION,
        "spec_version": ASGI_VERSION,
    }
}
DEFAULT_RESPONSE_HEADERS = [(b"Server", SERVER_NAME.encode("ascii"))]

# TODO:
# Exception handling


class Server:
    _asgi_version = ASGI_VERSION

    def __init__(
        self,
        app: Callable[[dict, Callable, Callable], Coroutine] | str,
        port: int = 8075,
        host: str = "localhost",
    ):
        self.id: int | None = None
        self.host: str = host
        self.port: int = port
        self.app: Callable[[dict, Callable, Callable], Coroutine]
        if isinstance(app, str):
            self.app = self.load_app(app)
        else:
            self.app = app
        self.tls_enabled = False  # TODO: tls support
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

    def run(self, id: int = 0):
        """Start server on an eventloop"""
        self.id = id
        asyncio.run(self.start_server())

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

    async def start_server(self, event_loop: asyncio.AbstractEventLoop | None = None):
        """Start server"""
        server = await asyncio.start_server(
            self.handle_cli,
            host=self.host,
            port=self.port,
            family=socket.AF_UNSPEC,
            reuse_address=True,
            reuse_port=True,
        )
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
        for key, val in spec["headers"]:
            if key == b"upgrade" and val == "websocket":
                spec["type"] = ASGIScopeType.WEBSOCKET.value
                spec["scheme"] = "wss" if self.tls_enabled else "ws"
            elif key == b"sec-websocket-protocol":
                spec["subprotocols"] = [
                    proto.strip() for proto in val.decode("utf-8").split(",")
                ]
            elif key == b"content-length":
                parser_info["content_length"] = val.decode("utf-8")
            elif key == b"transfer-encoding" and val == b"chunked":
                parser_info["chunked_encoding"] = True
        parser_info["req_method"] = spec["method"]
        parser_info["req_path"] = spec["path"]

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

            if not remaining:
                pass

            elif parser_info[
                "chunked_encoding"
            ]:  # read type: transfer-encoding: chunked
                size_line = await reader.readline()
                if not size_line:
                    remaining = False
                chunk_size = int(
                    size_line.strip(), 16
                )  # TODO: possible conversion error
                if not chunk_size:
                    await reader.readline()  # for trailing CRLF
                    remaining = False
                payload = await reader.readexactly(chunk_size)
                await reader.readline()  # again for trailing CRLF

            elif fixed_content:  # read fixed fixed_content
                _len = (
                    READ_MAX_BYTES if remaining_len > READ_MAX_BYTES else remaining_len
                )
                payload = await reader.read(_len)
                remaining_len -= _len
                if not remaining_len:
                    remaining = False

            else:  # read all till null
                payload = await reader.read(READ_MAX_BYTES)
                if not payload:
                    remaining = False

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
                raise OSError(
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
            raise OSError("[pycorn] Attempt to write on a closed client-connection!")

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

    async def handle_cli(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        _spec = dict()
        _parser_info: ParserInfo = {
            "content_length": "",
            "chunked_encoding": False,
            "http_version_str": "HTTP/1.1",
            "req_path": "",
            "req_addr": "",
            "req_method": "",
        }
        try:
            if not await self._parse_header_line(reader, _spec, _parser_info):
                await self.write_errors(writer, 400, _parser_info, "Bad Request!")
                return
            if not await self._parse_headers(reader, _spec):
                await self.write_errors(writer, 400, _parser_info, "Bad Request!")
                return
            self._parse_pathname(_spec)
            self._parse_info(_spec, _parser_info)
            _spec["client"] = writer.get_extra_info("peername")[:2]
            _spec["server"] = self._addr
            _spec["state"] = self.life_span_state
            _parser_info["req_addr"] = _spec["client"][0]
        except Exception as exp:
            _logger.error(f"Error parsing request: {exp}")
            await self.write_errors(writer, 400, _parser_info, "Bad Request!")

        try:
            if _spec["type"] == ASGIScopeType.HTTP.value:
                await self.app(
                    _spec,
                    self.compose_http_recv(reader, _parser_info),
                    self.compose_http_send(writer, _parser_info),
                )
            elif _spec["type"] == ASGIScopeType.WEBSOCKET.value:
                # TODO
                ...
            else:
                NotImplementedError("Websocket recv and send handlers not implemented")
        except Exception as exp:
            _logger.exception(exp)
            _logger.error(f"ASGI applicatoin error on handling request: {exp}")
            await self.write_errors(writer, 500, _parser_info, "Internal Server Error!")
        finally:
            if not writer.is_closing():
                await writer.drain()
                writer.close()
                await writer.wait_closed()


def spin_server(app_ref: str, workers: int = 1, host="localhost", port=8075):
    """Spin server in worker pool"""
    try:
        app = Server.load_app(app_ref)
    except Exception as exp:
        _logger.critical(f"Error loading ASGI app. {exp}")
        exit(2)
    server = Server(app, host=host, port=port)

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

    args = parser.parse_args()

    if args.version:
        sys.stdout.write(f"v{__version__}\n")
        sys.stdout.flush()
    elif args.asgi_app is None:
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
        )


if __name__ == "__main__":
    cli()
