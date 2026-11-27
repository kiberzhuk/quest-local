"""Short-lived loopback-only cookie handoff. No logs, files or external listeners."""

import asyncio
import json
from pathlib import Path
import secrets


class LoginBridge:
    def __init__(self):
        self.nonce = secrets.token_hex(32)
        self.server = None
        self.token = None
        self.tasks = set()

    async def __aenter__(self):
        self.token = asyncio.get_running_loop().create_future()
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0, limit=16384)
        self.port = self.server.sockets[0].getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.url = f"{self.origin}/{self.nonce}/"
        return self

    async def __aexit__(self, *args):
        self.server.close()
        await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if not self.token.done():
            self.token.cancel()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            async with asyncio.timeout(5):
                header = await reader.readuntil(b"\r\n\r\n")
                lines = header.decode("ascii").split("\r\n")
                method, path, version = lines[0].split(" ")
                headers = {}
                for line in lines[1:]:
                    if line:
                        key, value = line.split(":", 1)
                        key = key.lower()
                        if key in headers:
                            raise ValueError("Duplicate header")
                        headers[key] = value.strip()
                if headers.get("host") != f"127.0.0.1:{self.port}":
                    await self.reply(writer, 403, b"Forbidden")
                    return
                base = f"/{self.nonce}/"
                if method == "GET" and path == base:
                    content = Path(__file__).with_name("login_page.html").read_bytes()
                    await self.reply(writer, 200, content, "text/html; charset=utf-8")
                elif method == "POST" and path == base + "token":
                    if (headers.get("origin") != self.origin
                            or headers.get("content-type") != "application/json"
                            or "transfer-encoding" in headers):
                        await self.reply(writer, 403, b"Forbidden")
                        return
                    length = int(headers.get("content-length", "0"))
                    if not 1 <= length <= 8192:
                        await self.reply(writer, 400, b"Invalid length")
                        return
                    data = json.loads(await reader.readexactly(length))
                    token = data.get("token") if isinstance(data, dict) else None
                    if not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
                        await self.reply(writer, 400, b"Invalid token")
                    elif self.token.done():
                        await self.reply(writer, 409, b"Already received")
                    else:
                        await self.reply(writer, 200, b"OK")
                        self.token.set_result(token)
                else:
                    await self.reply(writer, 404, b"Not found")
        except (ValueError, UnicodeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            pass
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self.tasks.discard(task)

    async def reply(self, writer, code, body, content_type="text/plain; charset=utf-8"):
        headers = (f"HTTP/1.1 {code} Response\r\nContent-Length: {len(body)}\r\n"
                   f"Content-Type: {content_type}\r\nCache-Control: no-store\r\n"
                   "Connection: close\r\nReferrer-Policy: no-referrer\r\n"
                   "X-Content-Type-Options: nosniff\r\n"
                   "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
                   "frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\r\n")
        writer.write(headers.encode("ascii") + body)
        await writer.drain()
