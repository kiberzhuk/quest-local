import asyncio
import json
import unittest
from unittest.mock import patch

from bridge import LoginBridge
from login import sign_in


async def exchange(bridge, method, path, body=b"", origin=None, host=None):
    reader, writer = await asyncio.open_connection("127.0.0.1", bridge.port)
    request = f"{method} {path} HTTP/1.1\r\nHost: {host or '127.0.0.1:' + str(bridge.port)}\r\n"
    if method == "POST":
        request += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        if origin:
            request += f"Origin: {origin}\r\n"
    writer.write(request.encode() + b"\r\n" + body)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_and_single_use_handoff(self):
        async with LoginBridge() as bridge:
            path = f"/{bridge.nonce}/"
            response = await exchange(bridge, "GET", path)
            self.assertIn(b"200 Response", response)
            self.assertIn(b"Cache-Control: no-store", response)
            response = await exchange(bridge, "POST", path + "token",
                                      b'{"token":"test-only-not-a-real-token"}', bridge.origin)
            self.assertIn(b"200 Response", response)
            self.assertEqual(await bridge.token, "test-only-not-a-real-token")
            response = await exchange(bridge, "POST", path + "token", b'{"token":"x"}', bridge.origin)
            self.assertIn(b"409 Response", response)

    async def test_wrong_origin_host_nonce_rejected(self):
        async with LoginBridge() as bridge:
            path = f"/{bridge.nonce}/token"
            for origin in (None, "https://other.test"):
                response = await exchange(bridge, "POST", path, b'{"token":"x"}', origin)
                self.assertIn(b"403 Response", response)
            response = await exchange(bridge, "GET", f"/{bridge.nonce}/", host="other.test")
            self.assertIn(b"403 Response", response)
            response = await exchange(bridge, "POST", "/wrong/token", b'{"token":"x"}', bridge.origin)
            self.assertIn(b"404 Response", response)
            self.assertFalse(bridge.token.done())

    async def test_server_closes_on_cancel(self):
        async with LoginBridge() as bridge:
            port = bridge.port
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", port)

    async def test_regular_browser_launch_no_profile_flags_or_process_checks(self):
        async def deliver(command):
            url = command[-1]
            from urllib.parse import urlsplit
            parsed = urlsplit(url)
            reader, writer = await asyncio.open_connection("127.0.0.1", parsed.port)
            body = b'{"token":"synthetic-test-token"}'
            writer.write((f"POST {parsed.path}token HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
                          f"Origin: http://{parsed.netloc}\r\nContent-Type: application/json\r\n"
                          f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()

        tasks = []
        def launch(command):
            self.assertEqual(command[:2], ["test-vivaldi.exe", "--new-tab"])
            self.assertEqual(len(command), 3)
            tasks.append(asyncio.create_task(deliver(command)))

        with patch("login.find_vivaldi", return_value="test-vivaldi.exe"), \
                patch("login.subprocess.Popen", side_effect=launch), \
                patch("login.retrieve", return_value="fake-secret") as retrieve:
            self.assertEqual(await sign_in(lambda text: None), "fake-secret")
            retrieve.assert_called_once_with("synthetic-test-token")
        await asyncio.gather(*tasks)
