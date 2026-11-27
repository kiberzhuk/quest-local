import datetime
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from collections import deque
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from nacl.public import Box, PrivateKey, PublicKey

from client import QuestClient, parse_secret
from login import find_vivaldi, select_login_token
from meta_secret import NoRedirect, find_secrets
from protocol import (ADB_SET, ADB_STATUS, APP_LAUNCH, AUTHENTICATE, Assembler, DEV_SET,
                      DEV_STATUS, HELLO, HMD_STATUS, HMD_VERSION, LICENSE_DETAILS, ProtocolError,
                      RemoteError, decode, encode, fragments)

SECRET = bytes(range(32))


class FakeQuest:
    """Wire-level peer: verifies HMAC, independent keys, encrypted response frames."""
    def __init__(self, *args, **kwargs):
        self.is_connected = False
        self.characteristic = SimpleNamespace(properties=["read", "write"])
        self.services = SimpleNamespace(get_service=lambda uuid: SimpleNamespace(
            get_characteristic=lambda uuid: self.characteristic))
        self.incoming = Assembler()
        self.outgoing = deque()
        self.box = None
        self.key = PrivateKey.generate()
        self.challenge = b"challenge-from-headset"
        self.authenticated = False
        self.methods = []
        self.dev = self.adb = 0
        self.reject_dev = False
        self.deny_dev = False
        self.ignore_dev = False
        self.bad_signature = False
        self.tamper = False
        self.no_reply = False
        self.mismatch_status = False
        self.reply_sequence = None
        self.reject_adb = False
        self.reject_launch = False
        self.launch_error = False

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def write_gatt_char(self, characteristic, chunk, response):
        packet = self.incoming.feed(chunk)
        if packet is None:
            return
        request = decode(self.box.decrypt(packet) if self.box else packet)
        method, sequence = request[2], request[3]
        self.methods.append(method)
        body = decode(request.get(4, b""))
        code, answer = 0, b""
        was_encrypted = self.box is not None
        if method == HELLO:
            self.box = Box(self.key, PublicKey(body[1]))
            signed = encode({1: bytes(self.key.public_key), 2: self.challenge})
            signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Quest")])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(signing_key.public_key()).serial_number(1)
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=1))
                    .sign(signing_key, hashes.SHA256()))
            signature = signing_key.sign(signed + body[2], padding.PKCS1v15(), hashes.SHA256())
            if self.bad_signature:
                signature = bytes(len(signature))
            answer = encode({1: signed, 2: signature,
                             3: cert.public_bytes(serialization.Encoding.DER)})
        elif method == AUTHENTICATE:
            if hmac.compare_digest(body[1], hmac.digest(SECRET, self.challenge, "sha256")):
                self.authenticated = True
            else:
                code, answer = 1, encode({1: 5})
        elif method == DEV_SET:
            if not self.authenticated:
                code, answer = 1, encode({1: 5})
            elif self.reject_dev:
                code, answer = 1, encode({1: 701})
            elif self.deny_dev:
                code, answer = 1, encode({1: 19, 5: 1054})
            elif not self.ignore_dev:
                self.dev = body[1]
        elif method == ADB_SET:
            if self.reject_adb:
                code, answer = 1, encode({1: 19, 5: 1054})
            else:
                self.adb = body[1]
        elif method == APP_LAUNCH:
            assert body == {1: b"com.android.settings"}
            if self.reject_launch:
                code, answer = 1, encode({1: 19})
            elif self.launch_error:
                answer = encode({1: "Test launch failure"})
        elif method == DEV_STATUS:
            answer = encode({1: self.dev})
        elif method == ADB_STATUS:
            answer = encode({1: self.adb})
        elif method == HMD_STATUS:
            answer = encode({1: 80, 61: self.dev, 62: 0 if self.mismatch_status else self.adb})
        elif method == HMD_VERSION:
            answer = encode({11: "Quest test", 33: "test-build"})
        elif method == LICENSE_DETAILS:
            code, answer = 1, encode({1: 701})
        else:
            raise AssertionError(f"Unexpected command {method}")
        reply = encode({1: sequence if self.reply_sequence is None else self.reply_sequence,
                        2: code, 3: answer})
        if was_encrypted:
            reply = bytes(self.box.encrypt(reply))
            if self.tamper:
                reply = reply[:-1] + bytes([reply[-1] ^ 1])
        if not self.no_reply:
            self.outgoing.extend(fragments(reply, 21))

    async def read_gatt_char(self, characteristic):
        return self.outgoing.popleft() if self.outgoing else b"\xff"


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.peer = FakeQuest()
        self.logs = []
        self.client = QuestClient(self.logs.append, lambda *a, **kw: self.peer, timeout=2)

    async def asyncTearDown(self):
        await self.client.disconnect()

    async def test_handshake_auth_enable_readback(self):
        await self.client.connect("fake")
        await self.client.enable(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, DEV_SET, DEV_STATUS,
                                            ADB_SET, ADB_STATUS, HMD_STATUS])
        self.assertTrue(any("ПОДТВЕРЖДЕНО ШЛЕМОМ" in line for line in self.logs))
        self.assertNotIn(SECRET.hex(), "\n".join(self.logs))

    async def test_status_logs_direct_devmode_separately_from_general_flag(self):
        await self.client.connect("fake")
        await self.client.authenticate(SECRET.hex())
        self.peer.dev = 1
        await self.client.status()
        self.assertIn(DEV_STATUS, self.peer.methods)
        self.assertTrue(any("Прямой статус Developer Mode (6002)" in line for line in self.logs))
        self.assertNotIn(SECRET.hex(), "\n".join(self.logs))

    async def test_read_only_status_needs_no_secret(self):
        await self.client.connect("fake")
        await self.client.status()
        self.assertEqual(self.peer.methods, [HELLO, HMD_STATUS, HMD_VERSION])

    async def test_bad_secret_never_changes_settings(self):
        await self.client.connect("fake")
        with self.assertRaises(RemoteError):
            await self.client.enable("ff" * 32)
        self.assertNotIn(DEV_SET, self.peer.methods)

    async def test_license_refusal_stops_before_adb(self):
        self.peer.reject_dev = True
        await self.client.connect("fake")
        with self.assertRaisesRegex(RemoteError, "DEVELOPMENT_LICENSE_DOES_NOT_EXIST"):
            await self.client.enable(SECRET.hex())
        self.assertNotIn(ADB_SET, self.peer.methods)

    async def test_1054_runs_only_read_diagnostics_after_refusal(self):
        self.peer.deny_dev = True
        await self.client.connect("fake")
        with self.assertRaisesRegex(ProtocolError, "Шлем не разрешил"):
            await self.client.enable(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, DEV_SET, DEV_STATUS,
                                            ADB_STATUS, LICENSE_DETAILS])
        self.assertEqual(self.peer.dev, 0)
        self.assertEqual(self.peer.adb, 0)
        self.assertFalse(any("ПОДТВЕРЖДЕНО ШЛЕМОМ" in line for line in self.logs))

    async def test_manual_diagnostics_do_not_send_settings_commands(self):
        await self.client.connect("fake")
        await self.client.diagnose_permission(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, DEV_STATUS,
                                            ADB_STATUS, LICENSE_DETAILS])
        self.assertTrue(any("Начало диагностики" in line for line in self.logs))
        self.assertTrue(any("Конец диагностики" in line for line in self.logs))

    async def test_usb_only_does_not_send_developer_command_or_unsupported_status(self):
        await self.client.connect("fake")
        await self.client.enable_usb_only(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, ADB_SET, HMD_STATUS])
        self.assertEqual(self.peer.dev, 0)

    async def test_usb_only_refusal_no_retry(self):
        self.peer.reject_adb = True
        await self.client.connect("fake")
        with self.assertRaises(RemoteError):
            await self.client.enable_usb_only(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, ADB_SET])

    async def test_settings_launch_has_no_settings_writes(self):
        await self.client.connect("fake")
        await self.client.open_android_settings(SECRET.hex())
        self.assertEqual(self.peer.methods, [HELLO, AUTHENTICATE, APP_LAUNCH])

    async def test_settings_launch_failure_not_success(self):
        self.peer.launch_error = True
        await self.client.connect("fake")
        with self.assertRaisesRegex(ProtocolError, "ошибку запуска"):
            await self.client.open_android_settings(SECRET.hex())

    async def test_settings_launch_refused_not_retried(self):
        self.peer.reject_launch = True
        await self.client.connect("fake")
        with self.assertRaises(RemoteError):
            await self.client.open_android_settings(SECRET.hex())
        self.assertEqual(self.peer.methods.count(APP_LAUNCH), 1)

    async def test_launch_allowlist_rejects_other_apps(self):
        await self.client.connect("fake")
        await self.client.authenticate(SECRET.hex())
        with self.assertRaises(ValueError):
            await self.client.request(APP_LAUNCH, encode({1: "another.package"}))
        self.assertNotIn(APP_LAUNCH, self.peer.methods)

    async def test_diagnostics_timeout_is_visible_and_finishes(self):
        await self.client.connect("fake")
        self.client.timeout = 0.08
        self.peer.no_reply = True
        await self.client.diagnose_permission()
        self.assertTrue(any("Запрашиваю: Developer Mode" in line for line in self.logs))
        self.assertTrue(any("ошибка" in line for line in self.logs))
        self.assertTrue(any("Соединение потеряно" in line for line in self.logs))
        self.assertIn("Конец диагностики", self.logs[-1])

    async def test_success_ack_without_state_change_is_not_success(self):
        self.peer.ignore_dev = True
        await self.client.connect("fake")
        with self.assertRaisesRegex(ProtocolError, "не подтверждён"):
            await self.client.enable(SECRET.hex())
        self.assertNotIn(ADB_SET, self.peer.methods)

    async def test_general_status_must_confirm_both(self):
        self.peer.mismatch_status = True
        await self.client.connect("fake")
        with self.assertRaisesRegex(ProtocolError, "общий статус"):
            await self.client.enable(SECRET.hex())
        self.assertFalse(any("ПОДТВЕРЖДЕНО ШЛЕМОМ" in line for line in self.logs))

    async def test_invalid_signature_disconnects(self):
        self.peer.bad_signature = True
        with self.assertRaises(ProtocolError):
            await self.client.connect("fake")
        self.assertFalse(self.peer.is_connected)

    async def test_empty_connect_timeout_has_stage_and_releases_partial_transport(self):
        self.peer.connect = AsyncMock(side_effect=TimeoutError())
        self.peer.disconnect = AsyncMock()
        with self.assertRaisesRegex(ProtocolError, "GATT-служб.*TimeoutError"):
            await self.client.connect("fake")
        self.peer.disconnect.assert_awaited_once()
        self.assertIsNone(self.client.transport)
        self.assertFalse(self.peer.methods)

    async def test_disconnect_error_does_not_hide_connect_error(self):
        self.peer.connect = AsyncMock(side_effect=TimeoutError())
        self.peer.disconnect = AsyncMock(side_effect=RuntimeError("cleanup failed"))
        with self.assertRaisesRegex(ProtocolError, "TimeoutError"):
            await self.client.connect("fake")
        self.assertTrue(any("cleanup failed" in line for line in self.logs))

    async def test_retry_after_failed_connect_uses_fresh_transport(self):
        failed = FakeQuest()
        failed.connect = AsyncMock(side_effect=TimeoutError())
        factory = Mock(side_effect=[failed, self.peer])
        self.client.factory = factory
        with self.assertRaises(ProtocolError):
            await self.client.connect("fake")
        await self.client.connect("fake")
        self.assertTrue(self.client.connected)
        self.assertEqual(factory.call_count, 2)

    async def test_gatt_recovery_rescans_same_address_and_retries_once(self):
        failed = FakeQuest()
        failed.connect = AsyncMock(side_effect=TimeoutError())
        failed.disconnect = AsyncMock()
        fresh = SimpleNamespace(address="test-address")
        self.client.rediscover = AsyncMock(return_value=fresh)
        factory = Mock(side_effect=[failed, self.peer])
        self.client.factory = factory
        await self.client.connect(SimpleNamespace(address="test-address"))
        self.client.rediscover.assert_awaited_once_with("test-address", timeout=10)
        self.assertIs(factory.call_args_list[1].args[0], fresh)
        failed.disconnect.assert_awaited_once()
        self.assertTrue(self.client.connected)
        self.assertEqual(self.peer.methods, [HELLO])

    async def test_recovery_never_switches_to_another_device(self):
        self.peer.connect = AsyncMock(side_effect=TimeoutError())
        self.client.rediscover = AsyncMock(return_value=None)
        with self.assertRaisesRegex(ProtocolError, "больше не обнаруживается"):
            await self.client.connect(SimpleNamespace(address="test-address"))
        self.assertFalse(self.client.connected)

    async def test_windows_recovery_cache_then_uncached_single_service(self):
        failed = FakeQuest()
        failed.connect = AsyncMock(side_effect=TimeoutError())
        factory = Mock(side_effect=[failed, self.peer])
        self.client.factory = factory
        self.client.rediscover = AsyncMock(return_value="fresh-device")
        with patch("client.sys.platform", "win32"):
            await self.client.connect("test-address")
        first, second = factory.call_args_list
        self.assertEqual(first.kwargs["services"], second.kwargs["services"])
        self.assertEqual(len(first.kwargs["services"]), 1)
        self.assertTrue(first.kwargs["winrt"]["use_cached_services"])
        self.assertFalse(second.kwargs["winrt"]["use_cached_services"])

    async def test_changed_ciphertext_disconnects(self):
        await self.client.connect("fake")
        self.peer.tamper = True
        with self.assertRaises(Exception):
            await self.client.status()
        self.assertFalse(self.client.connected)

    async def test_timeout_disconnects_and_does_not_retry(self):
        await self.client.connect("fake")
        self.client.timeout = 0.08
        self.peer.no_reply = True
        with self.assertRaisesRegex(ProtocolError, "Результат.*неизвестен"):
            await self.client.status()
        self.assertFalse(self.client.connected)
        self.assertEqual(self.peer.methods.count(HMD_STATUS), 1)

    async def test_unrelated_sequence_is_not_accepted(self):
        await self.client.connect("fake")
        self.client.timeout = 0.08
        self.peer.reply_sequence = 9999
        with self.assertRaises(ProtocolError):
            await self.client.status()

    async def test_unapproved_methods_never_go_to_transport(self):
        await self.client.connect("fake")
        with self.assertRaises(ValueError):
            await self.client.request(5001)
        self.assertEqual(self.peer.methods, [HELLO])


class CodecTests(unittest.TestCase):
    def test_vivaldi_found_in_standard_install_path(self):
        with patch("login.os.environ", {"LOCALAPPDATA": "C:/TestUser"}), \
                patch("login.sys.platform", "test"), \
                patch("login.shutil.which", return_value=None), \
                patch("login.Path.is_file", return_value=True):
            self.assertTrue(find_vivaldi().replace("\\", "/").endswith(
                "/Vivaldi/Application/vivaldi.exe"))

    def test_no_vivaldi_means_error_not_fallback(self):
        with patch("login.os.environ", {}), patch("login.sys.platform", "test"), \
                patch("login.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "Vivaldi не найден"):
                find_vivaldi()

    def test_known_protobuf_request(self):
        self.assertEqual(encode({1: 1, 2: 6001, 3: 0, 4: encode({1: 1})}).hex(),
                         "080110f12e180022020801")

    def test_roundtrip_fragments_boundaries_and_idle(self):
        for length in (1, 18, 19, 256, 10000):
            payload = bytes(index % 256 for index in range(length))
            decoder = Assembler()
            self.assertIsNone(decoder.feed(b"\xff"))
            results = [decoder.feed(chunk) for chunk in fragments(payload)]
            self.assertEqual(results[-1], payload)
            self.assertTrue(all(item is None for item in results[:-1]))

    def test_out_of_order_rejected(self):
        with self.assertRaises(ProtocolError):
            Assembler().feed(b"\x80\x01x")

    def test_truncated_and_invalid_proto(self):
        for packet in (b"\x08\x80", b"\x12\x05hi", b"\x00", b"\x0b"):
            with self.subTest(packet=packet), self.assertRaises(ProtocolError):
                decode(packet)

    def test_secret_validation(self):
        for value in ("", "g" * 64, "f" * 63):
            with self.assertRaises(ValueError):
                parse_secret(value)

    def test_only_expected_cookie_domain_is_read(self):
        cookie = {"name": "oc_www_at", "domain": "oculus.com.attacker.test", "value": "fake"}
        self.assertIsNone(select_login_token([cookie]))
        cookie["domain"] = ".oculus.com"
        self.assertEqual(select_login_token([cookie]), "fake")

    def test_only_explicit_secret_fields_are_extracted(self):
        value = {"data": [{"device_secret": SECRET.hex()}], "unrelated": "aa" * 32}
        self.assertEqual(find_secrets(value), [SECRET.hex()])

    def test_redirect_does_not_forward_token(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))


if __name__ == "__main__":
    unittest.main()
