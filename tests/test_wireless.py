import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from protocol import (HMD_STATUS, ProtocolError, SLEEP_SET, SLEEP_STATUS,
                      WIRELESS_DETAILS, WIRELESS_START, decode, encode)
from wireless import (SETTINGS_PAGES, WirelessADB, connection_endpoint,
                      settings_activity_visible, validate_host)


HOST = "10.77.0.42"
ENDPOINT = HOST + ":42489"
MDNS = ("quest _adb-tls-connect._tcp " + ENDPOINT + "\n"
        "other _adb-tls-connect._tcp 10.77.0.99:36487\n")


def activity_dump(component, *, state="RESUMED", visible="true"):
    return (f"  * Task{{test visible=true}}\n"
            f"    topResumedActivity=ActivityRecord{{test u0 {component} t1}}\n"
            f"    * Hist  #0: ActivityRecord{{test u0 {component} t1}}\n"
            f"      state={state} delayedResume=false\n"
            f"      mVisibleRequested=true mVisible={visible} mClientVisible={visible}\n")


class FakeClient:
    def __init__(self):
        self.authenticate = AsyncMock()
        self.calls = []
        self.sleep = 60
        self.started = False
        self.wrong_host = False

    async def request(self, method, body=None):
        self.calls.append((method, body))
        if method == HMD_STATUS:
            return encode({15: HOST})
        if method == SLEEP_STATUS:
            return encode({1: self.sleep})
        if method == SLEEP_SET:
            self.sleep = decode(body)[1]
            return b""
        if method == WIRELESS_START:
            self.started = True
            return b""
        if method == WIRELESS_DETAILS:
            # Regression: connection port is zero when pairing is ready.
            return encode({1: "10.77.0.98" if self.wrong_host else HOST,
                           2: 33485 if self.started else 0, 3: "123456", 4: 0})
        raise AssertionError(method)


class ValidationTests(unittest.TestCase):
    def test_activity_requires_resumed_and_visible_in_same_record(self):
        component = SETTINGS_PAGES["developer"][2]
        self.assertTrue(settings_activity_visible(activity_dump(component), component))
        self.assertTrue(settings_activity_visible(
            activity_dump(component.replace("/.", "/com.android.settings.")), component))
        for dump in (activity_dump(component, state="STOPPED"),
                     activity_dump(component, visible="false"),
                     "mTargetComponent=" + component,
                     activity_dump(component + "Other"),
                     activity_dump(SETTINGS_PAGES["network"][2])):
            self.assertFalse(settings_activity_visible(dump, component))

    def test_unrelated_activity_visibility_cannot_confirm_settings(self):
        component = SETTINGS_PAGES["developer"][2]
        dump = activity_dump(component, state="STOPPED", visible="false")
        dump += activity_dump("com.other/.Activity")
        self.assertFalse(settings_activity_visible(dump, component))

    def test_only_quest_ip_is_selected(self):
        self.assertEqual(connection_endpoint(MDNS, HOST), ENDPOINT)
        self.assertIsNone(connection_endpoint(MDNS, "10.77.0.100"))
        self.assertIsNone(connection_endpoint("quest _adb-tls-pairing._tcp " + ENDPOINT, HOST))

    def test_ambiguous_ports_rejected(self):
        with self.assertRaises(ProtocolError):
            connection_endpoint(MDNS + f"other _adb-tls-connect._tcp {HOST}:42000\n", HOST)

    def test_external_loopback_and_invalid_hosts_rejected(self):
        self.assertEqual(validate_host(HOST.encode()), HOST)
        for value in (None, "8.8.8.8", "127.0.0.1", "0.0.0.0", "::1", "169.254.1.1", "other.test"):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                validate_host(value)


class WirelessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.logs = []
        self.client = FakeClient()
        self.adb = WirelessADB(self.logs.append, executable="test-adb", wait=AsyncMock())

    def responder(self, args, **kwargs):
        if args[0] == "mdns":
            return MDNS
        if args[0] == "connect":
            return "connected to " + ENDPOINT
        if args[0] == "pair":
            self.assertEqual(args, ["pair", HOST + ":33485"])
            self.assertEqual(kwargs["code"], "123456")
            return "Successfully paired"
        if args[-1] == "get-state":
            return "device"
        if args[-1] == "ro.product.model":
            return "Quest 3"
        if args[-1] == "id":
            return "uid=2000(shell) gid=2000(shell)"
        raise AssertionError(args)

    async def test_existing_pair_connects_without_timer_or_server_changes(self):
        self.adb.run = AsyncMock(side_effect=self.responder)
        self.assertEqual(await self.adb.connect(self.client, "fake-secret"), ENDPOINT)
        self.assertEqual(self.client.calls, [(HMD_STATUS, None)])
        self.assertTrue(any("ПОДТВЕРЖДЕНО" in line for line in self.logs))

    async def test_separate_pairing_and_connection_ports_supported(self):
        calls = 0
        def respond(args, **kwargs):
            nonlocal calls
            if args[0] == "mdns":
                calls += 1
                return "" if calls == 1 else MDNS
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        self.assertEqual(await self.adb.connect(self.client, "fake-secret"), ENDPOINT)
        self.assertEqual(self.client.sleep, 60)
        self.assertIn((WIRELESS_START, None), self.client.calls)
        self.assertFalse(any("123456" in line for line in self.logs))
        self.assertEqual([decode(b)[1] for m,b in self.client.calls if m == SLEEP_SET], [900, 60])

    async def test_wrong_host_stops_pairing_and_restores_timer(self):
        self.client.wrong_host = True
        self.adb.run = AsyncMock(return_value="")
        with self.assertRaisesRegex(ProtocolError, "не совпадает"):
            await self.adb.connect(self.client, "fake-secret")
        self.assertEqual(self.client.sleep, 60)
        self.assertFalse(any(call.args[0][0] == "pair" for call in self.adb.run.call_args_list))

    async def test_cancel_pairing_restores_timer(self):
        async def respond(args, **kwargs):
            if args[0] == "pair":
                raise asyncio.CancelledError()
            return ""
        self.adb.run = AsyncMock(side_effect=respond)
        with self.assertRaises(asyncio.CancelledError):
            await self.adb.connect(self.client, "fake-secret")
        self.assertEqual(self.client.sleep, 60)
        self.assertIsNone(self.adb.target)

    async def test_unconfirmed_adb_shell_not_success(self):
        def respond(args, **kwargs):
            if args[-1] == "id":
                return "not a shell"
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        with self.assertRaisesRegex(ProtocolError, "доступ ADB shell"):
            await self.adb.connect_endpoint(ENDPOINT)
        self.assertIsNone(self.adb.target)

    async def test_failed_revalidation_clears_previous_target(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=ProtocolError("disconnected"))
        with self.assertRaises(ProtocolError):
            await self.adb.status()
        self.assertIsNone(self.adb.target)

    async def test_pairing_code_is_stdin_only_and_redacted(self):
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (b"123456 Successfully paired", None)
        with patch("wireless.asyncio.create_subprocess_exec", return_value=process) as spawn:
            result = await self.adb.run(["pair", HOST + ":33485"], code="123456")
        self.assertNotIn("123456", result)
        self.assertNotIn("123456", spawn.call_args.args)
        process.communicate.assert_awaited_once_with(b"123456\n")

    async def test_keep_awake_requires_real_quest_wakelock(self):
        self.adb.target = ENDPOINT
        def respond(args, **kwargs):
            if args[-1] == "vrpowermanager":
                return "Virtual proximity state: CLOSE\nState: HEADSET_MOUNTED\nMountWakeLock count: 1"
            if "broadcast" in args:
                return "Broadcast completed: result=0"
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        await self.adb.set_keep_awake(True)
        self.assertTrue(any("виртуальный датчик CLOSE" in line for line in self.logs))

    async def test_broadcast_success_alone_does_not_confirm_awake(self):
        self.adb.target = ENDPOINT
        def respond(args, **kwargs):
            if args[-1] == "vrpowermanager":
                return "Virtual proximity state: DISABLED\nMountWakeLock count: 0"
            if "broadcast" in args:
                return "Broadcast completed: result=0"
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        with self.assertRaisesRegex(ProtocolError, "не подтверждено"):
            await self.adb.set_keep_awake(True)

    async def test_normal_sensor_restore_is_checked(self):
        self.adb.target = ENDPOINT
        def respond(args, **kwargs):
            if args[-1] == "vrpowermanager":
                return "Virtual proximity state: DISABLED\nMountWakeLock count: 0"
            if "broadcast" in args:
                self.assertEqual(args[-1], "com.oculus.vrpowermanager.automation_disable")
                return "Broadcast completed: result=0"
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        await self.adb.set_keep_awake(False)
        self.assertTrue(any("Возвращено обычное" in line for line in self.logs))

    async def test_sidequest_settings_are_written_and_read_back(self):
        self.adb.target = ENDPOINT
        def respond(args, **kwargs):
            if "settings" in args:
                return "1" if "get" in args else ""
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        await self.adb.enable_sidequest()
        settings_calls = [c.args[0] for c in self.adb.run.call_args_list if "settings" in c.args[0]]
        self.assertEqual([c[4] for c in settings_calls], ["put", "get", "put", "get"])
        self.assertTrue(any("ПОДТВЕРЖДЕНО: Android-настройки" in line for line in self.logs))

    async def test_sidequest_ack_without_readback_is_not_success(self):
        self.adb.target = ENDPOINT
        def respond(args, **kwargs):
            if "settings" in args:
                return "0" if "get" in args else ""
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        with self.assertRaisesRegex(ProtocolError, "не подтверждён"):
            await self.adb.enable_sidequest()
        self.assertFalse(any("ПОДТВЕРЖДЕНО: Android-настройки" in line for line in self.logs))

    def settings_responder(self, *, page="developer", dump=None, resolved=None, start=None):
        action, label, component = SETTINGS_PAGES[page]
        def respond(args, **kwargs):
            if "resolve-activity" in args:
                self.assertIn(action, args)
                return resolved if resolved is not None else component
            if "am" in args and "start" in args:
                self.assertEqual(args, ["-s", ENDPOINT, "shell", "am", "start", "-a", action,
                                        "-p", "com.android.settings"])
                return start if start is not None else "Starting: Intent"
            if "dumpsys" in args:
                return dump if dump is not None else activity_dump(component)
            if "settings" in args:
                self.assertEqual(args[-4:], ["settings", "get", "global", "development_settings_enabled"])
                return "1"
            return self.responder(args, **kwargs)
        return respond

    async def test_developer_settings_uses_fixed_action_and_checks_visibility(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder())
        self.assertTrue(await self.adb.open_settings())
        self.assertTrue(any("ПОДТВЕРЖДЕНО СИСТЕМОЙ" in line for line in self.logs))
        self.assertFalse(any("put" in c.args[0] or "broadcast" in c.args[0]
                             for c in self.adb.run.call_args_list))

    async def test_network_settings_has_separate_action(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder(page="network"))
        self.assertTrue(await self.adb.open_settings("network"))

    async def test_settings_cannot_launch_unknown_page_or_without_target(self):
        self.adb.run = AsyncMock()
        with self.assertRaises(ValueError):
            await self.adb.open_settings("arbitrary")
        with self.assertRaisesRegex(ProtocolError, "Сначала"):
            await self.adb.open_settings()
        self.adb.run.assert_not_awaited()

    async def test_disabled_or_unexpected_settings_activity_not_launched(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder(
            resolved="com.android.settings/.development.DevelopmentSettingsDisabledActivity"))
        with self.assertRaisesRegex(ProtocolError, "не разрешился"):
            await self.adb.open_settings()
        self.assertFalse(any("start" in c.args[0] for c in self.adb.run.call_args_list))

    async def test_guardian_is_reported_without_bypassing_it(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder(
            dump="mFocusedApp=ActivityRecord{test u0 com.oculus.guardian/.Dialog t1}"))
        self.assertFalse(await self.adb.open_settings())
        self.assertTrue(any("активен Guardian" in line for line in self.logs))
        self.assertFalse(any("ПОДТВЕРЖДЕНО СИСТЕМОЙ" in line for line in self.logs))

    async def test_start_ack_and_stale_task_do_not_confirm_window(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder(
            dump=activity_dump(SETTINGS_PAGES["developer"][2], state="STOPPED", visible="false")))
        self.assertFalse(await self.adb.open_settings())
        self.assertFalse(any("ПОДТВЕРЖДЕНО СИСТЕМОЙ" in line for line in self.logs))

    async def test_error_in_success_exit_start_output_not_accepted(self):
        self.adb.target = ENDPOINT
        self.adb.run = AsyncMock(side_effect=self.settings_responder(start="Error: Activity not started"))
        with self.assertRaisesRegex(ProtocolError, "отказал"):
            await self.adb.open_settings()

    async def test_reconnect_discovers_new_port_only_for_original_ip(self):
        self.adb.target = HOST + ":40000"
        self.adb.run = AsyncMock(side_effect=self.responder)
        self.assertEqual(await self.adb.reconnect(), ENDPOINT)
        self.assertIn(["connect", ENDPOINT], [c.args[0] for c in self.adb.run.call_args_list])

    async def test_delayed_connection_uses_ble_port_when_mdns_absent(self):
        original = self.client.request
        detail_count = 0
        async def request(method, body=None):
            nonlocal detail_count
            response = await original(method, body)
            if method == WIRELESS_DETAILS and self.client.started:
                detail_count += 1
                if detail_count >= 4:
                    return encode({1: HOST, 4: 42489})
            return response
        self.client.request = request
        def respond(args, **kwargs):
            if args[0] == "mdns":
                return ""
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        self.assertEqual(await self.adb.connect(self.client, "fake-secret"), ENDPOINT)
        self.assertEqual(self.client.sleep, 60)
        self.assertTrue(any("разные шаги" in line for line in self.logs))

    async def test_connection_timeout_keeps_single_server_start_and_restores_sleep(self):
        def respond(args, **kwargs):
            if args[0] == "mdns":
                return ""
            return self.responder(args, **kwargs)
        self.adb.run = AsyncMock(side_effect=respond)
        with self.assertRaisesRegex(ProtocolError, "порт ADB не появился"):
            await self.adb.connect(self.client, "fake-secret")
        self.assertEqual(self.client.sleep, 60)
        self.assertEqual(self.client.calls.count((WIRELESS_START, None)), 1)
