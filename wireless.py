"""Verified Quest BLE -> wireless ADB path. No arbitrary shell commands or APK installs."""

import asyncio
from contextlib import asynccontextmanager
import ipaddress
import os
from pathlib import Path
import re
import shutil

from errors import describe_error
from protocol import (HMD_STATUS, ProtocolError, SLEEP_SET, SLEEP_STATUS,
                      WIRELESS_DETAILS, WIRELESS_START, decode, encode)


def find_adb():
    candidates = [shutil.which("adb")]
    for variable in ("PROGRAMFILES", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            candidates.extend([str(Path(base) / "platform-tools" / "adb.exe"),
                               str(Path(base) / "Android" / "Sdk" / "platform-tools" / "adb.exe")])
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise ProtocolError("ADB не найден. Установи Android SDK Platform-Tools и добавь adb в PATH.")


def as_text(value):
    return value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value


def validate_host(value):
    try:
        address = ipaddress.ip_address(as_text(value))
    except (ValueError, TypeError, UnicodeError):
        raise ProtocolError("Шлем не сообщил корректный локальный IPv4-адрес Wi-Fi.") from None
    if (address.version != 4 or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_unspecified or address.is_multicast):
        raise ProtocolError("Допускается только локальный IPv4-адрес выбранного шлема.")
    return str(address)


def valid_port(value):
    return type(value) is int and 1 <= value <= 65535


def connection_endpoint(services, host):
    endpoints = set()
    for line in services.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[-2] != "_adb-tls-connect._tcp":
            continue
        address, _, port = parts[-1].rpartition(":")
        if address == host and port.isascii() and port.isdigit() and valid_port(int(port)):
            endpoints.add(f"{host}:{int(port)}")
    if len(endpoints) > 1:
        raise ProtocolError("Для IP шлема обнаружено несколько портов ADB. Повтори проверку позже.")
    return next(iter(endpoints), None)


SETTINGS_PAGES = {
    "developer": ("android.settings.APPLICATION_DEVELOPMENT_SETTINGS", "Для разработчиков",
                  "com.android.settings/.Settings$DevelopmentSettingsDashboardActivity"),
    "network": ("android.settings.WIRELESS_SETTINGS", "Сеть и интернет",
                "com.android.settings/.Settings$NetworkDashboardActivity"),
}


def settings_activity_visible(dump, component):
    """Require one actual ActivityRecord to be both resumed and visible, not a stale task."""
    full = component.replace("/.", "/com.android.settings.")
    records = re.split(r"(?m)^\s*\* Hist\s+#\d+:", dump)[1:]
    for record in records:
        # Only the first ActivityRecord belongs to this history entry.
        header = record.splitlines()[0] if record.splitlines() else ""
        if not any(re.search(re.escape(value) + r"(?:\s|\})", header)
                   for value in (component, full)):
            continue
        # Stop before the next task/display so its visibility cannot confirm this record.
        record = re.split(r"(?m)^\s*\* (?:Task|ActivityRecord)|^Display #", record)[0]
        if (re.search(r"\bstate=RESUMED\b", record)
                and re.search(r"\bmVisible=true\b", record)):
            return True
    return False


class WirelessADB:
    def __init__(self, log, executable=None, wait=asyncio.sleep):
        self.log = log
        self.executable = executable
        self.wait = wait
        self.target = None

    async def run(self, arguments, *, code=None):
        executable = self.executable or find_adb()
        process = await asyncio.create_subprocess_exec(
            executable, *arguments, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            output, _ = await asyncio.wait_for(
                process.communicate((code + "\n").encode() if code else None), timeout=25)
        except BaseException:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            raise
        result = output.decode("utf-8", errors="replace").strip()
        if code:
            result = result.replace(code, "[код скрыт]")
        if process.returncode:
            # Do not expose unfiltered ADB output; it may contain a pairing code.
            raise ProtocolError(f"ADB завершился с кодом {process.returncode}; операция не подтверждена.")
        return result

    @asynccontextmanager
    async def awake_during_pairing(self, client):
        old = None
        changed = False
        try:
            old = decode(await client.request(SLEEP_STATUS)).get(1)
            if type(old) is int and 0 < old < 900:
                changed = True  # A write may have taken effect even if its reply is lost.
                await client.request(SLEEP_SET, encode({1: 900}))
                actual = decode(await client.request(SLEEP_STATUS)).get(1)
                self.log(f"На время сопряжения таймер сна: {actual} с. Подтверди окно в шлеме.")
            yield
        finally:
            if changed:
                async def restore():
                    try:
                        await client.request(SLEEP_SET, encode({1: old}))
                        actual = decode(await client.request(SLEEP_STATUS)).get(1)
                        if actual != old:
                            raise ProtocolError("Повторное чтение не совпало с исходным значением.")
                        self.log(f"Прежний таймер сна восстановлен: {actual} с.")
                    except Exception as exc:
                        self.log("ВНИМАНИЕ: восстановление таймера сна не подтверждено: " + describe_error(exc))
                task = asyncio.create_task(restore())
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise

    async def discover(self, host):
        return connection_endpoint(await self.run(["mdns", "services"]), host)

    async def connect_endpoint(self, endpoint):
        self.target = None
        await self.run(["connect", endpoint])
        state = await self.run(["-s", endpoint, "get-state"])
        if state.strip() != "device":
            raise ProtocolError("ADB ещё не авторизован. Проверь окно в шлеме.")
        model = await self.run(["-s", endpoint, "shell", "getprop", "ro.product.model"])
        if model.strip() != "Quest 3":
            raise ProtocolError("Модель ADB-устройства не совпадает с проверенным Quest 3.")
        identity = await self.run(["-s", endpoint, "shell", "id"])
        if "uid=2000(shell)" not in identity:
            raise ProtocolError("Ожидаемый доступ ADB shell не подтверждён.")
        self.target = endpoint
        self.log(f"ПОДТВЕРЖДЕНО: беспроводной ADB shell на Quest 3 ({endpoint}).")
        self.log("Доступ ADB shell подтверждён. Само подключение не проверяет режим разработчика или USB-кабель; "
                 "сопряжение ПК сохраняется в стандартных хранилищах ADB.")
        return endpoint

    async def reconnect(self):
        if not self.target:
            raise ProtocolError("Сначала подключи Wi-Fi ADB к выбранному по Bluetooth шлему.")
        previous = self.target
        self.target = None
        host = validate_host(previous.rpartition(":")[0])
        # Ports change after a reboot. Never select another IP from mDNS.
        endpoint = await self.discover(host)
        return await self.connect_endpoint(endpoint or previous)

    async def connect(self, client, secret):
        self.target = None
        # Fail before changing the timer/starting a server if platform-tools is missing.
        if self.executable is None:
            self.executable = find_adb()
        await client.authenticate(secret)
        host = validate_host(decode(await client.request(HMD_STATUS)).get(15))
        self.log(f"Беспроводной ADB: только IP выбранного по BLE шлема {host}.")
        endpoint = await self.discover(host)
        if endpoint:
            try:
                return await self.connect_endpoint(endpoint)
            except ProtocolError:
                self.log("Готовое ADB-соединение не подтверждено. Проверяю сопряжение через BLE…")
        async with self.awake_during_pairing(client):
            details = decode(await client.request(WIRELESS_DETAILS))
            if not valid_port(details.get(2)):
                self.log("Запускаю сервер сопряжения. Если появится запрос в VR — разреши беспроводную отладку.")
                await client.request(WIRELESS_START)
            for attempt in range(60):
                details = decode(await client.request(WIRELESS_DETAILS))
                reported = as_text(details.get(1))
                if reported not in (None, "", host):
                    raise ProtocolError("Адрес сервера сопряжения не совпадает с IP выбранного шлема.")
                code = as_text(details.get(3))
                port = details.get(2)
                if (reported == host and valid_port(port) and isinstance(code, str)
                        and code.isascii() and code.isdigit() and 4 <= len(code) <= 12):
                    break
                code = None
                if attempt % 10 == 0:
                    self.log("Жду разрешение в шлеме и сведения сопряжения (до 2 минут)…")
                await self.wait(2)
            else:
                raise ProtocolError("Сведения сопряжения не получены за 2 минуты. Проверь запрос в VR.")
            try:
                self.log("Выполняю сопряжение ADB. Код передаётся через stdin, не выводится и не сохраняется.")
                result = await self.run(["pair", f"{host}:{port}"], code=code)
                if "Successfully paired" not in result:
                    raise ProtocolError("ADB не подтвердил сопряжение.")
            finally:
                code = None
                details = None
            self.log("Сопряжение принято. Ищу отдельный порт подключения только для IP шлема…")
            for attempt in range(60):
                endpoint = await self.discover(host)
                if not endpoint:
                    details = decode(await client.request(WIRELESS_DETAILS))
                    reported = as_text(details.get(1))
                    if reported not in (None, "", host):
                        raise ProtocolError("Адрес подключения не совпадает с IP выбранного шлема.")
                    if reported == host and valid_port(details.get(4)):
                        endpoint = f"{host}:{details[4]}"
                    details = None
                if endpoint:
                    return await self.connect_endpoint(endpoint)
                if attempt % 10 == 0:
                    self.log("Сопряжение ПК и разрешение отладки в Wi-Fi-сети — разные шаги. "
                             "Разбуди шлем и подтверди запрос отладки для текущей сети. "
                             "Жду отдельный порт ADB до 2 минут; повторный вход Meta пока не нужен.")
                await self.wait(2)
            raise ProtocolError("Сопряжение прошло, но порт ADB не появился. "
                                "Подтверди отладку для Wi-Fi-сети в шлеме и повтори подключение. "
                                "Секрет остаётся в памяти до закрытия программы; повторять вход Meta не нужно.")

    async def status(self):
        if not self.target:
            raise ProtocolError("Сначала подключи беспроводной ADB.")
        await self.reconnect()
        for setting in ("development_settings_enabled", "adb_enabled", "adb_wifi_enabled"):
            value = await self.run(["-s", self.target, "shell", "settings", "get", "global", setting])
            self.log(f"Android {setting}: {value[:20]}")

    async def enable_sidequest(self):
        if not self.target:
            raise ProtocolError("Сначала подключи беспроводной ADB.")
        await self.reconnect()
        self.log("Включаю Android-настройки разработчика и USB ADB через подтверждённый Wi-Fi ADB…")
        for setting in ("development_settings_enabled", "adb_enabled"):
            await self.run(["-s", self.target, "shell", "settings", "put", "global", setting, "1"])
            value = await self.run(["-s", self.target, "shell", "settings", "get", "global", setting])
            self.log(f"Повторное чтение Android {setting}: {value[:20]}")
            if value.strip() != "1":
                raise ProtocolError(f"Android {setting} не подтверждён. Уже применённые изменения не откатывались.")
        self.log("ПОДТВЕРЖДЕНО: Android-настройки разработчика и adb_enabled включены. "
                 "Работу USB-подключения нужно проверить отдельно кабелем к ПК.")

    async def set_keep_awake(self, enabled):
        if not self.target:
            raise ProtocolError("Сначала подключи беспроводной ADB.")
        await self.reconnect()
        action = "prox_close" if enabled else "automation_disable"
        await self.run(["-s", self.target, "shell", "am", "broadcast", "-a",
                        "com.oculus.vrpowermanager." + action])
        state = await self.run(["-s", self.target, "shell", "dumpsys", "vrpowermanager"])
        fields = {}
        for line in state.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        if enabled:
            if (fields.get("Virtual proximity state") != "CLOSE"
                    or fields.get("MountWakeLock count") not in ("1", "2", "3")
                    or fields.get("State") != "HEADSET_MOUNTED"):
                raise ProtocolError("Удержание бодрствования службой Quest не подтверждено.")
            self.log("ПОДТВЕРЖДЕНО: виртуальный датчик CLOSE, Quest HEADSET_MOUNTED, mount wake lock активен. "
                     "Шлем можно снять. Не оставляй его без присмотра; это повышает расход энергии и нагрев.")
        else:
            if fields.get("Virtual proximity state") != "DISABLED":
                raise ProtocolError("Возврат к физическому датчику не подтверждён.")
            self.log("ПОДТВЕРЖДЕНО: виртуальный датчик выключен. Возвращено обычное определение надетого шлема.")
        self.log("Закрытие программы не отменяет эту настройку. Используй «Вернуть обычный сон» "
                 "после работы; после перезапуска шлема проверь состояние заново.")

    async def open_settings(self, page="developer"):
        if page not in SETTINGS_PAGES:
            raise ValueError("Допускаются только разделы разработчика и сети Android Settings.")
        await self.reconnect()
        action, label, expected = SETTINGS_PAGES[page]
        resolved = await self.run(["-s", self.target, "shell", "cmd", "package", "resolve-activity",
                                   "--brief", "-a", action, "-p", "com.android.settings"])
        components = [line.strip() for line in resolved.splitlines()
                      if line.strip().startswith("com.android.settings/")]
        if components != [expected] and components != [expected.replace("/.", "/com.android.settings.")]:
            raise ProtocolError(f"Раздел «{label}» не разрешился в проверенную Activity этой прошивки. "
                                "Запуск не отправлен; компоненты и разрешения не изменялись.")
        self.log(f"Открываю Android Settings → «{label}» через стандартный Intent. "
                 "Переключатели и настройки сна этой кнопкой не меняются.")
        # Use the fixed action, not a shell component containing '$'. No -W: Guardian can queue it.
        result = await self.run(["-s", self.target, "shell", "am", "start", "-a", action,
                                 "-p", "com.android.settings"])
        if any(marker in result.lower() for marker in ("error:", "exception", "permission denial")):
            raise ProtocolError("Android отказал в запуске настроек. Окно не подтверждено.")
        for _ in range(10):
            dump = await self.run(["-s", self.target, "shell", "dumpsys", "activity", "activities"])
            if settings_activity_visible(dump, expected):
                self.log(f"ПОДТВЕРЖДЕНО СИСТЕМОЙ: «{label}» — Activity RESUMED и окно visible=true. "
                         "Посмотри в шлеме: фактическое появление панели подтверждает пользователь.")
                if page == "developer":
                    value = await self.run(["-s", self.target, "shell", "settings", "get", "global",
                                            "development_settings_enabled"])
                    self.log(f"Android development_settings_enabled: {value[:20]}. "
                             "Это не статус аккаунта разработчика Meta и не общий флаг BLE 8001/61.")
                return True
            if "com.oculus.guardian/" in dump and re.search(
                    r"(?:mCurrentFocus|mFocusedApp|topResumedActivity)=[^\n]*com\.oculus\.guardian/", dump):
                self.log("Окно пока не подтверждено: активен Guardian. Безопасно подтверди границу "
                         "в шлеме и нажми кнопку открытия ещё раз. Защита не отключается.")
                return False
            await self.wait(1)
        self.log("Запрос отправлен, но видимая активная Activity не подтверждена. "
                 "Разбуди шлем, проверь диалог Guardian и повтори открытие; успех не заявляется.")
        return False
