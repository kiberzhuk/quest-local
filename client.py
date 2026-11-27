"""Local Bluetooth transport; no HTTP, telemetry, credential files or raw packet logs."""

import asyncio
import hashlib
import hmac
import os
import sys

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from nacl.public import Box, PrivateKey, PublicKey
from errors import describe_error

from protocol import (ADB_SET, ADB_STATUS, ALLOWED, APP_LAUNCH, AUTHENTICATE, Assembler,
                      CHARACTERISTIC, DEV_SET, DEV_STATUS, HELLO, HMD_STATUS,
                      HMD_VERSION, LICENSE_DETAILS, ProtocolError, RemoteError, SERVICE,
                      SLEEP_SET, WIRELESS_START, decode,
                      encode, fragments)


def parse_secret(value):
    value = value.strip()
    if len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError("Нужен device_secret: ровно 64 шестнадцатеричных символа.")
    return bytes.fromhex(value)


async def scan():
    found = await BleakScanner.discover(timeout=8, return_adv=True)
    return [(device, SERVICE in [s.lower() for s in advertisement.service_uuids])
            for device, advertisement in found.values()
            if SERVICE in [s.lower() for s in advertisement.service_uuids]
            or any(word in (device.name or "").lower() for word in ("quest", "oculus"))]


def establish_session(body, private_key, challenge):
    hello = decode(body)
    try:
        signed, signature, certificate_der = hello[1], hello[2], hello[3]
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Not RSA")
        public_key.verify(signature, signed + challenge, padding.PKCS1v15(), hashes.SHA256())
        data = decode(signed)
        server_key = data[1]
        if len(server_key) != 32:
            raise ValueError("Invalid server key")
        auth_challenge = data.get(2, b"")
        if not isinstance(auth_challenge, bytes):
            raise ValueError("Invalid challenge")
        box = Box(private_key, PublicKey(server_key))
    except Exception as exc:
        raise ProtocolError("Не удалось проверить подпись или ключ BLE-сессии.") from exc
    # This verifies proof of possession, NOT a Meta certificate chain/identity.
    fingerprint = hashlib.sha256(certificate_der).hexdigest()
    return box, auth_challenge, bool(data.get(3, 0)), fingerprint


class QuestClient:
    def __init__(self, log=lambda message: None, transport_factory=BleakClient, timeout=20,
                 rediscover=None):
        self.log = log
        self.factory = transport_factory
        self.timeout = timeout
        self.rediscover = rediscover
        if self.rediscover is None and transport_factory is BleakClient:
            self.rediscover = BleakScanner.find_device_by_address
        self.transport = None
        self.characteristic = None
        self.box = None
        self.auth_challenge = b""
        self.authenticated = False
        self.sequence = 0
        self.lock = asyncio.Lock()

    @property
    def connected(self):
        return bool(self.transport and self.transport.is_connected and self.box)

    async def connect(self, device):
        await self.disconnect()
        stage = "открытие Bluetooth-соединения и обнаружение GATT-служб"
        try:
            await self.open_transport(device)
            stage = "проверка службы Quest Companion"
            self.log("Bluetooth-соединение открыто. Проверяю службу Quest Companion…")
            service = self.transport.services.get_service(SERVICE)
            if service is None:
                raise ProtocolError("Служба Quest Companion BLE отсутствует. "
                                    "Эта прошивка или устройство не предоставляет нужный интерфейс.")
            self.characteristic = service.get_characteristic(CHARACTERISTIC)
            if self.characteristic is None:
                raise ProtocolError("Не найдена командная характеристика Quest BLE.")
            if "read" not in self.characteristic.properties:
                raise ProtocolError("Командная характеристика недоступна для чтения.")
            private_key = PrivateKey.generate()
            challenge = os.urandom(16)
            body = encode({1: bytes(private_key.public_key), 2: challenge,
                           4: "625733718350566", 5: "5.8.0"})
            stage = "обмен HELLO со шлемом"
            self.log("Служба найдена. Выполняю обмен HELLO…")
            response = await self.request(HELLO, body)
            stage = "проверка подписи BLE-сессии"
            self.box, self.auth_challenge, locked, fingerprint = establish_session(
                response, private_key, challenge)
            self.log("BLE-сессия установлена. SHA-256 сертификата: " + fingerprint)
            self.log("Подпись проверена по сертификату шлема; цепочка доверия Meta не проверяется.")
            if locked:
                self.log("Шлем сообщает о блокировке — разблокируй его внутри VR.")
            if not self.auth_challenge:
                self.log("Шлем не прислал challenge владельца. Изменение настроек заблокировано.")
        except asyncio.CancelledError:
            await self.disconnect()
            raise
        except Exception as exc:
            await self.disconnect()
            raise ProtocolError(f"Подключение не завершено. Этап: {stage}. "
                                + describe_error(exc)) from exc

    async def open_transport(self, device):
        attempts = 2 if self.rediscover else 1
        for attempt in range(attempts):
            if attempt:
                self.log("Восстановление BLE: заново ищу выбранный шлем по его адресу…")
                address = getattr(device, "address", device)
                device = await self.rediscover(address, timeout=10)
                if device is None:
                    raise ProtocolError("Выбранный шлем больше не обнаруживается. "
                                        "Разбуди его и повтори поиск. Другие устройства не выбирались.")
            options = {"timeout": 30}
            if sys.platform == "win32":
                # Do not enumerate every unrelated Quest service and descriptor.
                # First use the existing Windows database; retry reads it afresh.
                options.update(services=[SERVICE], winrt={"use_cached_services": attempt == 0})
            self.log(f"Подключение BLE: попытка {attempt + 1}/{attempts}; "
                     + ("служба Quest из кэша Windows" if attempt == 0 and sys.platform == "win32"
                        else "чтение службы Quest с устройства") + " (до 30 секунд)…")
            self.transport = self.factory(device, **options)
            try:
                async with asyncio.timeout(35):
                    await self.transport.connect()
                return
            except (TimeoutError, BleakError) as exc:
                self.log("Не удалось открыть GATT-соединение: " + describe_error(exc))
                await self.disconnect()
                if attempt + 1 == attempts:
                    raise
                self.log("Освобождаю соединение перед единственной повторной попыткой…")
                await asyncio.sleep(1)

    async def disconnect(self):
        transport, self.transport = self.transport, None
        self.box = None
        self.characteristic = None
        self.auth_challenge = b""
        self.authenticated = False
        self.sequence = 0
        if transport:
            # Failed/partial WinRT connects can own resources even with is_connected=False.
            # Cleanup must not replace the original connect error with a second exception.
            try:
                async with asyncio.timeout(8):
                    await transport.disconnect()
            except Exception as exc:
                self.log("Освобождение Bluetooth-соединения: " + describe_error(exc))

    async def request(self, method, body=None):
        if method not in ALLOWED:
            raise ValueError("Эта команда отсутствует в разрешённом наборе утилиты.")
        async with self.lock:
            if not self.transport or not self.transport.is_connected or self.characteristic is None:
                raise ProtocolError("Сначала подключись к шлему.")
            if method != HELLO and self.box is None:
                raise ProtocolError("Шифрованная сессия не установлена.")
            if method in (DEV_SET, ADB_SET, APP_LAUNCH, SLEEP_SET, WIRELESS_START) and not self.authenticated:
                raise ProtocolError("Сначала требуется авторизация владельца.")
            if method == APP_LAUNCH and body != encode({1: "com.android.settings"}):
                raise ValueError("Допускается запуск только com.android.settings без дополнительных параметров.")
            sequence = self.sequence
            self.sequence += 1
            fields = {1: 1, 2: method, 3: sequence}
            if body is not None:
                fields[4] = body
            packet = encode(fields)
            encrypted = method != HELLO
            if encrypted:
                packet = bytes(self.box.encrypt(packet))
            try:
                async with asyncio.timeout(self.timeout):
                    properties = self.characteristic.properties
                    if "write" in properties:
                        response = True
                    elif "write-without-response" in properties:
                        response = False
                    else:
                        raise ProtocolError("BLE-характеристика не поддерживает запись.")
                    # Conservative 20-byte ATT writes: 2-byte header + 18-byte payload.
                    for chunk in fragments(packet):
                        await self.transport.write_gatt_char(self.characteristic, chunk, response=response)
                    assembler = Assembler()
                    while True:
                        chunk = bytes(await self.transport.read_gatt_char(self.characteristic))
                        message = assembler.feed(chunk)
                        if message is None:
                            await asyncio.sleep(0.02)
                            continue
                        if encrypted:
                            message = self.box.decrypt(message)
                        reply = decode(message)
                        if reply.get(1) != sequence:
                            continue
                        if 2 not in reply or not isinstance(reply[2], int):
                            raise ProtocolError("В ответе нет кода результата.")
                        reply_body = reply.get(3, b"")
                        if not isinstance(reply_body, bytes):
                            raise ProtocolError("Некорректное тело BLE ответа.")
                        if reply[2] != 0:
                            raise RemoteError(method, reply[2], decode(reply_body))
                        return reply_body
            except RemoteError:
                raise
            except TimeoutError as exc:
                await self.disconnect()
                raise ProtocolError("Шлем не ответил вовремя. Соединение закрыто. "
                                    "Результат отправленной команды неизвестен; "
                                    "подключись заново и проверь статус.") from exc
            except BaseException:
                await self.disconnect()
                raise

    async def authenticate(self, secret):
        if self.authenticated:
            return
        if not self.connected or not self.auth_challenge:
            raise ProtocolError("Нет challenge владельца; авторизация недоступна.")
        key = parse_secret(secret)
        proof = hmac.digest(key, self.auth_challenge, "sha256")
        await self.request(AUTHENTICATE, encode({1: proof}))
        self.authenticated = True
        self.log("Авторизация владельца принята шлемом.")

    async def status(self):
        status = decode(await self.request(HMD_STATUS))
        self.log("Developer Mode в общем статусе (8001, поле 61): " + format_flag(status.get(61)))
        self.log("ADB в общем статусе (8001, поле 62): " + format_flag(status.get(62)))
        if self.authenticated:
            try:
                direct = decode(await self.request(DEV_STATUS)).get(1)
                self.log("Прямой статус Developer Mode (6002): " + format_flag(direct))
                if direct is not None and status.get(61) is not None and direct != status[61]:
                    self.log("Показания 6002 и общего флага 8001 расходятся. "
                             "На этой прошивке 6002 читает Android adb_enabled; "
                             "общий флаг сам по себе не доказывает отсутствие ADB-доступа.")
            except RemoteError as exc:
                self.log("Прямой статус Developer Mode: " + str(exc))
        battery = status.get(1)
        if isinstance(battery, int):
            self.log(f"Батарея: {battery}%")
        try:
            version = decode(await self.request(HMD_VERSION))
            for number, label in ((11, "Модель"), (5, "Сборка"), (33, "Incremental"), (34, "Android")):
                value = version.get(number)
                if isinstance(value, bytes):
                    text = value.decode("utf-8", errors="replace")
                    self.log(label + ": " + "".join(c for c in text if c.isprintable())[:300])
        except RemoteError as exc:
            self.log(str(exc))
        return status

    async def enable(self, secret):
        await self.authenticate(secret)
        try:
            await self.request(DEV_SET, encode({1: 1}))
        except RemoteError as exc:
            if exc.code == 19 or exc.code_v2 == 1054:
                self.log(str(exc))
                self.log("Авторизация владельца успешна, но шлем запретил включение Developer Mode. "
                         "На проверенной V2.10 code_v2=1054 означает NOT_DEVELOPER. "
                         "Команда USB ADB не отправлялась. Выполняю только чтение диагностики…")
                await self.diagnose_permission()
                raise ProtocolError("Шлем не разрешил включить режим разработчика. "
                                    "Перезапуск браузера и повторное получение секрета "
                                    "не исправляют этот отказ. Настройки не изменялись этой попыткой.") from exc
            raise
        self.log("Шлем принял команду Developer Mode. Проверяю состояние…")
        dev = decode(await self.request(DEV_STATUS)).get(1)
        if dev != 1:
            raise ProtocolError(f"Режим разработчика не подтверждён: статус={dev}. USB ADB не менялся.")
        await self.request(ADB_SET, encode({1: 1}))
        adb = decode(await self.request(ADB_STATUS)).get(1)
        if adb != 1:
            raise ProtocolError(f"Developer Mode подтверждён, USB ADB не подтверждён: статус={adb}.")
        state = decode(await self.request(HMD_STATUS))
        if state.get(61) != 1 or state.get(62) != 1:
            raise ProtocolError("Ответы отдельных команд положительные, но общий статус "
                                "не подтвердил оба флага. Подключись заново и проверь состояние.")
        self.log("ПОДТВЕРЖДЕНО ШЛЕМОМ: Developer Mode и USB ADB включены.")
        self.log("Подключи USB к ПК и разреши USB-отладку внутри шлема.")

    async def open_android_settings(self, secret):
        await self.authenticate(secret)
        self.log("Эксперимент: запрашиваю запуск установленного com.android.settings (7001). "
                 "Доступ на этой прошивке не подтверждён.")
        body = decode(await self.request(APP_LAUNCH, encode({1: "com.android.settings"})))
        error = body.get(1)
        if error:
            # Do not log arbitrary app response strings that could contain private information.
            raise ProtocolError("Служба приняла запрос, но вернула ошибку запуска настроек Android.")
        self.log("Служба приняла запрос запуска. Посмотри в шлеме: "
                 "только появившееся окно подтверждает, что настройки действительно открылись.")
        self.log("Режим разработчика этой командой НЕ включался.")

    async def enable_usb_only(self, secret):
        await self.authenticate(secret)
        self.log("Эксперимент: одна команда включения USB ADB (6005) без команды Developer Mode. "
                 "Разрешение на этой прошивке не подтверждено.")
        await self.request(ADB_SET, encode({1: 1}))
        self.log("Команда USB ADB принята. Проверяю общий статус (8001), а не неподдерживаемую 6006…")
        state = decode(await self.request(HMD_STATUS))
        self.log("Режим разработчика: " + format_flag(state.get(61)))
        self.log("USB ADB: " + format_flag(state.get(62)))
        if state.get(62) != 1:
            raise ProtocolError("Включение USB ADB не подтверждено общим статусом шлема.")
        self.log("Флаг USB ADB подтверждён шлемом. Подключи USB к ПК и проверь запрос разрешения "
                 "отладки в VR. Доступ к установке APK ещё нужно подтвердить подключением ADB.")

    async def diagnose_permission(self, secret=None):
        self.log("=== Начало диагностики: только чтение, настройки не меняются ===")
        try:
            if not self.connected:
                self.log("Диагностика недоступна: нет соединения со шлемом.")
                return
            if secret and not self.authenticated:
                try:
                    await self.authenticate(secret)
                except Exception as exc:
                    self.log(f"Авторизация для диагностики не удалась: {exc}")
                    return
            if not self.authenticated:
                self.log("Авторизация владельца не выполнена; часть запросов может быть отклонена. "
                         "Для полной проверки сначала используй «Войти в Meta».")
            for method, label in ((DEV_STATUS, "Developer Mode"), (ADB_STATUS, "USB ADB"),
                                  (LICENSE_DETAILS, "Разрешение разработки")):
                if not self.connected:
                    self.log("Соединение потеряно. Оставшиеся запросы не отправлены; подключись заново.")
                    break
                self.log(f"Запрашиваю: {label} (команда {method})…")
                try:
                    details = decode(await self.request(method))
                    if method == LICENSE_DETAILS:
                        if not details:
                            self.log(label + ": ответ пуст, вывод о наличии разрешения сделать нельзя.")
                        else:
                            self.log(label + ": revoked=" + str(details.get(3, "не сообщается"))
                                     + ", issued_time_s=" + str(details.get(2, "не сообщается"))
                                     + ", expiry_time_s=" + str(details.get(1, "не сообщается")))
                            self.log("Наличие этих сведений само по себе не доказывает право включения режима.")
                    else:
                        self.log("Диагностика " + label + ": " + format_flag(details.get(1)))
                except Exception as exc:
                    self.log("Диагностика " + label + ": ошибка — " + str(exc))
        finally:
            self.log("=== Конец диагностики ===")


def format_flag(value):
    return {0: "выключен", 1: "включён"}.get(value, "не сообщается")
