"""Small, bounded protobuf/fragment codec for the Quest companion protocol.

Wire field numbers and methods: ptrpaws/quest-ble-client/protocol.proto.
Only status, authentication, development/ADB setters, a fixed Settings launch,
autosleep configuration and wireless ADB pairing are exposed.
"""

import struct

SERVICE = "0000feb8-0000-1000-8000-00805f9b34fb"
CHARACTERISTIC = "7a442881-509c-47fa-ac02-b06a37d9eb76"
MAX_MESSAGE = 1024 * 1024
HELLO, AUTHENTICATE = 1, 2
DEV_SET, DEV_STATUS, ADB_SET, ADB_STATUS = 6001, 6002, 6005, 6006
HMD_STATUS, HMD_VERSION = 8001, 8002
LICENSE_DETAILS = 16001
APP_LAUNCH = 7001
SLEEP_SET, SLEEP_STATUS, WIRELESS_START, WIRELESS_DETAILS = 6013, 6014, 6018, 6019
ALLOWED = {HELLO, AUTHENTICATE, DEV_SET, DEV_STATUS, ADB_SET, ADB_STATUS,
           HMD_STATUS, HMD_VERSION, LICENSE_DETAILS, APP_LAUNCH,
           SLEEP_SET, SLEEP_STATUS, WIRELESS_START, WIRELESS_DETAILS}
ERROR_NAMES = {1: "BAD_REQUEST", 2: "UNSUPPORTED_METHOD", 5: "AUTHENTICATION_FAILURE",
               8: "USER_PIN_REQUIRED", 19: "OPERATION_NOT_ALLOWED",
               32: "BLE_PAIRING_KEY_REQUIRED", 701: "DEVELOPMENT_LICENSE_DOES_NOT_EXIST",
               801: "GK_CHECK_FAILED"}


class ProtocolError(Exception):
    pass


class RemoteError(ProtocolError):
    def __init__(self, method, response_code, details):
        self.method = method
        self.code = details.get(1)
        self.code_v2 = details.get(5)
        name = ERROR_NAMES.get(self.code, "UNKNOWN_ERROR")
        # Never include arbitrary server debug strings (may contain private data).
        super().__init__(f"Команда {method}: {name}, код={self.code}, "
                         f"code_v2={self.code_v2}, ответ={response_code}.")


def varint(value):
    if value < 0 or value >= 2**64:
        raise ValueError("Unsigned 64-bit integer required")
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _varint(data, offset):
    result = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ProtocolError("Оборванный protobuf varint.")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ProtocolError("Переполнение protobuf varint.")
        result |= (byte & 127) << shift
        if byte < 128:
            return result, offset
    raise ProtocolError("Слишком длинный protobuf varint.")


def encode(fields):
    result = bytearray()
    for number, value in fields.items():
        if not 1 <= number < 2**29:
            raise ValueError("Invalid protobuf field number")
        if isinstance(value, str):
            value = value.encode("utf-8")
        if isinstance(value, bytes):
            result += varint(number << 3 | 2) + varint(len(value)) + value
        else:
            result += varint(number << 3) + varint(value)
    return bytes(result)


def decode(data):
    if len(data) > MAX_MESSAGE:
        raise ProtocolError("Слишком большой protobuf пакет.")
    result, offset = {}, 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number < 2**29:
            raise ProtocolError("Некорректный номер protobuf поля.")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, offset = _varint(data, offset)
            else:
                size = 8 if wire == 1 else 4
            if size > len(data) - offset:
                raise ProtocolError("Оборванное protobuf поле.")
            value = data[offset:offset + size]
            offset += size
        else:
            raise ProtocolError("Неподдерживаемый protobuf wire type.")
        result[number] = value
    return result


def fragments(data, payload_size=18):
    if not data or len(data) > MAX_MESSAGE or payload_size < 1:
        raise ValueError("Invalid fragment input")
    count = (len(data) + payload_size - 1) // payload_size
    if count > 32768:
        raise ValueError("Too many fragments")
    for index in range(count):
        header = index | (0x8000 if index == count - 1 else 0)
        yield struct.pack(">H", header) + data[index * payload_size:(index + 1) * payload_size]


class Assembler:
    def __init__(self):
        self.buffer = bytearray()
        self.next_index = 0

    def feed(self, packet):
        if packet in (b"", b"\xff"):
            return None
        if len(packet) < 2:
            raise ProtocolError("Оборванный BLE фрагмент.")
        header = int.from_bytes(packet[:2], "big")
        if header & 0x7fff != self.next_index:
            raise ProtocolError("Нарушен порядок BLE фрагментов; подключись заново.")
        self.buffer.extend(packet[2:])
        self.next_index += 1
        if len(self.buffer) > MAX_MESSAGE:
            raise ProtocolError("Превышен размер BLE ответа.")
        if header & 0x8000:
            message = bytes(self.buffer)
            self.buffer.clear()
            self.next_index = 0
            return message
        return None
