"""Open regular Vivaldi tabs; a user-installed extension provides the Meta token."""

import asyncio
import os
from pathlib import Path
import shutil
import subprocess
import sys
from bridge import LoginBridge
from meta_secret import retrieve

LOGIN_URL = "https://secure.oculus.com/"


def find_vivaldi():
    candidates = []
    for variable in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        base = os.environ.get(variable)
        if base:
            candidates.append(Path(base) / "Vivaldi" / "Application" / "vivaldi.exe")
    if sys.platform == "win32":
        import winreg

        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\App Paths\vivaldi.exe",
                                        0, winreg.KEY_READ | view) as key:
                        path, _ = winreg.QueryValueEx(key, None)
                        candidates.append(Path(os.path.expandvars(path.strip('"'))))
                except OSError:
                    pass
    from_path = shutil.which("vivaldi.exe")
    if from_path:
        candidates.append(Path(from_path))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise ValueError("Vivaldi не найден. Установи Vivaldi и повтори вход. "
                     "Другие браузеры программа запускать не будет.")


def select_login_token(cookies):
    for cookie in cookies:
        # Reject look-alike domains and unrelated cookies.
        if (cookie.get("name") == "oc_www_at"
                and cookie.get("domain", "").lstrip(".").lower() in
                {"secure.oculus.com", "oculus.com"}
                and cookie.get("value")):
            return cookie["value"]
    return None


async def sign_in(log):
    executable = find_vivaldi()
    async with LoginBridge() as bridge:
        subprocess.Popen([executable, "--new-tab", bridge.url])
        log("Открыта обычная вкладка Vivaldi. Браузер и фоновые процессы закрывать не нужно.")
        log("Во вкладке нажми «Использовать вход Meta». Для первого запуска установи расширение кнопкой в программе.")
        try:
            token = await asyncio.wait_for(asyncio.shield(bridge.token), timeout=300)
        except TimeoutError:
            raise ValueError("Вход не получен за 5 минут. Проверь расширение Quest Local "
                             "и нажми «Использовать вход Meta» в локальной вкладке.") from None
        log("Сессия получена из Vivaldi. Запрашиваю device_secret напрямую у Meta…")
        try:
            secret = await asyncio.to_thread(retrieve, token)
        finally:
            token = None
        log("Секрет получен автоматически. Vivaldi остаётся открытым.")
        return secret


def open_extension_setup():
    executable = find_vivaldi()
    subprocess.Popen([executable, "--new-tab", "vivaldi://extensions"])
    os.startfile(str(Path(__file__).resolve().parent / "vivaldi-extension"))
