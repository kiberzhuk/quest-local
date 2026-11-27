"""Russian desktop UI. All BLE and login work runs on one asyncio worker thread."""

import asyncio
import concurrent.futures
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from client import QuestClient, scan
from errors import describe_error
from login import open_extension_setup, sign_in
from wireless import WirelessADB

VERSION = "0.5.0"


class App:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.loop = asyncio.new_event_loop()
        self.worker = threading.Thread(target=self.run_loop, daemon=True)
        self.worker.start()
        self.client = QuestClient(self.log)
        self.adb = WirelessADB(self.log)
        self.secret = None
        self.devices = []
        self.job = None
        self.closing = False
        self.buttons = []

        root.title(f"Quest Local {VERSION} — ADB и настройки Android")
        root.geometry("960x840")
        root.minsize(700, 560)
        style = ttk.Style(root)
        style.configure("TButton", padding=8)
        style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"))
        panel = ttk.Frame(root, padding=18)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="Quest Local", style="Title.TLabel").pack(anchor="w")
        ttk.Label(panel, text="Беспроводной ADB через авторизацию Bluetooth", font=("Segoe UI", 11)).pack(anchor="w", pady=(2, 12))
        ttk.Label(panel, wraplength=790, text=(
            "Ничего устанавливать в шлем не нужно. На ПК нужен Bluetooth. "
            "На Quest 3 V2.10 проверены Wi-Fi ADB, установка APK и передача файлов в Movies. "
            "Проверено открытие Android → «Для разработчиков». Статус аккаунта Meta этим не меняется; "
            "USB-кабель проверяется отдельно.")
        ).pack(anchor="w", pady=(0, 12))

        account = ttk.LabelFrame(panel, text="1. Аккаунт Meta", padding=10)
        account.pack(fill="x", pady=(0, 10))
        self.button(account, "Войти в Meta", self.login).pack(side="left")
        self.button(account, "Установить расширение", self.extension_setup).pack(side="left", padx=(8, 0))
        self.login_status = ttk.Label(account, text="Вход не выполнен", padding=(12, 0))
        self.login_status.pack(side="left")
        ttk.Label(panel, wraplength=790, text=(
            "Используется основной профиль Vivaldi с сохранённым входом в Meta. "
            "Закрывать Vivaldi не нужно. Один раз загрузи расширение кнопкой выше. "
            "Если сессия истекла, Meta попросит войти снова.")
        ).pack(anchor="w", pady=(0, 12))

        bluetooth = ttk.LabelFrame(panel, text="2. Шлем", padding=10)
        bluetooth.pack(fill="x", pady=(0, 10))
        row = ttk.Frame(bluetooth)
        row.pack(fill="x")
        self.button(row, "Найти Quest", self.find).pack(side="left", padx=(0, 8))
        self.chooser = ttk.Combobox(row, state="readonly")
        self.chooser.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.button(row, "Подключиться", self.connect).pack(side="left")
        ttk.Label(bluetooth, text="Держи шлем включённым, разблокированным и рядом с ПК.").pack(anchor="w", pady=(8, 0))

        actions = ttk.Frame(panel)
        actions.pack(fill="x", pady=(0, 8))
        self.button(actions, "Проверить статус", lambda: self.submit(self.client.status())).pack(side="left", padx=(0, 8))
        self.button(actions, "Включить отладку для SideQuest", self.enable_sidequest).pack(side="left")
        self.button(actions, "Отключиться", lambda: self.submit(self.disconnect())).pack(side="right")
        journal_actions = ttk.Frame(panel)
        journal_actions.pack(fill="x", pady=(0, 8))
        # Copy remains available while Bluetooth/login operations are running.
        ttk.Button(journal_actions, text="Скопировать журнал", command=self.copy_log).pack(side="right")
        wireless = ttk.LabelFrame(panel, text="Проверенный путь: Wi-Fi ADB (ПК и Quest в одной локальной сети)", padding=6)
        wireless.pack(fill="x", pady=(0, 8))
        self.button(wireless, "Подключить Wi-Fi ADB", self.connect_wireless).pack(side="left", padx=(0, 8))
        self.button(wireless, "Проверить ADB", lambda: self.submit(self.adb.status())).pack(side="left")
        self.button(wireless, "Не усыплять снятый шлем", lambda: self.keep_awake(True)).pack(side="left", padx=(8, 0))
        self.button(wireless, "Вернуть обычный сон", lambda: self.keep_awake(False)).pack(side="left", padx=(8, 0))
        settings = ttk.LabelFrame(panel, text="Обычные настройки Android — после подключения Wi-Fi ADB", padding=6)
        settings.pack(fill="x", pady=(0, 8))
        self.button(settings, "Открыть «Для разработчиков»", lambda: self.open_settings("developer")).pack(side="left", padx=(0, 8))
        self.button(settings, "Открыть «Сеть и интернет»", lambda: self.open_settings("network")).pack(side="left")
        self.operation = ttk.Label(panel, text="Готово к работе")
        self.operation.pack(anchor="w", pady=(0, 6))
        self.output = ScrolledText(panel, wrap="word", height=12, font=("Consolas", 10), state="disabled")
        self.output.pack(fill="both", expand=True)
        self.cancel = ttk.Button(panel, text="Отменить текущую операцию", command=self.cancel_job, state="disabled")
        self.cancel.pack(anchor="e", pady=(8, 0))
        self.log(f"Quest Local {VERSION} — Wi-Fi ADB и проверенный запуск раздела «Для разработчиков».")
        self.log("Начни с «Войти в Meta». Также можно сначала найти шлем и проверить доступность BLE.")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.drain)

    def run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
        pending = asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        self.loop.close()

    def button(self, parent, text, command):
        result = ttk.Button(parent, text=text, command=command)
        self.buttons.append(result)
        return result

    def log(self, text):
        self.events.put(("log", text))

    def copy_log(self):
        text = self.output.get("1.0", "end-1c")
        if not text:
            self.operation.configure(text="Журнал пока пуст")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.operation.configure(text="Журнал скопирован — можно вставить в сообщение")
        except tk.TclError:
            self.operation.configure(text="Не удалось открыть буфер обмена. Повтори копирование.")

    def submit(self, coroutine, result=None):
        if self.job and not self.job.done():
            coroutine.close()
            return
        for button in self.buttons:
            button.configure(state="disabled")
        self.cancel.configure(state="normal")
        self.operation.configure(text="Выполняется…")
        self.job = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        self.job.add_done_callback(lambda future: self.events.put(("done", (future, result))))

    def login(self):
        async def task():
            self.secret = None
            self.client.authenticated = False
            return await sign_in(self.log)

        self.login_status.configure(text="Вход не выполнен")
        self.submit(task(), self.logged_in)

    def logged_in(self, secret):
        self.secret = secret
        self.login_status.configure(text="Секрет получен автоматически")

    def extension_setup(self):
        try:
            open_extension_setup()
            self.log("В Vivaldi: включи «Режим разработчика» → «Загрузить распакованное расширение» → "
                     "выбери папку vivaldi-extension из открывшегося Проводника. "
                     "Это режим страницы расширений браузера, не режим разработчика шлема.")
        except (ValueError, OSError) as exc:
            self.log(f"Не удалось открыть установку расширения: {exc}")

    def find(self):
        self.log("Поиск Bluetooth-устройств, около 8 секунд…")
        self.submit(scan(), self.found)

    def found(self, devices):
        self.devices = devices
        labels = [f"{device.name or 'Quest'} — {device.address}" + ("" if advertised else " (BLE-служба не объявлена)")
                  for device, advertised in devices]
        self.chooser.configure(values=labels)
        if devices:
            self.chooser.current(0)
            self.log(f"Найдено устройств: {len(devices)}. Выбери свой шлем и нажми «Подключиться».")
        else:
            self.chooser.set("")
            self.log("Quest не найден. Проверь Bluetooth на ПК, разбуди шлем и повтори поиск. "
                     "Если он занят приложением Horizon на телефоне, закрой приложение и повтори.")

    def connect(self):
        index = self.chooser.current()
        if index < 0 or index >= len(self.devices):
            self.log("Сначала нажми «Найти Quest» и выбери шлем.")
            return
        device = self.devices[index][0]

        async def task():
            await self.client.connect(device)
            await self.client.status()

        self.submit(task())

    def connect_wireless(self):
        if not self.secret or not self.client.connected:
            self.log("Сначала используй «Войти в Meta» и подключись к шлему по Bluetooth.")
            return
        if messagebox.askyesno("Беспроводной ADB", (
                "Разрешить запуск беспроводной отладки и сопряжение этого ПК с выбранным шлемом? "
                "Может появиться окно в VR — его нужно подтвердить. Сопряжение сохраняется. "
                "Во время сопряжения таймер сна временно увеличивается до 15 минут и затем восстанавливается. "
                "APK автоматически не устанавливаются; Developer Mode и USB ADB не изменяются."), parent=self.root):
            self.submit(self.adb.connect(self.client, self.secret))

    def keep_awake(self, enabled):
        if enabled and not messagebox.askyesno("Удержание бодрствования", (
                "Временно включить виртуальный датчик надетого шлема? Это удерживает Quest бодрствующим "
                "после снятия, увеличивает расход энергии и нагрев. Не оставляй шлем без присмотра. "
                "После работы нажми «Вернуть обычный сон». Закрытие программы не отменяет настройку."), parent=self.root):
            return
        self.submit(self.adb.set_keep_awake(enabled))

    def open_settings(self, page):
        if not self.adb.target:
            self.log("Сначала нажми «Подключить Wi-Fi ADB». Затем можно открывать настройки без нового входа Meta.")
            return
        self.submit(self.adb.open_settings(page))

    def enable_sidequest(self):
        if not self.adb.target:
            self.log("Сначала нажми «Подключить Wi-Fi ADB». Для первичного сопряжения нужны вход Meta и Bluetooth.")
            return
        if not messagebox.askyesno("Отладка для SideQuest", (
                "Включить Android-настройки разработчика и USB ADB через Wi-Fi ADB? "
                "Изменения сохраняются. Это разрешает доступ отладки авторизованным ПК. "
                "Полный USB-доступ нужно проверить кабелем к ПК; общий флаг Developer Mode может отличаться."), parent=self.root):
            return

        async def task():
            await self.adb.enable_sidequest()
            if self.client.connected and self.secret:
                await self.client.authenticate(self.secret)
                await self.client.status()

        self.submit(task())

    async def disconnect(self):
        await self.client.disconnect()
        self.log("Bluetooth-соединение закрыто.")

    def cancel_job(self):
        if self.job and not self.job.done():
            self.job.cancel()

    def drain(self):
        if self.closing:
            return
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                future, callback = value
                try:
                    result = future.result()
                    if callback:
                        callback(result)
                except concurrent.futures.CancelledError:
                    self.log("Операция отменена. Если команда уже отправлена шлему, проверь её результат повторным чтением статуса.")
                except Exception as exc:
                    self.log("Ошибка: " + describe_error(exc))
                for button in self.buttons:
                    button.configure(state="normal")
                self.cancel.configure(state="disabled")
                self.operation.configure(text="Готово к работе")
            else:
                self.output.configure(state="normal")
                self.output.insert("end", value + "\n")
                self.output.see("end")
                self.output.configure(state="disabled")
        self.root.after(100, self.drain)

    def close(self):
        self.closing = True
        self.secret = None
        if self.job and not self.job.done():
            self.job.cancel()

        async def shutdown():
            try:
                await self.client.disconnect()
            finally:
                self.loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    application = App(root)
    if "--smoke-test" in sys.argv:
        root.after(500, application.close)
    root.mainloop()
    application.worker.join(timeout=5)
