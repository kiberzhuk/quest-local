import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from app import App
from errors import describe_error


class CopyTests(unittest.TestCase):
    def test_empty_error_is_never_blank(self):
        self.assertIn("TimeoutError", describe_error(TimeoutError()))
        self.assertIn("Истекло", describe_error(TimeoutError()))
        self.assertIn("Система не передала", describe_error(Exception()))

    def test_copy_full_journal_without_changing_text(self):
        app = SimpleNamespace(root=Mock(), output=Mock(), operation=Mock())
        app.output.get.return_value = "Строка 1\nСтрока 2"
        App.copy_log(app)
        app.root.clipboard_clear.assert_called_once()
        app.root.clipboard_append.assert_called_once_with("Строка 1\nСтрока 2")
        app.output.delete.assert_not_called()

    def test_clipboard_error_is_displayed(self):
        app = SimpleNamespace(root=Mock(), output=Mock(), operation=Mock())
        app.root.clipboard_clear.side_effect = tk.TclError("busy")
        App.copy_log(app)
        self.assertIn("Не удалось", app.operation.configure.call_args.kwargs["text"])

    def test_open_settings_requires_wireless_target_not_another_login(self):
        app = SimpleNamespace(adb=SimpleNamespace(target=None), log=Mock(), submit=Mock())
        App.open_settings(app, "developer")
        app.submit.assert_not_called()
        self.assertIn("Wi-Fi ADB", app.log.call_args.args[0])

    def test_open_settings_submits_correct_page(self):
        from unittest.mock import AsyncMock
        app = SimpleNamespace(adb=SimpleNamespace(target="selected", open_settings=AsyncMock()),
                              log=Mock(), submit=Mock())
        App.open_settings(app, "developer")
        app.adb.open_settings.assert_called_once_with("developer")
        app.submit.call_args.args[0].close()
