"""Optional direct request to Meta. No browser access, redirects or credential storage."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "https://graph.oculus.com/graphql"
DOCUMENT = "7400628006644133"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def find_secrets(value):
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if key == "device_secret" and isinstance(item, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item):
                    found.add(item.lower())
                else:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return sorted(found)


def retrieve(cookie):
    cookie = cookie.strip()
    if not cookie or "\n" in cookie or "\r" in cookie:
        raise ValueError("Вставь только значение cookie oc_www_at.")
    payload = urllib.parse.urlencode({"access_token": cookie, "doc_id": DOCUMENT}).encode("utf-8")
    request = urllib.request.Request(ENDPOINT, data=payload, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "QuestLocal/0.1"})
    # Disable proxy environment variables to avoid forwarding credentials through a configured proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=25) as response:
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError(f"Meta вернула HTTP {exc.code}. Ответ не записан. "
                         "Перенаправления запрещены; токен дальше не отправлялся.") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ValueError("Не удалось связаться с graph.oculus.com. Проверь сеть. "
                         "Запрос не повторялся автоматически.") from None
    if len(body) > 1024 * 1024:
        raise ValueError("Слишком большой ответ Meta; обработка остановлена.")
    try:
        document = json.loads(body.removeprefix(b"for (;;);"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Meta вернула не JSON. Ответ не сохранён.") from None
    secrets = find_secrets(document)
    if len(secrets) != 1:
        raise ValueError("Meta не вернула единственный device_secret "
                         f"(найдено: {len(secrets)}). Текущий API может не поддерживать этот запрос.")
    return secrets[0]
