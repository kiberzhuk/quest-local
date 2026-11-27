"""User-facing exceptions must never turn into an empty journal line."""


def describe_error(exc):
    name = type(exc).__name__
    message = str(exc).strip()
    if not message:
        if isinstance(exc, TimeoutError):
            message = "Истекло время ожидания ответа."
        else:
            message = "Система не передала описание ошибки."
    codes = []
    for attribute in ("winerror", "hresult"):
        code = getattr(exc, attribute, None)
        if code is not None:
            codes.append(f"{attribute}={code}")
    suffix = " (" + ", ".join(codes) + ")" if codes else ""
    return f"{name}: {message}{suffix}"
