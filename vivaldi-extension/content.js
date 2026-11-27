(() => {
  if (window !== window.top || !/^\/[a-f0-9]{64}\/$/.test(location.pathname) ||
      !document.querySelector('meta[name="quest-local-bridge"][content="1"]')) return;
  const button = document.getElementById("use-meta");
  const status = document.getElementById("status");
  if (!button || !status) return;
  button.disabled = false;
  status.textContent = "Расширение подключено. Нажми кнопку, чтобы использовать сохранённую сессию Meta.";
  button.addEventListener("click", async event => {
    if (!event.isTrusted) return;
    button.disabled = true;
    try {
      const result = await chrome.runtime.sendMessage({type: "quest-local-meta-cookie"});
      if (!result?.token) throw new Error(result?.error || "Расширение не ответило.");
      const response = await fetch(location.pathname + "token", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({token: result.token}), credentials: "omit", redirect: "error"
      });
      delete result.token;
      if (!response.ok) throw new Error("Программа не приняла сессию. Повторно нажми «Войти в Meta» в программе.");
      status.textContent = "Сессия передана локальной программе. Результат получения секрета смотри в её окне. Эта вкладка больше не нужна.";
    } catch (error) {
      status.textContent = error.message || "Не удалось передать сессию программе.";
      button.disabled = false;
    }
  });
})();
