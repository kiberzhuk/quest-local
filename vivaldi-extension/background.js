chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (message?.type !== "quest-local-meta-cookie") return;
  let url;
  try { url = new URL(sender.url); } catch { return; }
  if (sender.id !== chrome.runtime.id || sender.frameId !== 0 ||
      url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port ||
      !/^\/[a-f0-9]{64}\/$/.test(url.pathname)) return;
  chrome.cookies.get({url: "https://secure.oculus.com/", name: "oc_www_at"})
    .then(cookie => {
      if (!cookie?.value) respond({error: "Вход Meta не найден. Открой официальный сайт по ссылке ниже, войди и повтори нажатие."});
      else respond({token: cookie.value});
    })
    .catch(() => respond({error: "Vivaldi не разрешил чтение cookie Meta. Проверь разрешения расширения."}));
  return true;
});
