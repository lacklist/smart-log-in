const API_DEFAULT = "https://api.example.com";
const PBKDF2_ITERATIONS = 310000;
const SERVICE_PERMISSIONS = {
  google: ["https://*.google.com/*", "https://google.com/*"],
  vk: ["https://*.vk.com/*", "https://vk.com/*"],
  mirea: ["https://*.mirea.ru/*", "https://mirea.ru/*"]
};
const COOKIE_ROOTS = { google: ["google.com"], vk: ["vk.com"], mirea: ["mirea.ru"] };
const SERVICE_URLS = {
  google: "https://accounts.google.com/",
  vk: "https://vk.com/",
  mirea: "https://online-edu.mirea.ru/"
};
const SERVICE_NAMES = { google: "Google", vk: "VK", mirea: "СДО МИРЭА" };

const $ = (id) => document.getElementById(id);
const openButton = $("restoreButton");
const clearButton = $("clearButton");
const confirmClear = $("confirmClear");
const statusNode = $("status");
let accessToken = null;
let accountEmail = null;

function showStatus(message, kind = "") {
  statusNode.textContent = message;
  statusNode.className = kind;
}

function showAccount(message, kind = "") {
  $("accountStatus").textContent = message;
  $("accountStatus").className = `small-status ${kind}`;
}

function selectedServices() {
  return [...document.querySelectorAll("[data-service]:checked")].map((input) => input.dataset.service);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function deriveVaultKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSnapshot(snapshot, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(password, salt);
  const plaintext = new TextEncoder().encode(JSON.stringify(snapshot));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    createdAt: new Date().toISOString()
  };
}

async function decryptSnapshot(envelope, password) {
  if (!envelope || envelope.version !== 1 || envelope.kdf !== "PBKDF2-SHA256") {
    throw new Error("Неизвестный формат зашифрованного снимка");
  }
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const key = await deriveVaultKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, base64ToBytes(envelope.ciphertext));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function apiBase() {
  return $("serverUrl").value.trim().replace(/\/+$/, "") || API_DEFAULT;
}

async function ensureServerPermission() {
  const base = new URL(apiBase());
  const local = base.hostname === "localhost" || base.hostname === "127.0.0.1";
  if (base.protocol !== "https:" && !local) throw new Error("Для удалённого сервера требуется HTTPS");
  const pattern = `${base.origin}/*`;
  const current = await chrome.permissions.contains({ origins: [pattern] });
  if (current) return base.href.replace(/\/$/, "");
  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted) throw new Error("Нет разрешения на подключение к серверу кабинета");
  return base.href.replace(/\/$/, "");
}

async function api(path, options = {}) {
  const base = await ensureServerPermission();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(`${base}${path}`, { ...options, headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Ошибка сервера (${response.status})`);
  return body;
}

function setAccount(token, email) {
  accessToken = token;
  accountEmail = email;
  chrome.storage.local.set({ apiBase: apiBase() });
  chrome.storage.session.set({ accessToken, accountEmail });
  showAccount(`Подключено: ${email}`, "success");
}

async function accountAction(action) {
  const email = $("email").value.trim().toLowerCase();
  const password = $("accountPassword").value;
  if (!email || !password) throw new Error("Введи почту и пароль кабинета");
  const inviteCode = $("inviteCode").value;
  const result = await api(`/api/${action}`, {
    method: "POST",
    body: JSON.stringify({ email, password, ...(action === "register" ? { inviteCode } : {}) })
  });
  setAccount(result.token, result.email);
  $("accountPassword").value = "";
  $("inviteCode").value = "";
  showStatus(action === "register" ? "Личный кабинет создан." : "Вход в личный кабинет выполнен.", "success");
}

async function requestServicePermissions(services) {
  const origins = [...new Set(services.flatMap((service) => SERVICE_PERMISSIONS[service]))];
  const granted = await chrome.permissions.request({ origins });
  if (!granted) throw new Error("Нужно разрешить доступ к выбранным сайтам");
}

function cookieBelongsToService(cookie, service) {
  const domain = cookie.domain.replace(/^\./, "");
  return COOKIE_ROOTS[service].some((root) => domain === root || domain.endsWith(`.${root}`));
}

async function readCookies(services) {
  const allCookies = await chrome.cookies.getAll({});
  const included = allCookies.filter((cookie) => services.some((service) => cookieBelongsToService(cookie, service)));
  return included.map(({ name, value, domain, path, secure, httpOnly, sameSite, expirationDate, session, hostOnly, partitionKey }) => ({
    name, value, domain, path, secure, httpOnly, sameSite, expirationDate, session, hostOnly, partitionKey
  }));
}

function cookieUrl(cookie) {
  const host = cookie.domain.replace(/^\./, "");
  return `https://${host}${cookie.path || "/"}`;
}

async function removeCookies(services) {
  const allCookies = await chrome.cookies.getAll({});
  const selected = allCookies.filter((cookie) => services.some((service) => cookieBelongsToService(cookie, service)));
  const results = await Promise.allSettled(selected.map((cookie) => chrome.cookies.remove({
    url: cookieUrl(cookie),
    name: cookie.name,
    storeId: cookie.storeId,
    ...(cookie.partitionKey ? { partitionKey: cookie.partitionKey } : {})
  })));
  return results.filter((result) => result.status === "fulfilled" && result.value).length;
}

async function saveSnapshot() {
  if (!accessToken) throw new Error("Сначала войди в личный кабинет");
  const password = $("masterPassword").value;
  if (password.length < 12) throw new Error("Мастер-пароль должен быть не короче 12 символов");
  const services = selectedServices();
  if (!services.length) throw new Error("Выбери хотя бы один сервис");
  await requestServicePermissions(services);
  const cookies = await readCookies(services);
  if (!cookies.length) throw new Error("Для выбранных сайтов не найдено cookie. Сначала войди в них в этом браузере.");
  const envelope = await encryptSnapshot({ version: 1, services, cookies }, password);
  await api("/api/vault", { method: "PUT", body: JSON.stringify({ envelope }) });
  $("masterPassword").value = "";
  showStatus(`Снимок сохранён в зашифрованном виде (${cookies.length} cookie).`, "success");
}

async function restoreSnapshot() {
  if (!accessToken) throw new Error("Сначала войди в личный кабинет");
  const password = $("masterPassword").value;
  if (!password) throw new Error("Введи мастер-пароль снимка");
  const services = selectedServices();
  if (!services.length) throw new Error("Выбери хотя бы один сервис");
  await requestServicePermissions(services);
  const { envelope } = await api("/api/vault", { method: "GET" });
  const snapshot = await decryptSnapshot(envelope, password);
  const removed = await removeCookies(services);
  const selectedRoots = services.flatMap((service) => COOKIE_ROOTS[service]);
  const snapshotCookies = snapshot.cookies.filter((cookie) => {
    const domain = cookie.domain.replace(/^\./, "");
    return selectedRoots.some((root) => domain === root || domain.endsWith(`.${root}`));
  });
  const results = await Promise.allSettled(snapshotCookies.map((cookie) => {
    const details = {
      url: cookieUrl(cookie),
      name: cookie.name,
      value: cookie.value,
      path: cookie.path || "/",
      secure: Boolean(cookie.secure),
      httpOnly: Boolean(cookie.httpOnly),
      ...(cookie.hostOnly ? {} : { domain: cookie.domain }),
      ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
      ...(cookie.expirationDate && !cookie.session ? { expirationDate: cookie.expirationDate } : {}),
      ...(cookie.partitionKey ? { partitionKey: cookie.partitionKey } : {})
    };
    return chrome.cookies.set(details);
  }));
  const restored = results.filter((result) => result.status === "fulfilled" && result.value).length;
  const failed = results.length - restored;
  $("masterPassword").value = "";
  const opened = [];
  for (const service of services) {
    await chrome.tabs.create({ url: SERVICE_URLS[service], active: false });
    opened.push(SERVICE_NAMES[service]);
  }
  showStatus(`Восстановлено cookie: ${restored}; удалено прежних: ${removed}${failed ? `; не восстановлено: ${failed}` : ""}. Открыты: ${opened.join(", ")}. Сайт может снова запросить подтверждение.`, failed ? "error" : "success");
}

async function clearThisDevice() {
  if (!accessToken) throw new Error("Сначала войди в личный кабинет");
  const services = selectedServices();
  if (!services.length) throw new Error("Выбери хотя бы один сервис");
  await requestServicePermissions(services);
  const removed = await removeCookies(services);
  try { await api("/api/logout", { method: "POST", body: "{}" }); } catch { /* локальную очистку всё равно завершаем */ }
  accessToken = null;
  accountEmail = null;
  await chrome.storage.session.remove(["accessToken", "accountEmail"]);
  showAccount("Личный кабинет отключён на этом устройстве");
  confirmClear.checked = false;
  clearButton.disabled = true;
  showStatus(`Удалено cookie с этого устройства: ${removed}. Зашифрованный снимок в личном кабинете сохранён; удалённый отзыв у сайтов не подтверждён.`, "success");
}

$("registerButton").addEventListener("click", async () => {
  try { await accountAction("register"); } catch (error) { showAccount(error.message, "error"); }
});
$("loginButton").addEventListener("click", async () => {
  try { await accountAction("login"); } catch (error) { showAccount(error.message, "error"); }
});
$("saveButton").addEventListener("click", async () => {
  try { showStatus("Шифрую снимок на этом устройстве…"); await saveSnapshot(); } catch (error) { showStatus(error.message, "error"); }
});
openButton.addEventListener("click", async () => {
  try { showStatus("Подключаю сессии…"); await restoreSnapshot(); } catch (error) { showStatus(error.message, "error"); }
});
confirmClear.addEventListener("change", () => { clearButton.disabled = !confirmClear.checked; });
clearButton.addEventListener("click", async () => {
  if (!confirmClear.checked) return;
  try { showStatus("Очищаю данные текущего устройства…"); await clearThisDevice(); } catch (error) { showStatus(error.message, "error"); }
});

chrome.storage.local.get(["apiBase"], (stored) => {
  $("serverUrl").value = stored.apiBase || API_DEFAULT;
  chrome.storage.session.get(["accessToken", "accountEmail"], (session) => {
    accessToken = session.accessToken || null;
    accountEmail = session.accountEmail || null;
    if (accessToken && accountEmail) showAccount(`Подключено: ${accountEmail}`, "success");
  });
});
