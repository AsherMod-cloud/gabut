// worker.js
// safelinku resolver — full stack (frontend + api) on cloudflare workers

const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function extractCleanUrl(text) {
  if (!text || typeof text !== "string") return "";
  const match = text.match(/https?:\/\/[^\s]+/i);
  let clean = match ? match[0] : text.trim();
  if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
    clean = "https://" + clean;
  }
  return clean;
}

class SimpleCookieJar {
  constructor() {
    this.cookies = new Map();
  }
  setFromResponse(res) {
    let list = [];
    if (typeof res.headers.getSetCookie === "function") {
      list = res.headers.getSetCookie();
    } else {
      const raw = res.headers.get("set-cookie");
      if (raw) list = [raw];
    }
    for (const item of list) {
      if (!item) continue;
      const part = item.split(";")[0].trim();
      const eq = part.indexOf("=");
      if (eq !== -1) {
        const name = part.slice(0, eq).trim();
        const value = part.slice(eq + 1).trim();
        if (name) this.cookies.set(name, value);
      }
    }
  }
  getCookieHeader() {
    const pairs = [];
    for (const [k, v] of this.cookies.entries()) pairs.push(`${k}=${v}`);
    return pairs.join("; ");
  }
  get(name) {
    return this.cookies.get(name);
  }
}

function toHex(buf) {
  const view = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < view.length; i++) {
    out += view[i].toString(16).padStart(2, "0");
  }
  return out;
}

function b64DecodeToUtf8(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str),
  );
  return toHex(buf);
}

async function generateSessionToken(rawXsrfCookie) {
  const unquotedXsrf = decodeURIComponent(rawXsrfCookie);
  const dummyFp = await sha256Hex(
    "webgl:ANGLE (Intel, Intel(R) UHD Graphics Direct3D11)||canvas:abc12345||env:Asia/Jakarta,1920,1080",
  );
  const hashPart = "#" + btoa(dummyFp);
  return unquotedXsrf.slice(0, 128 - hashPart.length) + hashPart;
}

async function fetchHttp(url, options = {}, jar) {
  let currentUrl = url;
  let method = options.method || "GET";
  let data = options.data;
  const baseHeaders = {
    "User-Agent": DEFAULT_UA,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    ...(options.headers || {}),
  };

  const maxHops = 10;
  for (let hop = 0; hop < maxHops; hop++) {
    const headers = { ...baseHeaders };
    const cookieHeader = jar ? jar.getCookieHeader() : "";
    if (cookieHeader) headers["Cookie"] = cookieHeader;

    const res = await fetch(currentUrl, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : data,
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    if (jar) jar.setFromResponse(res);

    const status = res.status;
    const location = res.headers.get("location");

    if (status >= 300 && status < 400 && location) {
      baseHeaders["Referer"] = currentUrl;
      currentUrl = new URL(location, currentUrl).href;
      method = "GET";
      data = undefined;
      continue;
    }

    const text = await res.text();
    return { url: currentUrl, status, headers: res.headers, data: text };
  }
  throw new Error("Too many redirects");
}

function checkBase64Params(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const keys = ["url", "link", "target", "go", "u", "dest"];
    for (const key of keys) {
      const val = parsed.searchParams.get(key);
      if (!val) continue;
      try {
        const decoded = b64DecodeToUtf8(val);
        if (/^https?:\/\//i.test(decoded)) return decoded;
      } catch {}
      if (/^https?:\/\//i.test(val)) return val;
    }
  } catch {}
  return null;
}

async function resolveGateway(html, currentUrl, jar) {
  const formMatch = html.match(
    /<form[^>]+action=["']([^"']+)["'][^>]*>([\s\S]*?)<\/form>/i,
  );
  const rayMatch = html.match(/name=["']ray_id["']\s+value=["']([^"']+)["']/i);
  const aliasMatch = html.match(/name=["']alias["']\s+value=["']([^"']+)["']/i);

  if (!formMatch || !rayMatch || !aliasMatch) return null;

  const actionUrl = formMatch[1];
  const rayId = rayMatch[1];
  const alias = aliasMatch[1];

  const parsedAction = new URL(actionUrl, currentUrl);
  const blogOrigin = `${parsedAction.protocol}//${parsedAction.host}`;
  const redirectUrl = `${blogOrigin}/redirect.php?ray_id=${encodeURIComponent(
    rayId,
  )}&alias=${encodeURIComponent(alias)}`;

  const r2 = await fetchHttp(
    redirectUrl,
    { headers: { Referer: currentUrl } },
    jar,
  );
  const step1PageUrl = r2.url;

  const xsrf1 = jar.get("XSRF-TOKEN");
  if (!xsrf1) return null;

  const tokenPayload1 = await generateSessionToken(xsrf1);
  const sessionHeaders = {
    Origin: blogOrigin,
    Referer: step1PageUrl,
    "Content-Type": "application/json",
    Accept: "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
  };

  const sessionRes1 = await fetchHttp(
    `${blogOrigin}/api/session`,
    {
      method: "POST",
      headers: sessionHeaders,
      data: JSON.stringify({ _token: tokenPayload1 }),
    },
    jar,
  );

  let sessionData1 = {};
  try {
    sessionData1 = JSON.parse(sessionRes1.data);
  } catch {}

  const step = sessionData1.step || 1;
  let step2PageUrl = step1PageUrl;

  if (step === 1) {
    await sleep(800);
    const verifyRes = await fetchHttp(
      `${blogOrigin}/api/verify`,
      {
        method: "POST",
        headers: sessionHeaders,
        data: JSON.stringify({ _a: 0, captcha: null, passcode: null }),
      },
      jar,
    );

    let verifyData = {};
    try {
      verifyData = JSON.parse(verifyRes.data);
    } catch {}

    let target = verifyData.target || "/redirect.php";
    if (target.startsWith("/")) target = `${blogOrigin}${target}`;

    const r3 = await fetchHttp(
      target,
      { headers: { Referer: step1PageUrl } },
      jar,
    );
    step2PageUrl = r3.url;

    const xsrf2 = jar.get("XSRF-TOKEN") || xsrf1;
    sessionHeaders["Referer"] = step2PageUrl;
    await fetchHttp(
      `${blogOrigin}/api/session`,
      {
        method: "POST",
        headers: sessionHeaders,
        data: JSON.stringify({ _token: await generateSessionToken(xsrf2) }),
      },
      jar,
    );
  }

  await sleep(1500);
  const key = 500;
  const size = `${(1920 + key) * 2}.${(1080 + key) * 2}`;

  sessionHeaders["Referer"] = step2PageUrl;
  const goRes = await fetchHttp(
    `${blogOrigin}/api/go`,
    {
      method: "POST",
      headers: sessionHeaders,
      data: JSON.stringify({ key, size }),
    },
    jar,
  );

  let goData = {};
  try {
    goData = JSON.parse(goRes.data);
  } catch {
    return null;
  }

  let readyUrl = goData.url;
  if (!readyUrl) return null;
  if (!/^https?:\/\//i.test(readyUrl)) {
    readyUrl = new URL(readyUrl, blogOrigin).href;
  }

  const rReady = await fetchHttp(
    readyUrl,
    { headers: { Referer: step2PageUrl } },
    jar,
  );
  const htmlReady =
    typeof rReady.data === "string" ? rReady.data : JSON.stringify(rReady.data);

  const destMatch = htmlReady.match(
    /window\.location\.href\s*=\s*["']([^"']+)["']/i,
  );
  if (destMatch) {
    return destMatch[1].replace(/\\\//g, "/").replace(/\\u0026/g, "&");
  }

  return readyUrl;
}

async function scrape(url, options = {}) {
  try {
    if (!url || typeof url !== "string") throw new Error("Invalid URL.");
    const initialUrl = extractCleanUrl(url);
    const autoResolve = options.autoResolve !== false;

    const b64Check = checkBase64Params(initialUrl);
    if (b64Check) {
      return {
        status: true,
        result: {
          title: "Safelinku Destination Link",
          originalUrl: initialUrl,
          destinationUrl: b64Check,
          url: b64Check,
          downloads: [
            { type: "link", quality: "Direct Link", url: b64Check },
          ],
        },
      };
    }

    const jar = new SimpleCookieJar();
    const visited = new Set();
    let currentUrl = initialUrl;
    const maxChain = 8;

    for (let hop = 0; hop < maxChain; hop++) {
      if (visited.has(currentUrl)) break;
      visited.add(currentUrl);

      const res = await fetchHttp(currentUrl, {}, jar);
      currentUrl = res.url;
      const html = typeof res.data === "string" ? res.data : "";

      if (
        html.includes('name="ray_id"') ||
        html.includes("name='ray_id'") ||
        html.includes("redirect.php")
      ) {
        const resolved = await resolveGateway(html, currentUrl, jar);
        if (resolved && resolved !== currentUrl) {
          currentUrl = resolved;
          break;
        }
      }

      const metaRefresh = html.match(
        /<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"']+)["']/i,
      );
      if (metaRefresh && metaRefresh[1]) {
        currentUrl = new URL(metaRefresh[1].trim(), currentUrl).href;
        continue;
      }

      const scriptRedirect = html.match(
        /window\.location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i,
      );
      if (
        scriptRedirect &&
        scriptRedirect[1] &&
        scriptRedirect[1] !== currentUrl
      ) {
        currentUrl = scriptRedirect[1].replace(/\\\//g, "/");
        continue;
      }

      break;
    }

    if (currentUrl === initialUrl) {
      throw new Error("Could not resolve Safelinku destination URL.");
    }

    return {
      status: true,
      result: {
        title: "Safelinku Destination Link",
        originalUrl: initialUrl,
        destinationUrl: currentUrl,
        url: currentUrl,
        downloads: [{ type: "link", quality: "Direct Link", url: currentUrl }],
      },
    };
  } catch (error) {
    return { status: false, message: error.message };
  }
}

// ---------------- frontend ----------------
const HTML = /* html */ `<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>safelinku resolver</title>
<style>
  :root{
    --bg:#0b0d10;--panel:#11151a;--panel2:#161b22;--border:#232a34;
    --text:#e6edf3;--muted:#8b949e;--accent:#7ee787;--accent2:#58a6ff;--err:#ff7b72;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    background:radial-gradient(1200px 600px at 20% -10%,#15202b 0%,transparent 60%),var(--bg);
    color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px;
  }
  .card{
    width:100%;max-width:720px;background:var(--panel);border:1px solid var(--border);
    border-radius:16px;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.5);
  }
  h1{margin:0 0 4px;font-size:18px;letter-spacing:.5px}
  h1 span{color:var(--accent)}
  p.sub{margin:0 0 20px;color:var(--muted);font-size:12px}
  .row{display:flex;gap:10px}
  input[type=text]{
    flex:1;background:var(--panel2);border:1px solid var(--border);color:var(--text);
    padding:12px 14px;border-radius:10px;font:inherit;outline:none;transition:border .15s;
  }
  input[type=text]:focus{border-color:var(--accent2)}
  button{
    background:var(--accent);color:#04160a;border:none;padding:12px 18px;border-radius:10px;
    font:inherit;font-weight:700;cursor:pointer;transition:transform .1s,opacity .15s;
  }
  button:hover{opacity:.9}
  button:active{transform:scale(.97)}
  button:disabled{opacity:.5;cursor:not-allowed}
  .out{margin-top:20px;display:none}
  .out.show{display:block}
  .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
  .box{
    background:var(--panel2);border:1px solid var(--border);border-radius:10px;
    padding:12px 14px;word-break:break-all;font-size:13px;margin-bottom:14px;
  }
  .box.ok{border-color:#1f6f3f}
  .box.err{border-color:#7a2e2a;color:var(--err)}
  a.link{color:var(--accent2);text-decoration:none}
  a.link:hover{text-decoration:underline}
  .flex{display:flex;gap:8px;flex-wrap:wrap}
  .chip{
    background:var(--panel2);border:1px solid var(--border);color:var(--muted);
    font-size:11px;padding:6px 10px;border-radius:999px;cursor:pointer;
  }
  .chip:hover{color:var(--text);border-color:var(--accent2)}
  .status{font-size:11px;color:var(--muted);margin-top:10px}
  .spinner{
    display:inline-block;width:12px;height:12px;border:2px solid var(--muted);
    border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;
    vertical-align:-2px;margin-right:6px;
  }
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <h1><span>//</span> safelinku resolver</h1>
  <p class="sub">paste safelinku url → resolve ke destination. powered by cloudflare workers.</p>

  <form id="f" class="row" autocomplete="off">
    <input id="url" type="text" placeholder="https://safelinku.com/xxxx" required />
    <button id="btn" type="submit">resolve</button>
  </form>

  <div class="flex" style="margin-top:10px">
    <span class="chip" data-u="https://safelinku.com/">safelinku.com</span>
    <span class="chip" data-u="https://sfl.gl/">sfl.gl</span>
  </div>

  <div id="status" class="status"></div>

  <div id="out" class="out">
    <div class="label">original</div>
    <div id="orig" class="box"></div>
    <div class="label">destination</div>
    <div id="dest" class="box ok"></div>
    <div class="label">actions</div>
    <div class="flex">
      <button id="copy" type="button">copy url</button>
      <button id="open" type="button">open</button>
    </div>
  </div>
</div>

<script>
  const $ = (id) => document.getElementById(id);
  const f = $("f"), input = $("url"), btn = $("btn"), status = $("status");
  const out = $("out"), orig = $("orig"), dest = $("dest");
  const copyBtn = $("copy"), openBtn = $("open");
  let lastUrl = "";

  document.querySelectorAll(".chip").forEach((c) => {
    c.addEventListener("click", () => {
      input.value = c.dataset.u;
      input.focus();
    });
  });

  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    btn.disabled = true;
    out.classList.remove("show");
    status.innerHTML = '<span class="spinner"></span>resolving... (bisa 5-15 detik)';

    try {
      const res = await fetch("/api/resolve?url=" + encodeURIComponent(url));
      const data = await res.json();
      if (!data.status) {
        status.textContent = "gagal: " + (data.message || "unknown error");
        out.classList.remove("show");
        return;
      }
      status.textContent = "";
      lastUrl = data.result.destinationUrl;
      orig.textContent = data.result.originalUrl;
      dest.innerHTML =
        '<a class="link" href="' + lastUrl + '" target="_blank" rel="noopener">' +
        lastUrl + "</a>";
      out.classList.add("show");
    } catch (err) {
      status.textContent = "error: " + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  copyBtn.addEventListener("click", async () => {
    if (!lastUrl) return;
    await navigator.clipboard.writeText(lastUrl);
    copyBtn.textContent = "copied!";
    setTimeout(() => (copyBtn.textContent = "copy url"), 1200);
  });

  openBtn.addEventListener("click", () => {
    if (lastUrl) window.open(lastUrl, "_blank", "noopener");
  });
</script>
</body>
</html>`;

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
};

export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    if (pathname === "/api/resolve") {
      let target = searchParams.get("url");

      if (!target && request.method === "POST") {
        try {
          const body = await request.json();
          target = body.url;
        } catch {}
      }

      if (!target) {
        return new Response(
          JSON.stringify({ status: false, message: "missing url param" }),
          {
            status: 400,
            headers: { "content-type": "application/json", ...CORS },
          },
        );
      }

      const result = await scrape(target, { autoResolve: false });
      return new Response(JSON.stringify(result), {
        headers: { "content-type": "application/json; charset=utf-8", ...CORS },
      });
    }

    if (pathname === "/" || pathname === "/index.html") {
      return new Response(HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("not found", { status: 404 });
  },
};

export { scrape };