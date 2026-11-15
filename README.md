# Aral Pars

**Aral Pars** — پنل پروکسی سبک و سریع با **معماری تک‌پورت**؛ همهٔ کانفیگ‌ها روی همان یک پورتی که سرور به شما داده کار می‌کنند. طراحی‌شده برای هاست‌های رایگان/ارزان (مثل Pterodactyl) با Node.js 18+.

پروتکل‌های پشتیبانی‌شده (همه روی یک پورت واحد):

| کانفیگ | سازگاری کلاینت‌ها |
|---|---|
| VLESS-WS / VLESS-WS-TLS | همهٔ کلاینت‌ها |
| VMess-WS / VMess-WS-TLS | همهٔ کلاینت‌ها |
| Trojan-WS / Trojan-WS-TLS | همهٔ کلاینت‌ها (Clash: فقط Trojan-WS-TLS) |
| VLESS / VMess / Trojan HTTPUpgrade | Xray و sing-box (Clash: فقط VLESS و VMess) |
| VLESS-gRPC / VLESS-gRPC-TLS | Xray، sing-box، Clash Meta |
| Shadowsocks-WS | Xray، sing-box، Clash Meta (v2ray-plugin websocket) |
| VLESS-XHTTP | فقط کلاینت‌های Xray (v2rayN، v2rayNG، Hiddify با هستهٔ Xray) |

موتورها: **sing-box** و **Xray-core** — در اولین اجرا خودکار از گیت‌هاب دانلود می‌شوند (به دانلود چند لحظه فرصت بدهید).

## نصب روی هاست رایگان (Pterodactyl)

1. یک سرور **Node.js** بسازید (Node 18 یا بالاتر؛ 20 توصیه می‌شود).
2. در **File Manager** همهٔ فایل‌های پروژه را آپلود کنید: `index.js`، `package.json`، `lib/`، `public/` و `scripts/` (در صورت نیاز). پوشهٔ `node_modules` را آپلود نکنید؛ خودش نصب می‌شود.
3. Startup file: `index.js` (دستور اجرا: `node index.js`).
4. سرور را استارت کنید. پورت پنل به‌صورت خودکار از `SERVER_PORT` / `PORT` خوانده می‌شود؛ نیازی به تنظیم نیست.
5. در اولین استارت، پنل **sing-box** و **Xray-core** را از گیت‌هاب دانلود می‌کند؛ یک دقیقه صبر کنید.
6. `http://<server-ip>:<port>/aral` را باز کنید و **رمز عبور پنل** را بسازید.
7. کانفیگ‌ها یا لینک سابسکریپشن را در کلاینت کپی کنید.

## نصب روی سرور اختصاصی / VPS

```bash
git clone <repo> aral-pars && cd aral-pars
npm install
PORT=8080 node index.js
```

## ⚠️ پوشهٔ `aral-data/` را نگه دارید

این پوشه رمز پنل، UUID، گواهی TLS و تنظیمات شما را نگه می‌دارد. اگر حذفش کنید همهٔ کانفیگ‌ها و پین TLS تغییر می‌کنند و باید دوباره سابسکریپشن را ایمپورت کنید.

ساختار پوشهٔ داده:

```
aral-data/
├── state.json       # UUID و لینک‌های ذخیره‌شده
├── auth.json        # رمز پنل (scrypt) + توکن سابسکریپشن
├── settings.json    # تنظیمات پنل (دامنه، پروتکل‌ها، SS)
├── traffic.json     # شمارندهٔ ترافیک
├── cert/            # گواهی self-signed TLS
├── bin/             # باینری sing-box و Xray
├── sing-box.json / sing-box.log
└── xray.json / xray.log
```

## تنظیمات (متغیرهای محیطی — همگی اختیاری)

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `UUID` | تصادفی، ذخیره در `aral-data` | UUID ثابت برای همهٔ کانفیگ‌ها |
| `PANEL_PASSWORD` | — | رمز ثابت پنل (۸+ کاراکتر) |
| `SUB_TOKEN` | تصادفی | توکن ثابت سابسکریپشن |
| `DOMAIN` | آی‌پی سرور | دامنه یا هاست استفاده‌شده در لینک‌ها |
| `ENABLE_VLESS_WS` / `ENABLE_VLESS_WS_TLS` | `true` | کانفیگ‌های VLESS-WS |
| `ENABLE_VMESS_WS` / `ENABLE_VMESS_WS_TLS` | `true` | کانفیگ‌های VMess-WS |
| `ENABLE_TROJAN_WS` / `ENABLE_TROJAN_WS_TLS` | `true` | کانفیگ‌های Trojan-WS |
| `ENABLE_HTTPUPGRADE` / `ENABLE_VMESS_HTTPUPGRADE` / `ENABLE_TROJAN_HTTPUPGRADE` | `true` | کانفیگ‌های HTTPUpgrade |
| `ENABLE_VLESS_GRPC` / `ENABLE_VLESS_GRPC_TLS` | `true` | کانفیگ‌های gRPC |
| `ENABLE_SS_WS` | `true` | Shadowsocks-WS |
| `ENABLE_XHTTP` | `true` | VLESS-XHTTP |
| `SS_METHOD` / `SS_PASSWORD` | `aes-256-gcm` / تصادفی | رمزنگاری و رمز Shadowsocks (برای cipherهای 2022 باید کلید base64 باشد) |
| `LINK_ALLOW_INSECURE` | `true` | `false` حذف `allowInsecure=1` از لینک‌ها |

غیرفعال‌کردن یک کانفیگ: متغیر آن را `false` بگذارید و سرور را ری‌استارت کنید. (از خود پنل هم می‌توانید سوئیچ‌ها را تغییر دهید؛ با ری‌استارت اعمال می‌شود.)

## TLS

- کانفیگ‌های TLS از گواهی **self-signed** استفاده می‌کنند.
- لینک‌ها `allowInsecure=1` (کلاینت‌های قدیمی) و `pcs=<sha256>` (پین گواهی برای Xray 26.2+) دارند.
- گواهی قبل از انقضا خودکار تمدید می‌شود؛ در آن صورت سابسکریپشن را دوباره ایمپورت کنید.

## عیب‌یابی

- **لینک‌های XHTTP یا Shadowsocks نیست:** دانلود Xray ناموفق بوده. کنسول را ببینید و سرور را ری‌استارت کنید.
- **کانفیگ TLS در کلاینت جدید Xray وصل نمی‌شود:** سابسکریپشن را دوباره ایمپورت کنید تا پین `pcs=` تازه شود.
- **کانفیگ‌ها بعد از ری‌استارت عوض شدند:** پوشهٔ `aral-data/` پاک شده. برای ثابت‌ماندن، `UUID` و `PANEL_PASSWORD` و `SUB_TOKEN` را به‌عنوان متغیر تنظیم کنید.
- **تست اتصال:** از **Real delay** یا URL-Test استفاده کنید، نه TCP ping.
- **لینک سابسکریپشن را محرمانه نگه دارید؛** توکن شما داخلش است.

## ساختار پروژه

```
aral-pars/
├── index.js                 # نقطهٔ ورود: boot، ترتیب استارت ماژول‌ها
├── package.json
├── lib/
│   ├── constants.js         # برند، مسیرها، توابع مشترک
│   ├── logger.js            # لاگ رنگی کنسول
│   ├── settings.js          # تنظیمات runtime (settings.json)
│   ├── state.js             # state.json (UUID و…)
│   ├── traffic.js           # شمارش ترافیک per-protocol
│   ├── ports.js             # تخصیص پورت محلی
│   ├── cert.js              # گواهی self-signed (openssl یا pure-JS)
│   ├── binaries.js          # دانلود/به‌روزرسانی sing-box و Xray
│   ├── tls-sni.js           # پارسر ClientHello (SNI/ALPN)
│   ├── engines/
│   │   ├── singbox.js       # اینباند‌های sing-box روی 127.0.0.1
│   │   └── xray.js          # اینباند‌های XHTTP و Shadowsocks-WS
│   ├── mux/
│   │   └── tcp-router.js    # مالتی‌پلکسر تک‌پورت (TLS/ALPN/h2c + upgradeها)
│   └── panel/
│       ├── http-panel.js    # اکسپرس: ورود، APIها، سابسکریپشن‌ها
│       └── links.js         # تولید لینک‌ها و سابسکریپشن‌ها
├── public/                  # UI (RTL فارسی، تم Barberry Gold)
│   ├── index.html           # صفحهٔ اصلی پنل
│   ├── login.html           # صفحهٔ ورود
│   ├── app.js               # منطق کلاینت پنل
│   └── assets/              # CSS، بته‌جقه، لوگو
└── scripts/                 # ابزارهای توسعه (ساخت دارایی‌ها)
```

## معماری تک‌پورت (خلاصه)

روتر TCP روی پورت عمومی به‌ازای هر اتصال، بایت‌های اول را بررسی می‌کند:

- **TLS ClientHello** → اگر ALPN فقط `h2` باشد (کلاینت gRPC) → اینباند gRPC-TLS در sing-box؛ در غیر این صورت → سرور HTTPS داخلی Node که TLS را تمام می‌کند و پنل/سابسکریپشن/WS/HTTPUpgrade/XHTTP را روی ALPN `http/1.1` سرو می‌کند (و مسیرهای gRPC را با روتر h2 به sing-box می‌رساند).
- **پری‌فیس HTTP/2 رمزنشده** (`PRI * HTTP/2.0`) → VLESS-gRPC روی h2c.
- **HTTP ساده** → اکسپرس پنل + آپگریدهای WS بر اساس مسیر (مسیریابی دقیق با طول مسیر، برای تفکیک `vmess` و `vmess-hu`).

همهٔ اینباند‌های داخلی فقط روی `127.0.0.1` گوش می‌دهند؛ فقط همان یک پورت عمومی باز است.

---
Aral Pars · یک پورت، همهٔ مسیرها
