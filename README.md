# GetContactAPI

> **Disclaimer**  
> For educational/research use on your own device/account only. Respect laws & ToS. No warranties.

---

## What this is

Sends app-like requests:
- Body: JSON → **AES-ECB** → Base64 in "data".`"data"`.
- `X-Req-Signature`: `Base64(HMAC-SHA256(ts + "-" + rawJson))`.
- Handles captcha on HTTP 403 (saves `captcha.jpg`, asks for code, retries).

**This is not an official SDK.** It’s a protocol exploration helper intended for legitimate testing on your own device/account.

---

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp cred.example.py cred.py         # fill with your values
```
`cred.py` is git-ignored and must not be committed.

---

## Configure (`cred.py`)
Fill in your legally obtained values:
```bash
HOST         = "pbssrv-centralevents.com"
API_VER      = "v2.8"
TOKEN        = "..."   # your own account token
AES_KEY_HEX  = "..."   # 16/24/32-byte AES key in hex (64 hex chars for 256-bit)
HMAC_KEY_HEX = "..."   # HMAC key (hex OR plain text — both supported)
DEVICE_ID    = "..."   # your device id as used by the app
APP_VERSION  = "8.8.0"
OS_STRING    = "android 11"
LANG         = "en_US"
NET_CC       = "us"
USER_AGENT   = "Dalvik/2.1.0 (Linux; U; Android 11; sdk_gphone_arm64 Build/RSR1.210722.003)"
VALIDATE_PATH = "verify-code"
```

---

## Where to get the values
AES key & token: `/data/data/app.source.getcontact/shared_prefs/GetContactSettingsPref.xml` (fields like FINAL_KEY, TOKEN) or capture your traffic with Burp.
(the XML typically contains fields like `FINAL_KEY` and `TOKEN`).
Alternatively, you can intercept your own device’s traffic and inspect it with a proxy (e.g., Burp) to see the token and request structure.

HMAC key: from the app’s signing routine on your instance (dynamic instrumentation or static analysis of your own build).

### Notes

- Reading /data/data/... requires a rooted device/emulator you control.
- Never publish or use someone else’s keys/tokens.

---

## Run
```bash
python getcontactAPI.py +7**********
# or without the plus – the script normalizes it:
python getcontactAPI.py 7**********
```

---

## Captcha

On 403004 the script writes captcha.jpg; enter the code (case-sensitive, short TTL). If invalid, it requests a new captcha and retries in the same session.

## Troubleshooting (short)
- 403004 require validation: solve captcha.
- 403 invalid code: wrong chars/expired/new search replaced it.
- 403 Forbidden: headers/metadata mismatch; keep them consistent with your device.
- Decrypt/signature errors: wrong AES/HMAC or string-to-sign.

---

## Debug files
`resp_data.b64` (encrypted) and `resp_data.dec.json` (decrypted). Optional; can be deleted/disabled.