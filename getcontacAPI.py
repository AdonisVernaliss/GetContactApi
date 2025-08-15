#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, time, json, base64, hmac, hashlib, binascii, os
import requests
from Cryptodome.Cipher import AES
from cred import HOST, API_VER, TOKEN, AES_KEY_HEX, HMAC_KEY_HEX, DEVICE_ID, APP_VERSION, OS_STRING, LANG, NET_CC, USER_AGENT, VALIDATE_PATH

DEBUG = False  # True — for logs in stderr

def dprint(*a, **kw):
    if DEBUG: print(*a, **kw, file=sys.stderr)

def load_hmac_key(hex_or_text: str) -> bytes:
    try:
        return bytes.fromhex(hex_or_text)
    except ValueError:
        return hex_or_text.encode("utf-8")

HMAC_KEY = load_hmac_key(HMAC_KEY_HEX)

class AESCipher:
    def __init__(self, aes_key_hex: str):
        try:
            key = binascii.unhexlify(aes_key_hex)
        except binascii.Error:
            raise ValueError("AES_KEY_HEX must be correct hex.")
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES the key should be 16/24/32 bytes, now {len(key)}")
        self.key = key
        self.bs  = 16

    def _pad(self, b: bytes) -> bytes:
        pad = self.bs - (len(b) % self.bs)
        return b + bytes([pad])*pad

    def _unpad(self, b: bytes) -> bytes:
        if not b: return b
        pad = b[-1]
        return b[:-pad] if 1 <= pad <= 16 else b

    def encrypt_b64(self, raw_json_str: str) -> str:
        pt = self._pad(raw_json_str.encode("utf-8"))
        ct = AES.new(self.key, AES.MODE_ECB).encrypt(pt)
        return base64.b64encode(ct).decode("ascii")

    def decrypt_b64(self, enc_b64: str) -> str:
        enc_b64 = enc_b64 + ("=" * ((-len(enc_b64)) % 4))  # padding just in case
        ct = base64.b64decode(enc_b64)
        if len(ct) % 16 != 0:
            raise RuntimeError(f"ciphertext length {len(ct)} not multiple of 16")
        pt = AES.new(self.key, AES.MODE_ECB).decrypt(ct)
        return self._unpad(pt).decode("utf-8", errors="replace")

aes = AESCipher(AES_KEY_HEX)

_last_ts = 0
def ts_ms_str() -> str:
    global _last_ts
    t = int(time.time() * 1000)
    if t <= _last_ts:
        t = _last_ts + 1
    _last_ts = t
    return str(t)

def sign(ts: str, obj: dict) -> tuple[str, str]:
    body_str = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    msg = f"{ts}-{body_str}".encode("utf-8")
    sig = base64.b64encode(hmac.new(HMAC_KEY, msg, hashlib.sha256).digest()).decode("ascii")
    dprint("SIGN INPUT:", msg.decode("utf-8"))
    dprint("SIGNATURE:", sig)
    return sig, body_str

# --- HTTP session (n't lose cookies) ---
session = requests.Session()
session.headers.update({
    "User-Agent": USER_AGENT,
    "X-Os": OS_STRING,
    "X-Mobile-Service": "GMS",
    "X-Store": "PLAYSTORE",
    "X-App-Version": APP_VERSION,
    "X-Client-Device-Id": DEVICE_ID,
    "X-Lang": LANG,
    "X-Token": TOKEN,
    "X-Encrypted": "1",
    "X-Roaming-Country": NET_CC,
    "X-Network-Country": NET_CC,
    "X-Country-Code": NET_CC,
    "Content-Type": "application/json; charset=utf-8",
    "Accept-Encoding": "gzip, deflate, br",
})

def send_post(path: str, body_obj: dict, path_hint: str):
    ts = ts_ms_str()
    sig, body_str = sign(ts, body_obj)
    enc_b64 = aes.encrypt_b64(body_str)

    url = f"https://{HOST}/{API_VER}/{path}"
    headers = {
        "X-Req-Timestamp": ts,
        "X-Req-Signature": sig,
        "X-Path": f"[{API_VER}, {path_hint}]",
    }
    payload = json.dumps({"data": enc_b64}, ensure_ascii=False).encode("utf-8")

    r = session.post(url, data=payload, headers=headers, timeout=25)

    # always read JSON
    try:
        j = r.json()
    except Exception:
        j = None

    if isinstance(j, dict) and "data" in j:
        enc = j["data"]
        try:
            with open("resp_data.b64", "w") as f: f.write(enc)
        except Exception:
            pass
        try:
            dec = aes.decrypt_b64(enc)
            try:
                with open("resp_data.dec.json", "w", encoding="utf-8") as f: f.write(dec)
            except Exception:
                pass

            if r.ok:
                return json.loads(dec)

            ###
            msg_short = dec
            try:
                dj = json.loads(dec)
                for k in ("message", "error", "reason", "detail", "code"):
                    if isinstance(dj, dict) and k in dj and dj[k]:
                        msg_short = f"{k}: {dj[k]}"
                        break
                if isinstance(dj, dict) and "meta" in dj and isinstance(dj["meta"], dict):
                    m = dj["meta"]
                    if "errorMessage" in m:
                        msg_short = f"{m.get('errorCode')}: {m.get('errorMessage')}"
            except Exception:
                pass

            raise RuntimeError(f"{r.status_code} {r.reason}: {msg_short}")

        except Exception as e:
            try:
                ct_len = len(base64.b64decode(enc + ("=" * ((-len(enc)) % 4))))
            except Exception:
                ct_len = -1
            raise RuntimeError(
                f"{r.status_code} {r.reason}; decrypt failed: {e}; len(b64)={len(enc)}, len(ct)={ct_len}"
            )

    if r.ok:
        return j if j is not None else {"raw": r.text}
    else:
        raise RuntimeError(f"{r.status_code} {r.reason}; no 'data' field")

# --- format ---
def dial_cc(e164: str) -> str:
    s = e164.lstrip('+')
    if s.startswith('7'):  return '7'   # RU/KZ
    if s.startswith('1'):  return '1'
    if s.startswith('63'): return '63'
    return s[:1] or "7"

# --- calls ---
def search_number(e164: str) -> dict:
    body = {
        "countryCode": dial_cc(e164),      # dial code, not ISO
        "dn": None,
        "dualSim": None,
        "esim": False,
        "inC": False,
        "phoneNumber": e164,
        "source": "searchHistory",
        "token": TOKEN,
    }
    return send_post("search", body, "search")

def number_detail(e164: str) -> dict:
    body = {
        "countryCode": dial_cc(e164),
        "source": "details",
        "token": TOKEN,
        "phoneNumber": e164,
    }
    return send_post("number-detail", body, "number-detail")

def validate_user(code: str) -> dict:
    body = {"validationCode": code, "token": TOKEN}
    return send_post(VALIDATE_PATH, body, "verify-code")

def save_captcha_from_errorfile(json_path="resp_data.dec.json", out_path="captcha.jpg") -> bool:
    if not os.path.exists(json_path):
        return False
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            dec = json.load(f)
        img_b64 = (((dec or {}).get("result") or {}).get("image"))
        if not img_b64:
            return False
        img_b64 = img_b64.replace("\\/", "/")
        with open(out_path, "wb") as imgf:
            imgf.write(base64.b64decode(img_b64 + "=" * ((-len(img_b64)) % 4)))
        return True
    except Exception:
        return False

# --- output ---
def _pick_first_result(resp: dict):
    res = resp.get("result")
    if isinstance(res, dict):
        return res.get("profile") or {}, res.get("subscriptionInfo") or {}, res.get("tags"), res
    if isinstance(res, list) and res:
        item = res[0] if isinstance(res[0], dict) else {}
        return item.get("profile") or item, item.get("subscriptionInfo") or {}, item.get("tags"), item
    return {}, {}, None, res

def _get_name(p: dict):
    for k in ("displayName","name","title","label"):
        v = p.get(k)
        if v: return v

def _tag_count(profile: dict, tags):
    if isinstance(tags, list): return len(tags)
    tc = profile.get("tagCount")
    return tc if isinstance(tc, int) else 0

def _fmt_usage(usage: dict, sec: str) -> str:
    if not isinstance(usage, dict): return "?/?"
    r = usage.get(sec) or {}
    return f"{r.get('remainingCount','?')}/{r.get('limit','?')}"

def solve_and_validate(phone: str, max_attempts: int = 5) -> None:
    """
        Repeats the captcha input in the same HTTP session.
        With 'invalid code', it requests a new captcha itself (via repeated search).
        Throws an exception if attempts have ended.
    """
    for attempt in range(1, max_attempts + 1):
        if not save_captcha_from_errorfile():
            raise RuntimeError("Captcha payload not found (see resp_data.dec.json)")

        print(f"\n🔐 Validation required (attempt {attempt}/{max_attempts}). Saved: captcha.jpg")
        code = input("Enter the code from the image: ").strip()

        try:
            validate_user(code)         # /v2.8/verify-code — same global session
            return                      # success
        except Exception as e:
            msg = str(e)
            if "403004" in msg and "invalid" in msg.lower():
                print("✖ Invalid code → requesting a new captcha…")
                # triggering a new captcha with the same session
                try:
                    _ = search_number(phone)  # Waiting for the 403 again with a new cap.pic
                except Exception as se:
                    if "403004" in str(se):
                        continue
                    raise
            else:
                raise
    raise RuntimeError("Validation failed: attempts exhausted")


# --- main ---
def main(argv):
    if len(argv) < 2:
        print("Usage: python GetContactAPI.py <phone>", file=sys.stderr); sys.exit(1)

    raw = argv[1].strip()
    phone = ''.join(ch for ch in raw if ch.isdigit() or ch == '+')
    if phone.startswith('00'):
        phone = '+' + phone[2:]
    elif not phone.startswith('+'):
        phone = '+' + phone

    cc = dial_cc(phone)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')

    banner = (
        "\n"
        "┌────────────────────────────────────────────┐\n"
        "│              Getcontact Lookup             │\n"
        "├────────────────────────────────────────────┤\n"
        f"│  📞  Number : {phone:<28} │\n"
        f"│  🌐   CC    : {cc:<28} │\n"
        f"│  🕒  Time   : {ts:<28} │\n"
        "└────────────────────────────────────────────┘"
    )
    print(banner)

    # 1) search
    try:
        sr = search_number(phone)
    except Exception as e:
        msg = str(e)
        if "403004" in msg or "User validation is required" in msg:
            try:
                solve_and_validate(phone)
                print("✅ Validation completed → repeating the search…")
                sr = search_number(phone)
            except Exception as e2:
                print(f"\n╭─ Validation error ─────────────────────────╮\n"
                      f"│ {e2}\n"
                      f"╰────────────────────────────────────────────╯")
                print("─" * 56); sys.exit(2)
        else:
            print(f"\n╭─ Search error ─────────────────────────────╮\n"
                  f"│ {e}\n"
                  f"╰────────────────────────────────────────────╯")
            print("─" * 56); sys.exit(2)

    # 2) details (tags)
    p, sub, tags_inline, _ = _pick_first_result(sr)
    name = _get_name(p)

    # details (tags)
    tags, usage = None, {}
    try:
        dt = number_detail(phone)
        p2, s2, tags, _ = _pick_first_result(dt)
        if not name:
            n2 = _get_name(p2)
            if n2: name = n2
        usage = (s2 or sub or {}).get("usage") or {}
    except Exception as e:
        dprint("detail error:", e)
        usage = (sub or {}).get("usage") or {}
        tags = tags_inline

    tc = _tag_count(p, tags if tags is not None else tags_inline)

    card_top = "╭─ Result ───────────────────────────────────╮"
    card_bot = "╰────────────────────────────────────────────╯"
    print(card_top)
    print(f"│ Name       : {name or 'Not found!'}")
    print(f"│ Tags       : {tc}")
    print(f"│ Searches   : {_fmt_usage(usage, 'search')}")
    print(f"│ With tags  : {_fmt_usage(usage, 'numberDetail')}")
    print(card_bot)

    if isinstance(tags, list) and tc:
        print("• Tags:")
        for t in tags:
            print(f"  - {t.get('tag') if isinstance(t, dict) else str(t)}")
    else:
        print("• Tags: " + ("hidden or missing" if tc > 0 else "not found"))

    print("─" * 56)


if __name__ == "__main__":
    main(sys.argv)
