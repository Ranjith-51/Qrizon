import io
import re
import ipaddress
from urllib.parse import urlparse

import numpy as np
import cv2
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# pyzbar depends on the system libzbar shared library. On some serverless
# hosts that library isn't available, so we import it defensively and fall
# back to OpenCV's built-in QR detector (which ships fully inside
# opencv-python-headless and needs no extra system packages) if it fails.
try:
    from pyzbar.pyzbar import decode as zbar_decode
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False

app = FastAPI(title="QRizon API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Heuristics configuration
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "bank", "banking", "secure", "security", "account", "update",
    "confirm", "password", "credential", "wallet", "suspend",
    "unlock", "alert", "billing", "invoice", "gift", "free", "prize",
    "urgent", "limited", "click", "reset",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".zip", ".mov", ".click", ".gq", ".tk", ".ml",
    ".cf", ".ga", ".work", ".support", ".live",
]


def is_ip_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    host = hostname.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(raw_url: str) -> dict:
    flags = []
    score = 100  # start at full trust, deduct per flag

    parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    scheme = (parsed.scheme or "").lower()
    hostname = parsed.hostname or ""
    full_lower = raw_url.lower()

    # 1. Unsecured connection check
    if scheme == "http":
        flags.append({
            "id": "insecure-scheme",
            "severity": "high",
            "message": "Uses unencrypted HTTP instead of HTTPS.",
        })
        score -= 30
    elif scheme != "https":
        flags.append({
            "id": "unknown-scheme",
            "severity": "medium",
            "message": f"Unrecognized or missing URL scheme ('{scheme or 'none'}').",
        })
        score -= 15

    # 2. Phishing keyword scan
    matched_keywords = sorted({kw for kw in PHISHING_KEYWORDS if kw in full_lower})
    if matched_keywords:
        flags.append({
            "id": "phishing-keywords",
            "severity": "high" if len(matched_keywords) >= 3 else "medium",
            "message": f"Contains suspicious keyword(s): {', '.join(matched_keywords)}.",
        })
        score -= min(35, 10 * len(matched_keywords))

    # 3. Direct IP address as hostname
    if is_ip_hostname(hostname):
        flags.append({
            "id": "ip-hostname",
            "severity": "high",
            "message": f"Destination uses a raw IP address ({hostname}) instead of a domain name.",
        })
        score -= 30

    # 4. Known URL shortener (obscures true destination)
    if any(shortener in hostname for shortener in URL_SHORTENERS):
        flags.append({
            "id": "url-shortener",
            "severity": "medium",
            "message": "Uses a URL shortening service, which can mask the real destination.",
        })
        score -= 15

    # 5. Suspicious / low-reputation TLD
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append({
            "id": "suspicious-tld",
            "severity": "medium",
            "message": f"Domain uses a top-level domain often associated with abuse ({hostname.split('.')[-1]}).",
        })
        score -= 15

    # 6. Excessive subdomains / punycode / @ tricks (lightweight extra checks)
    if "@" in raw_url:
        flags.append({
            "id": "at-symbol",
            "severity": "high",
            "message": "URL contains an '@' symbol, a common trick to disguise the real destination.",
        })
        score -= 25

    if hostname.count(".") >= 4:
        flags.append({
            "id": "excessive-subdomains",
            "severity": "low",
            "message": "Unusually long subdomain chain, sometimes used to imitate trusted domains.",
        })
        score -= 10

    if "xn--" in hostname:
        flags.append({
            "id": "punycode",
            "severity": "medium",
            "message": "Domain uses punycode encoding, which can be used to spoof lookalike characters.",
        })
        score -= 15

    score = max(0, min(100, score))

    if score >= 75:
        verdict = "SAFE"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"

    return {
        "url": raw_url,
        "hostname": hostname,
        "scheme": scheme,
        "score": score,
        "verdict": verdict,
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# QR decoding
# ---------------------------------------------------------------------------

def decode_qr(image_bytes: bytes):
    file_bytes = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if img is None:
        return None

    # Primary: OpenCV's built-in detector — no external system libs required.
    detector = cv2.QRCodeDetector()
    try:
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
        if retval:
            for text in decoded_info:
                if text:
                    return text
    except Exception:
        pass

    data, points, _ = detector.detectAndDecode(img)
    if data:
        return data

    # Fallback: pyzbar, if the system library is present.
    if PYZBAR_AVAILABLE:
        try:
            results = zbar_decode(img)
            if results:
                return results[0].data.decode("utf-8", errors="ignore")
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "pyzbar_available": PYZBAR_AVAILABLE}


@app.post("/api/scan")
async def scan_qr(file: UploadFile = File(...)):
    contents = await file.read()

    if not contents:
        return JSONResponse(status_code=400, content={"error": "Empty file uploaded."})

    decoded_text = decode_qr(contents)

    if not decoded_text:
        return JSONResponse(
            status_code=422,
            content={"error": "No QR code could be detected in the uploaded image."},
        )

    # Only run URL heuristics if it looks like a URL; otherwise still return
    # the raw payload with a neutral analysis.
    looks_like_url = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", decoded_text)) or "." in decoded_text

    if looks_like_url:
        analysis = analyze_url(decoded_text)
    else:
        analysis = {
            "url": decoded_text,
            "hostname": "",
            "scheme": "",
            "score": 50,
            "verdict": "SUSPICIOUS",
            "flags": [{
                "id": "non-url-payload",
                "severity": "medium",
                "message": "QR payload does not appear to be a standard URL.",
            }],
        }

    return {"decoded": decoded_text, "analysis": analysis}
