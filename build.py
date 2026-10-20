#!/usr/bin/env python3
"""Build the password-protected copy of the CO01 blog into docs/ (served by GitHub Pages).

Everything served is AES-256-GCM ciphertext: the blog HTML and every video. The key is derived in the
browser from the password (PBKDF2-SHA256), so without the password the files are unreadable.

    CO01_PASSWORD=... python3 build.py [path/to/co01-blog]   # default ~/Desktop/coco/co01-blog
"""
import base64, hashlib, json, os, re, shutil, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
HERE = Path(__file__).resolve().parent
SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "~/Desktop/coco/co01-blog").expanduser()
OUT = HERE / "docs"

password = os.environ.get("CO01_PASSWORD") or sys.exit("set CO01_PASSWORD")
salt = os.urandom(16)
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(password.encode())
aes = AESGCM(key)

def seal(data: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, data, None)

if OUT.exists():
    shutil.rmtree(OUT)
(OUT / "m").mkdir(parents=True)

# videos: media/sec5/<rel> -> docs/m/<hash>.bin (names hashed so they reveal nothing either)
vmap = {}
for f in sorted((SRC / "media/sec5").rglob("*.mp4")):
    rel = f.relative_to(SRC / "media/sec5").as_posix()
    name = hashlib.sha256((salt.hex() + rel).encode()).hexdigest()[:20] + ".bin"
    (OUT / "m" / name).write_bytes(seal(f.read_bytes()))
    vmap[rel] = name

html = (SRC / "co01-blog.html").read_text(encoding="utf-8")

# replace the video loader: fetch the encrypted file, decrypt with the page key, play from a blob URL
loader = re.compile(r"function pv_src\(v, rel\) \{.*?\n\}\n", re.S)
assert len(loader.findall(html)) == 1, "pv_src not found exactly once"
html = loader.sub(lambda _: """const PV_ENC = %s, PV_URL = {};
function pv_key() {
  return pv_key.k || (pv_key.k = crypto.subtle.importKey("raw", Uint8Array.from(atob(window.CO01K), c => c.charCodeAt(0)), "AES-GCM", false, ["decrypt"]));
}
function pv_src(v, rel) {
  if (v.dataset.rel === rel) return; v.dataset.rel = rel;
  (PV_URL[rel] = PV_URL[rel] || fetch("m/" + PV_ENC[rel]).then(r => r.ok ? r.arrayBuffer() : Promise.reject(r.status))
    .then(buf => pv_key().then(k => crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(buf, 0, 12) }, k, new Uint8Array(buf, 12))))
    .then(b => URL.createObjectURL(new Blob([b], { type: "video/mp4" }))))
    .then(u => { if (v.dataset.rel === rel) v.src = u; }).catch(e => { delete PV_URL[rel]; console.error("video", rel, e); });
}
""" % json.dumps(vmap), html, count=1)
html = html.replace("<head>", '<head>\n<meta name="robots" content="noindex,nofollow,noarchive">', 1)
assert "<head>\n<meta name=\"robots\"" in html

payload = base64.b64encode(seal(html.encode("utf-8"))).decode()
gate = (HERE / "gate.html").read_text(encoding="utf-8")
gate = gate.replace("__SALT__", base64.b64encode(salt).decode()).replace("__ITER__", str(ITER)).replace("__PAYLOAD__", payload)
(OUT / "index.html").write_text(gate, encoding="utf-8")
(OUT / ".nojekyll").write_text("")
(OUT / "robots.txt").write_text("User-agent: *\nDisallow: /\n")
print(f"built {OUT}: {len(vmap)} videos, page {len(gate) // 1024} KB")
