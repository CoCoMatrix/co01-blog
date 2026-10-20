#!/usr/bin/env python3
"""Build the password-protected copy of the CO01 blog into docs/ (served by GitHub Pages).

Everything served is AES-256-GCM ciphertext: the blog HTML and every file under media/ (videos, posters).
The key is derived in the browser from the password (PBKDF2-SHA256), so without it nothing is readable.

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
MIME = {".mp4": "video/mp4", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}

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

# media/<path> -> docs/m/<hash>.bin (names hashed so they reveal nothing either)
enc = {}
for f in sorted((SRC / "media").rglob("*")):
    if f.suffix.lower() not in MIME:
        continue
    rel = f.relative_to(SRC).as_posix()
    name = hashlib.sha256((salt.hex() + rel).encode()).hexdigest()[:20] + ".bin"
    (OUT / "m" / name).write_bytes(seal(f.read_bytes()))
    enc[rel] = name

html = (SRC / "co01-blog.html").read_text(encoding="utf-8")

def swap(pattern, new):
    global html
    rx = re.compile(pattern, re.S)
    assert len(rx.findall(html)) == 1, f"expected exactly one match for {pattern[:40]}"
    html = rx.sub(lambda _: new, html, count=1)

# every media file goes through co01_url: fetch the ciphertext, decrypt with the page key, return a blob URL
swap(r"function pv_src\(v, rel\) \{.*?\n\}\n", """const CO01_ENC = %s, CO01_MIME = %s, CO01_URL = {};
function co01_key() {
  return co01_key.k || (co01_key.k = crypto.subtle.importKey("raw", Uint8Array.from(atob(window.CO01K), c => c.charCodeAt(0)), "AES-GCM", false, ["decrypt"]));
}
function co01_url(path) {
  if (!CO01_ENC[path]) return Promise.reject("not packed: " + path);
  return CO01_URL[path] = CO01_URL[path] || fetch("m/" + CO01_ENC[path]).then(r => r.ok ? r.arrayBuffer() : Promise.reject(r.status))
    .then(buf => co01_key().then(k => crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(buf, 0, 12) }, k, new Uint8Array(buf, 12))))
    .then(b => URL.createObjectURL(new Blob([b], { type: CO01_MIME[path.slice(path.lastIndexOf(".")).toLowerCase()] })))
    .catch(e => { delete CO01_URL[path]; console.error("media", path, e); throw e; });
}
function pv_src(v, rel) {
  if (v.dataset.rel === rel) return; v.dataset.rel = rel;
  co01_url(PV.base + rel).then(u => { if (v.dataset.rel === rel) v.src = u; }).catch(() => {});
}
""" % (json.dumps(enc), json.dumps(MIME)))
swap(r"function media_load\(v\) \{.*?\n\}\n", """function media_load(v) {
  const url = v.dataset.src; if (!url || v.dataset.loaded) return; v.dataset.loaded = "1"; v.preload = "auto";
  co01_url(url).then(u => { v.src = u; if (v.dataset.want) v.play().catch(() => {}); }).catch(() => {});
}
""")
# posters: keep them out of the attribute, decrypt once the page is up
html, n = re.subn(r'poster="(media/[^"]+)"', r'data-poster-enc="\1"', html)
html = html.replace("</body>", """<script>
document.querySelectorAll("[data-poster-enc]").forEach(v => co01_url(v.dataset.posterEnc).then(u => { if (!v.poster) v.poster = u; }).catch(() => {}));
</script>
</body>""", 1)
html = html.replace("<head>", '<head>\n<meta name="robots" content="noindex,nofollow,noarchive">', 1)
assert '<meta name="robots"' in html
missing = sorted(set(re.findall(r'(media/[^"\'`\s<>()]+\.(?:mp4|jpg|jpeg|png|webp))', html)) - set(enc))
assert not missing, f"referenced but not packed: {missing}"
assert not re.search(r'(?<![-\w])(?:src|href|poster)="media/', html), "plain media/ reference left in the page"

payload = base64.b64encode(seal(html.encode("utf-8"))).decode()
gate = (HERE / "gate.html").read_text(encoding="utf-8")
gate = gate.replace("__SALT__", base64.b64encode(salt).decode()).replace("__ITER__", str(ITER)).replace("__PAYLOAD__", payload)
(OUT / "index.html").write_text(gate, encoding="utf-8")
(OUT / ".nojekyll").write_text("")
(OUT / "robots.txt").write_text("User-agent: *\nDisallow: /\n")
print(f"built {OUT}: {len(enc)} media files ({n} posters), page {len(gate) // 1024} KB")
