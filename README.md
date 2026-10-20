# co01-blog (password-protected)

`docs/` is what GitHub Pages serves. Every file in it is AES-256-GCM ciphertext (the blog HTML and each video);
the browser derives the key from the password with PBKDF2-SHA256, so nothing is readable without it.

Rebuild after the blog changes:

    CO01_PASSWORD=... python3 build.py ~/Desktop/coco/co01-blog
    git add -A && git commit -m "Update blog" && git push
