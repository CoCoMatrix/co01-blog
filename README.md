# CO01 blog

GitHub Pages serves `docs/`. The article and media files are encrypted with AES-256-GCM. The password gate derives the key with PBKDF2-SHA256. Keep passwords, decrypted HTML, and source media outside this public repository.

## Edit the article

Use Node.js 18 or later. Set and export `CO01_PASSWORD` in your shell without saving it in a file or command history.

Extract the current page to a private directory:

```sh
	node page.mjs unpack /path/to/private/co01-blog.html
```

Edit that HTML, then encrypt the updated page:

```sh
	node page.mjs pack /path/to/private/co01-blog.html
```

`page.mjs` checks the password before writing. It preserves the existing salt and encrypted media files and uses a new nonce for the updated page. It rejects a changed media map. Use the full build when you add or replace media.

Serve `docs/` locally and check the password gate, article, and affected figures. Review the changes before committing the encrypted page and any intended code changes. A push to `main` updates the live site.

## Rebuild the article and media

The full build needs the original source directory, with `co01-blog.html` and `media/`, and a Python environment with `cryptography` installed. With `CO01_PASSWORD` set, run:

```sh
	uv run --offline --no-project python build.py /path/to/private/source
```

`build.py` replaces `docs/` and encrypts all media again. Review the changed files and commit only the intended paths.

## Check the page editor

Run the encryption and input-validation test:

```sh
	node --test page.test.mjs
```
