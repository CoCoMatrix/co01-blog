import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';

const password = 'test-only-password';
const salt = randomBytes(16).toString('base64');
const iterations = 1000;
const key = pbkdf2Sync(password, Buffer.from(salt, 'base64'), iterations, 32, 'sha256');
const html = '<head><meta name="robots" content="noindex,nofollow,noarchive"></head><body>Original<script>const CO01_ENC = {"media/clip.mp4":"clip.bin"}, CO01_MIME = {};</script></body>';
function seal(text) {
	const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
	return Buffer.concat([iv, cipher.update(text), cipher.final(), cipher.getAuthTag()]).toString('base64');
}
function decrypt(gate) {
	const payload = gate.match(/PAYLOAD = "([^"]+)"/)[1], data = Buffer.from(payload, 'base64');
	const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
	decipher.setAuthTag(data.subarray(-16));
	return Buffer.concat([decipher.update(data.subarray(12, -16)), decipher.final()]).toString();
}

test('page edits preserve encryption and media and reject unsafe inputs', async () => {
	const root = await mkdtemp(join(tmpdir(), 'co01-page-test-'));
	try {
		const repo = join(root, 'repo');
		await mkdir(join(repo, 'docs', 'm'), {recursive:true});
		await copyFile(new URL('./page.mjs', import.meta.url), join(repo, 'page.mjs'));
		const gatePath = join(repo, 'docs', 'index.html'), mediaPath = join(repo, 'docs', 'm', 'clip.bin');
		const pagePath = join(root, 'private.html');
		const original = `<!doctype html><script>const SALT = "${salt}", ITER = ${iterations}, PAYLOAD = "${seal(html)}";</script>`;
		const media = randomBytes(128);
		await writeFile(gatePath, original); await writeFile(mediaPath, media);
		const run = (mode, secret = password, target = pagePath) => execFileSync(process.execPath, [join(repo, 'page.mjs'), mode, target], {env:{...process.env,CO01_PASSWORD:secret},stdio:'pipe'});
		assert.throws(() => run('unpack', password, join(repo, 'plaintext.html')));
		assert.throws(() => run('unpack', 'wrong-password'));
		run('unpack'); assert.equal(await readFile(pagePath,'utf8'), html);
		assert.throws(() => run('unpack')); // Never overwrite an existing plaintext file.
		run('pack'); assert.equal(await readFile(gatePath,'utf8'), original); // No-op leaves ciphertext unchanged.
		for (const invalid of [html.replace('clip.bin','other.bin'), html.replace('noindex,nofollow,noarchive','index'), html.replace('Original','<script>window.CO01K = "secret";</script>')]) {
			await writeFile(pagePath, invalid); assert.throws(() => run('pack'));
			assert.equal(await readFile(gatePath,'utf8'), original);
		}
		await writeFile(pagePath, html.replace('Original','Edited article'));
		assert.throws(() => run('pack','wrong-password')); assert.equal(await readFile(gatePath,'utf8'), original);
		run('pack'); const packed = await readFile(gatePath,'utf8');
		assert.notEqual(packed, original); assert.equal(decrypt(packed), html.replace('Original','Edited article'));
		assert.equal(packed.match(/SALT = "([^"]+)"/)[1],salt);
		assert.equal(packed.match(/ITER = (\d+)/)[1],String(iterations));
		assert.deepEqual(await readFile(mediaPath), media);
		assert.ok(!packed.includes('Edited article')); assert.ok(!packed.includes(password));
	} finally { await rm(root,{recursive:true,force:true}); }
});
