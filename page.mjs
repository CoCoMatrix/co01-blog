#!/usr/bin/env node
/** Edit the encrypted page without rebuilding or changing encrypted media. */
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, writeFile, rename, unlink, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const gatePath = fileURLToPath(new URL('./docs/index.html', import.meta.url));
const usage = 'Usage: CO01_PASSWORD=... node page.mjs unpack|pack path/to/page.html';
const [mode, file, ...extra] = process.argv.slice(2);

async function main() {
	if (!['unpack', 'pack'].includes(mode) || !file || extra.length) throw new Error(usage);
	if (!process.env.CO01_PASSWORD) throw new Error('Set CO01_PASSWORD.');
	const requestedPath = resolve(file);
	const inputPath = mode === 'pack' ? await realpath(requestedPath) : resolve(await realpath(dirname(requestedPath)), basename(requestedPath));
	const repositoryPath = await realpath(fileURLToPath(new URL('./', import.meta.url)));
	const fromRepository = relative(repositoryPath, inputPath);
	if (fromRepository !== '..' && !fromRepository.startsWith(`..${sep}`) && !isAbsolute(fromRepository)) {
		throw new Error('Keep the decrypted page outside this public repository.');
	}
	const gate = await readFile(gatePath, 'utf8');
	const matches = [...gate.matchAll(/const SALT = "([A-Za-z0-9+/=]+)", ITER = (\d+), PAYLOAD = "([A-Za-z0-9+/=]+)";/g)];
	if (matches.length !== 1) throw new Error('Expected one encrypted page payload.');
	const [declaration, salt, iterations, payload] = matches[0];
	const key = pbkdf2Sync(process.env.CO01_PASSWORD, Buffer.from(salt, 'base64'), Number(iterations), 32, 'sha256');
	const sealed = Buffer.from(payload, 'base64');
	const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12));
	decipher.setAuthTag(sealed.subarray(-16));
	let original;
	try {
		original = Buffer.concat([decipher.update(sealed.subarray(12, -16)), decipher.final()]);
	} catch {
		throw new Error('Cannot decrypt the page. Check the password and encrypted file.');
	}
	if (mode === 'unpack') {
		await writeFile(inputPath, original, { flag: 'wx', mode: 0o600 });
		console.log('Saved the decrypted page. Keep it outside Git.');
		return;
	}
	const html = await readFile(inputPath, 'utf8');
	// The original salt and media map bind the existing media ciphertext to this page.
	const mediaMap = source => source.match(/const CO01_ENC = (\{[^\n]+?\}), CO01_MIME = /)?.[1];
	if (!mediaMap(original.toString('utf8')) || mediaMap(html) !== mediaMap(original.toString('utf8'))) {
		throw new Error('The media map changed. Use build.py for media changes.');
	}
	if (!/<meta\s+name="robots"\s+content="noindex,nofollow,noarchive">/.test(html)) {
		throw new Error('Keep the robots metadata in the encrypted page.');
	}
	if (/window\.CO01K\s*=/.test(html)) throw new Error('Remove the browser-injected key before packing.');
	if (html === original.toString('utf8')) {
		console.log('The page has no changes.');
		return;
	}
	const iv = randomBytes(12);
	const cipher = createCipheriv('aes-256-gcm', key, iv);
	const encrypted = Buffer.concat([iv, cipher.update(html, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64');
	const updated = gate.replace(declaration, `const SALT = "${salt}", ITER = ${iterations}, PAYLOAD = "${encrypted}";`);
	const temp = `${gatePath}.${randomBytes(8).toString('hex')}.tmp`;
	try {
		await writeFile(temp, updated, {flag:'wx', mode:0o600});
		await rename(temp, gatePath);
	} finally {
		await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; });
	}
	console.log('Updated the encrypted page. Existing encrypted media is unchanged.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
