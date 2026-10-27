/**
 * Pure-JS MD4 (RFC 1320).
 *
 * OpenSSL 3 disables MD4, but NTLM authentication requires it. The shim below
 * patches crypto.createHash so that 'md4' falls back to this implementation
 * whenever the native one is unavailable.
 */

function rol(x: number, s: number): number {
	return ((x << s) | (x >>> (32 - s))) >>> 0;
}

export class MD4 {
	private buffer: Buffer = Buffer.alloc(0);

	update(data: Buffer | string, inputEncoding?: BufferEncoding): this {
		const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data, inputEncoding ?? 'utf8');
		this.buffer = Buffer.concat([this.buffer, chunk]);
		return this;
	}

	digest(): Buffer;
	digest(encoding: BufferEncoding | 'hex' | 'base64' | 'latin1'): string;
	digest(encoding?: BufferEncoding): Buffer | string {
		const msg = this.buffer;
		const bitLenLo = (msg.length << 3) >>> 0;
		const bitLenHi = Math.floor(msg.length / 0x20000000) >>> 0;
		const padLen = (((55 - msg.length) % 64) + 64) % 64 + 1;
		const padded = Buffer.alloc(msg.length + padLen + 8);
		msg.copy(padded, 0);
		padded[msg.length] = 0x80;
		padded.writeUInt32LE(bitLenLo, padded.length - 8);
		padded.writeUInt32LE(bitLenHi, padded.length - 4);

		let a = 0x67452301;
		let b = 0xefcdab89;
		let c = 0x98badcfe;
		let d = 0x10325476;
		const X: number[] = new Array(16);

		for (let block = 0; block < padded.length; block += 64) {
			for (let i = 0; i < 16; i++) {
				X[i] = padded.readUInt32LE(block + i * 4);
			}
			const aa = a;
			const bb = b;
			const cc = c;
			const dd = d;

			const F = (x: number, y: number, z: number) => ((x & y) | (~x & z)) >>> 0;
			const r1 = (v: number, x: number, y: number, z: number, k: number, s: number) =>
				rol((v + F(x, y, z) + X[k]) >>> 0, s);
			a = r1(a, b, c, d, 0, 3);
			d = r1(d, a, b, c, 1, 7);
			c = r1(c, d, a, b, 2, 11);
			b = r1(b, c, d, a, 3, 19);
			a = r1(a, b, c, d, 4, 3);
			d = r1(d, a, b, c, 5, 7);
			c = r1(c, d, a, b, 6, 11);
			b = r1(b, c, d, a, 7, 19);
			a = r1(a, b, c, d, 8, 3);
			d = r1(d, a, b, c, 9, 7);
			c = r1(c, d, a, b, 10, 11);
			b = r1(b, c, d, a, 11, 19);
			a = r1(a, b, c, d, 12, 3);
			d = r1(d, a, b, c, 13, 7);
			c = r1(c, d, a, b, 14, 11);
			b = r1(b, c, d, a, 15, 19);

			const G = (x: number, y: number, z: number) => ((x & y) | (x & z) | (y & z)) >>> 0;
			const r2 = (v: number, x: number, y: number, z: number, k: number, s: number) =>
				rol((v + G(x, y, z) + X[k] + 0x5a827999) >>> 0, s);
			a = r2(a, b, c, d, 0, 3);
			d = r2(d, a, b, c, 4, 5);
			c = r2(c, d, a, b, 8, 9);
			b = r2(b, c, d, a, 12, 13);
			a = r2(a, b, c, d, 1, 3);
			d = r2(d, a, b, c, 5, 5);
			c = r2(c, d, a, b, 9, 9);
			b = r2(b, c, d, a, 13, 13);
			a = r2(a, b, c, d, 2, 3);
			d = r2(d, a, b, c, 6, 5);
			c = r2(c, d, a, b, 10, 9);
			b = r2(b, c, d, a, 14, 13);
			a = r2(a, b, c, d, 3, 3);
			d = r2(d, a, b, c, 7, 5);
			c = r2(c, d, a, b, 11, 9);
			b = r2(b, c, d, a, 15, 13);

			const H = (x: number, y: number, z: number) => (x ^ y ^ z) >>> 0;
			const r3 = (v: number, x: number, y: number, z: number, k: number, s: number) =>
				rol((v + H(x, y, z) + X[k] + 0x6ed9eba1) >>> 0, s);
			a = r3(a, b, c, d, 0, 3);
			d = r3(d, a, b, c, 8, 9);
			c = r3(c, d, a, b, 4, 11);
			b = r3(b, c, d, a, 12, 15);
			a = r3(a, b, c, d, 2, 3);
			d = r3(d, a, b, c, 10, 9);
			c = r3(c, d, a, b, 6, 11);
			b = r3(b, c, d, a, 14, 15);
			a = r3(a, b, c, d, 1, 3);
			d = r3(d, a, b, c, 9, 9);
			c = r3(c, d, a, b, 5, 11);
			b = r3(b, c, d, a, 13, 15);
			a = r3(a, b, c, d, 3, 3);
			d = r3(d, a, b, c, 11, 9);
			c = r3(c, d, a, b, 7, 11);
			b = r3(b, c, d, a, 15, 15);

			a = (a + aa) >>> 0;
			b = (b + bb) >>> 0;
			c = (c + cc) >>> 0;
			d = (d + dd) >>> 0;
		}

		const out = Buffer.alloc(16);
		out.writeUInt32LE(a, 0);
		out.writeUInt32LE(b, 4);
		out.writeUInt32LE(c, 8);
		out.writeUInt32LE(d, 12);
		return encoding ? out.toString(encoding) : out;
	}
}

export function ensureMd4Support(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const crypto = require('crypto');
	if (crypto.__md4ShimInstalled) return;

	const originalCreateHash = crypto.createHash.bind(crypto);
	crypto.createHash = function (algorithm: string, options?: unknown) {
		if (typeof algorithm === 'string' && algorithm.toLowerCase() === 'md4') {
			try {
				return originalCreateHash(algorithm, options);
			} catch {
				return new MD4();
			}
		}
		return originalCreateHash(algorithm, options);
	};
	crypto.__md4ShimInstalled = true;
}
