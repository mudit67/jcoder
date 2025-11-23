import * as crypto from "crypto";

const SCRYPT_KEYLEN = 64;

/**
 * Hash password with random salt using scrypt.
 * Result format: salt:hash (both hex strings)
 */
export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, derivedKey) => {
      if (err) return reject(err);
      const hash = derivedKey.toString("hex");
      resolve(`${salt}:${hash}`);
    });
  });
}

/**
 * Verify password against stored salt:hash.
 */
export function verifyPassword(
  password: string,
  stored: string
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const [salt, hash] = stored.split(":");
    if (!salt || !hash) return resolve(false);

    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, derivedKey) => {
      if (err) return reject(err);
      const hashBuf = Buffer.from(hash, "hex");
      const derivedBuf = derivedKey as Buffer;

      if (hashBuf.length !== derivedBuf.length) return resolve(false);
      const match = crypto.timingSafeEqual(hashBuf, derivedBuf);
      resolve(match);
    });
  });
}
