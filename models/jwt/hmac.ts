"use strict";

import * as crypto from "crypto";

// Map JWT alg → Node crypto HMAC algorithm
const SUPPORTED_ALGS = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
} as const;

export type HmacAlg = keyof typeof SUPPORTED_ALGS;

export interface JwtHeader {
  alg: HmacAlg | string;
  typ?: string;
  kid?: string;
  [key: string]: any;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface SignOptions {
  algorithm?: HmacAlg;
  expiresIn?: number | string;
  notBefore?: number | string;
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  jwtid?: string;
  noTimestamp?: boolean;
  header?: Record<string, any>;
  keyid?: string;
  clockTimestamp?: number; // seconds since epoch
}

export interface VerifyOptions {
  algorithms?: HmacAlg[];
  issuer?: string | string[];
  subject?: string;
  audience?: string | string[];
  clockTimestamp?: number;
  clockTolerance?: number; // seconds
  maxAge?: number | string;
}

export interface DecodeOptions {
  complete?: boolean;
}

export interface CompleteDecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string | null;
}

/**
 * Base64URL encode a Buffer
 */
export function base64urlEncode(buffer: Buffer): string {
  return buffer
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Base64URL decode to Buffer
 */
export function base64urlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = 4 - (base64.length % 4);
  if (pad !== 4) {
    base64 += "=".repeat(pad);
  }
  return Buffer.from(base64, "base64");
}

/**
 * Parse a timespan like:
 *  - number (seconds)
 *  - "60" (seconds)
 *  - "10s", "5m", "2h", "7d"
 */
export function parseTimespan(value: number | string): number {
  if (typeof value === "number") return value;
  if (typeof value === "string" && /^\d+$/.test(value)) {
    // plain number in seconds
    return parseInt(value, 10);
  }

  const match = /^(\d+)([smhd])$/.exec(value || "");
  if (!match) {
    throw new TypeError("Invalid timespan format: " + value);
  }

  const amount = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "s":
      return amount;
    case "m":
      return amount * 60;
    case "h":
      return amount * 60 * 60;
    case "d":
      return amount * 60 * 60 * 24;
    default:
      throw new TypeError("Unsupported timespan unit: " + unit);
  }
}

/**
 * Safe JSON parse helper
 */
function safeJsonParse<T = any>(str: string): T {
  try {
    return JSON.parse(str) as T;
  } catch (err: any) {
    throw new JsonWebTokenError("Invalid JSON in token: " + err.message);
  }
}

/**
 * Errors similar to jsonwebtoken
 */
export class JsonWebTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonWebTokenError";
  }
}

export class TokenExpiredError extends JsonWebTokenError {
  expiredAt: Date;

  constructor(message: string, expiredAt: Date) {
    super(message);
    this.name = "TokenExpiredError";
    this.expiredAt = expiredAt;
  }
}

export class NotBeforeError extends JsonWebTokenError {
  date: Date;

  constructor(message: string, date: Date) {
    super(message);
    this.name = "NotBeforeError";
    this.date = date;
  }
}

/**
 * Create HMAC signature
 */
function createSignature(
  alg: HmacAlg | string,
  secret: crypto.BinaryLike | crypto.KeyObject,
  signingInput: string
): string {
  const nodeAlg = SUPPORTED_ALGS[alg as HmacAlg];
  if (!nodeAlg) {
    throw new JsonWebTokenError("Unsupported algorithm: " + alg);
  }

  const hmac = crypto.createHmac(nodeAlg, secret);
  hmac.update(signingInput);
  const sig = hmac.digest();
  return base64urlEncode(sig);
}

/**
 * Constant-time comparison of two base64url strings
 */
function timingSafeEqualStr(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);

  if (aBuf.length !== bBuf.length) {
    // still run timingSafeEqual with same length to avoid early return timing leaks
    const min = Math.min(aBuf.length, bBuf.length);
    const aSlice = aBuf.slice(0, min);
    const bSlice = bBuf.slice(0, min);
    crypto.timingSafeEqual(aSlice, bSlice);
    return false;
  }

  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * sign(payload, secret, options)
 */
export function sign(
  payload: JwtPayload,
  secret: crypto.BinaryLike | crypto.KeyObject,
  options: SignOptions = {}
): string {
  if (!secret) {
    throw new JsonWebTokenError("Secret is required for HMAC signing");
  }

  const algorithm: HmacAlg = options.algorithm || "HS256";
  if (!SUPPORTED_ALGS[algorithm]) {
    throw new JsonWebTokenError("Unsupported algorithm: " + algorithm);
  }

  const now =
    typeof options.clockTimestamp === "number"
      ? options.clockTimestamp
      : Math.floor(Date.now() / 1000);

  const header: JwtHeader = Object.assign(
    {
      alg: algorithm,
      typ: "JWT",
    },
    options.header || {}
  );

  if (options.keyid) {
    header.kid = options.keyid;
  }

  // Clone payload so we don't mutate the original
  const payloadCopy: JwtPayload =
    typeof payload === "object" && payload !== null
      ? { ...payload }
      : ({} as JwtPayload);

  if (typeof payloadCopy !== "object" || payloadCopy === null) {
    throw new JsonWebTokenError("Payload must be a non-null object");
  }

  // Set standard claims from options if not already present
  if (options.issuer) payloadCopy.iss = options.issuer;
  if (options.subject) payloadCopy.sub = options.subject;
  if (options.audience) payloadCopy.aud = options.audience;
  if (options.jwtid) payloadCopy.jti = options.jwtid;

  if (!options.noTimestamp && typeof payloadCopy.iat === "undefined") {
    payloadCopy.iat = now;
  }

  if (options.expiresIn) {
    const exp = now + parseTimespan(options.expiresIn);
    payloadCopy.exp = exp;
  }

  if (options.notBefore) {
    const nbf = now + parseTimespan(options.notBefore);
    payloadCopy.nbf = nbf;
  }

  const encodedHeader = base64urlEncode(
    Buffer.from(JSON.stringify(header), "utf8")
  );
  const encodedPayload = base64urlEncode(
    Buffer.from(JSON.stringify(payloadCopy), "utf8")
  );

  const signingInput = encodedHeader + "." + encodedPayload;
  const signature = createSignature(algorithm, secret, signingInput);

  return signingInput + "." + signature;
}

/**
 * verify(token, secret, options)
 */
export function verify(
  token: string,
  secret: crypto.BinaryLike | crypto.KeyObject,
  options: VerifyOptions = {}
): JwtPayload {
  if (!secret) {
    throw new JsonWebTokenError("Secret is required for HMAC verification");
  }

  if (typeof token !== "string") {
    throw new JsonWebTokenError("JWT must be a string");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JsonWebTokenError("JWT malformed");
  }

  const [encodedHeader, encodedPayload, signature] = parts;

  const header = safeJsonParse<JwtHeader>(
    base64urlDecode(encodedHeader).toString("utf8")
  );
  const payload = safeJsonParse<JwtPayload>(
    base64urlDecode(encodedPayload).toString("utf8")
  );

  // Algorithm checks
  if (!header.alg) {
    throw new JsonWebTokenError("JWT header missing alg");
  }

  if (!(header.alg in SUPPORTED_ALGS)) {
    throw new JsonWebTokenError("Unsupported algorithm: " + header.alg);
  }

  if (
    options.algorithms &&
    !options.algorithms.includes(header.alg as HmacAlg)
  ) {
    throw new JsonWebTokenError("Invalid algorithm: " + header.alg);
  }

  // Verify signature
  const signingInput = encodedHeader + "." + encodedPayload;
  const expectedSig = createSignature(header.alg, secret, signingInput);

  if (!timingSafeEqualStr(expectedSig, signature)) {
    throw new JsonWebTokenError("Invalid signature");
  }

  const now =
    typeof options.clockTimestamp === "number"
      ? options.clockTimestamp
      : Math.floor(Date.now() / 1000);

  const tolerance = options.clockTolerance || 0;

  // nbf (Not Before)
  if (typeof payload.nbf !== "undefined") {
    if (typeof payload.nbf !== "number") {
      throw new JsonWebTokenError("Invalid nbf");
    }
    if (now + tolerance < payload.nbf) {
      const date = new Date(payload.nbf * 1000);
      throw new NotBeforeError("jwt not active", date);
    }
  }

  // exp (Expiration)
  if (typeof payload.exp !== "undefined") {
    if (typeof payload.exp !== "number") {
      throw new JsonWebTokenError("Invalid exp");
    }
    if (now - tolerance >= payload.exp) {
      const date = new Date(payload.exp * 1000);
      throw new TokenExpiredError("jwt expired", date);
    }
  }

  // maxAge (extra constraint)
  if (options.maxAge) {
    if (typeof payload.iat !== "number") {
      throw new JsonWebTokenError("iat required when using maxAge");
    }
    const maxAgeSeconds = parseTimespan(options.maxAge);
    if (now - payload.iat > maxAgeSeconds + tolerance) {
      const date = new Date((payload.iat + maxAgeSeconds) * 1000);
      throw new TokenExpiredError("maxAge exceeded", date);
    }
  }

  // iss
  if (options.issuer) {
    const validIssuers = Array.isArray(options.issuer)
      ? options.issuer
      : [options.issuer];
    if (!validIssuers.includes(payload.iss as string)) {
      throw new JsonWebTokenError("invalid issuer");
    }
  }

  // sub
  if (options.subject && payload.sub !== options.subject) {
    throw new JsonWebTokenError("invalid subject");
  }

  // aud
  if (options.audience) {
    const audOption = options.audience;
    const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const validAudiences = Array.isArray(audOption) ? audOption : [audOption];

    const match = target.some((aud) => validAudiences.includes(aud as string));
    if (!match) {
      throw new JsonWebTokenError("invalid audience");
    }
  }

  return payload;
}

/**
 * decode(token, options)
 *
 * NOTE: This does NOT verify signature or any claims.
 */
export function decode(
  token: string,
  options: DecodeOptions = {}
): JwtPayload | CompleteDecodedJwt | null {
  if (typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length < 2) return null;

  const [encodedHeader, encodedPayload, encodedSig] = parts;

  try {
    const header = safeJsonParse<JwtHeader>(
      base64urlDecode(encodedHeader).toString("utf8")
    );
    const payload = safeJsonParse<JwtPayload>(
      base64urlDecode(encodedPayload).toString("utf8")
    );

    if (options.complete) {
      return {
        header,
        payload,
        signature: encodedSig || null,
      };
    }

    return payload;
  } catch {
    return null;
  }
}

// Optional: grouped internals (if you still want this pattern)
export const _internals = {
  base64urlEncode,
  base64urlDecode,
  parseTimespan,
};
