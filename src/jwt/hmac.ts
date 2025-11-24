"use strict";

import * as crypto from "crypto";
import {
  base64urlEncode,
  base64urlDecode,
  parseTimespan,
  safeJsonParse,
  JsonWebTokenError,
  TokenExpiredError,
  NotBeforeError,
  JwtHeader,
  JwtPayload,
  BaseSignOptions,
  BaseVerifyOptions,
  DecodeOptions,
  CompleteDecodedJwt,
  validateTimeClaims,
  validateStandardClaims,
  buildPayload,
  buildHeader,
  parseJwtToken,
} from "./utils";

const SUPPORTED_ALGS = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
} as const;

export type HmacAlg = keyof typeof SUPPORTED_ALGS;

export interface SignOptions extends BaseSignOptions {
  algorithm?: HmacAlg;
}

export interface VerifyOptions extends BaseVerifyOptions {
  algorithms?: HmacAlg[];
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

  const header = buildHeader(algorithm, options);
  const payloadCopy = buildPayload(payload, options);

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

  const { encodedHeader, encodedPayload, signature, header, payload } = parseJwtToken(token);

  if (!(header.alg in SUPPORTED_ALGS)) {
    throw new JsonWebTokenError("Unsupported algorithm: " + header.alg);
  }

  if (
    options.algorithms &&
    !options.algorithms.includes(header.alg as HmacAlg)
  ) {
    throw new JsonWebTokenError("Invalid algorithm: " + header.alg);
  }

  const signingInput = encodedHeader + "." + encodedPayload;
  const expectedSig = createSignature(header.alg, secret, signingInput);

  if (!timingSafeEqualStr(expectedSig, signature)) {
    throw new JsonWebTokenError("Invalid signature");
  }

  validateTimeClaims(payload, options);
  validateStandardClaims(payload, options);

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

export { 
  base64urlEncode,
  base64urlDecode,
  parseTimespan,
  JsonWebTokenError,
  TokenExpiredError,
  NotBeforeError,
  JwtHeader,
  JwtPayload,
  DecodeOptions,
  CompleteDecodedJwt
};