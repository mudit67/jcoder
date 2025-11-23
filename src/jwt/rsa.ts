"use strict";

import * as crypto from "crypto";
import {
  base64urlEncode,
  base64urlDecode,
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

// Map JWT alg → Node crypto RSA algorithm
const SUPPORTED_ALGS = {
  RS256: "RSA-SHA256",
  RS384: "RSA-SHA384",
  RS512: "RSA-SHA512",
} as const;

export type RsaAlg = keyof typeof SUPPORTED_ALGS;

export interface SignOptions extends BaseSignOptions {
  algorithm?: RsaAlg;
}

export interface VerifyOptions extends BaseVerifyOptions {
  algorithms?: RsaAlg[];
}

/**
 * Create RSA signature
 */
function createSignature(
  alg: RsaAlg | string,
  privateKey: crypto.KeyLike,
  signingInput: string
): string {
  const nodeAlg = SUPPORTED_ALGS[alg as RsaAlg];
  if (!nodeAlg) {
    throw new JsonWebTokenError("Unsupported algorithm: " + alg);
  }

  const signer = crypto.createSign(nodeAlg);
  signer.update(signingInput);
  signer.end();
  const sig = signer.sign(privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify RSA signature
 */
function verifySignature(
  alg: RsaAlg | string,
  publicKey: crypto.KeyLike,
  signingInput: string,
  signature: string
): boolean {
  const nodeAlg = SUPPORTED_ALGS[alg as RsaAlg];
  if (!nodeAlg) {
    throw new JsonWebTokenError("Unsupported algorithm: " + alg);
  }

  const verifier = crypto.createVerify(nodeAlg);
  verifier.update(signingInput);
  verifier.end();

  const sigBuf = base64urlDecode(signature);
  return verifier.verify(publicKey, sigBuf);
}

/**
 * sign(payload, privateKey, options)
 */
export function sign(
  payload: JwtPayload,
  privateKey: crypto.KeyLike,
  options: SignOptions = {}
): string {
  if (!privateKey) {
    throw new JsonWebTokenError("Private key is required for RSA signing");
  }

  const algorithm: RsaAlg = options.algorithm || "RS256";
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
  const signature = createSignature(algorithm, privateKey, signingInput);

  return signingInput + "." + signature;
}

/**
 * verify(token, publicKey, options)
 */
export function verify(
  token: string,
  publicKey: crypto.KeyLike,
  options: VerifyOptions = {}
): JwtPayload {
  if (!publicKey) {
    throw new JsonWebTokenError("Public key is required for RSA verification");
  }

  const { encodedHeader, encodedPayload, signature, header, payload } =
    parseJwtToken(token);

  // Algorithm checks
  if (!(header.alg in SUPPORTED_ALGS)) {
    throw new JsonWebTokenError("Unsupported algorithm: " + header.alg);
  }

  if (
    options.algorithms &&
    !options.algorithms.includes(header.alg as RsaAlg)
  ) {
    throw new JsonWebTokenError("Invalid algorithm: " + header.alg);
  }

  // Verify signature
  const signingInput = encodedHeader + "." + encodedPayload;
  const isValid = verifySignature(header.alg, publicKey, signingInput, signature);

  if (!isValid) {
    throw new JsonWebTokenError("Invalid signature");
  }

  // Validate time-based claims
  validateTimeClaims(payload, options);

  // Validate standard claims
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

// Re-export common types/errors if you want the same public API shape as HMAC
export {
  JsonWebTokenError,
  TokenExpiredError,
  NotBeforeError,
  JwtHeader,
  JwtPayload,
  DecodeOptions,
  CompleteDecodedJwt,
};
