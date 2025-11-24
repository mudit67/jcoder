/**
 * JWT Utility functions that can be shared across different algorithms (HMAC, RSA, etc.)
 */

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
export function safeJsonParse<T = any>(str: string): T {
  try {
    return JSON.parse(str) as T;
  } catch (err: any) {
    throw new JsonWebTokenError("Invalid JSON in token: " + err.message);
  }
}

/**
 * Common JWT error classes
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
 * Common JWT interfaces that can be used across algorithms
 */
export interface JwtHeader {
  alg: string;
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

export interface BaseSignOptions {
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

export interface BaseVerifyOptions {
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
 * Validate common JWT claims (can be used by both HMAC and RSA)
 */
export function validateTimeClaims(
  payload: JwtPayload, 
  options: BaseVerifyOptions = {}
): void {
  const now =
    typeof options.clockTimestamp === "number"
      ? options.clockTimestamp
      : Math.floor(Date.now() / 1000);

  const tolerance = options.clockTolerance || 0;

  if (typeof payload.nbf !== "undefined") {
    if (typeof payload.nbf !== "number") {
      throw new JsonWebTokenError("Invalid nbf");
    }
    if (now + tolerance < payload.nbf) {
      const date = new Date(payload.nbf * 1000);
      throw new NotBeforeError("jwt not active", date);
    }
  }

  if (typeof payload.exp !== "undefined") {
    if (typeof payload.exp !== "number") {
      throw new JsonWebTokenError("Invalid exp");
    }
    if (now - tolerance >= payload.exp) {
      const date = new Date(payload.exp * 1000);
      throw new TokenExpiredError("jwt expired", date);
    }
  }

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
}

/**
 * Validate audience, issuer, and subject claims (can be used by both HMAC and RSA)
 */
export function validateStandardClaims(
  payload: JwtPayload,
  options: BaseVerifyOptions = {}
) {
  if (options.issuer) {
    const validIssuers = Array.isArray(options.issuer)
      ? options.issuer
      : [options.issuer];
    if (!validIssuers.includes(payload.iss as string)) {
      throw new JsonWebTokenError("invalid issuer");
    }
  }

  if (options.subject && payload.sub !== options.subject) {
    throw new JsonWebTokenError("invalid subject");
  }

  if (options.audience) {
    const audOption = options.audience;
    const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const validAudiences = Array.isArray(audOption) ? audOption : [audOption];

    const match = target.some((aud) => validAudiences.includes(aud as string));
    if (!match) {
      throw new JsonWebTokenError("invalid audience");
    }
  }
}

/**
 * Build payload with standard claims (can be used by both HMAC and RSA)
 */
export function buildPayload(
  payload: JwtPayload,
  options: BaseSignOptions = {}
): JwtPayload {
  const now =
    typeof options.clockTimestamp === "number"
      ? options.clockTimestamp
      : Math.floor(Date.now() / 1000);

  const payloadCopy: JwtPayload =
    typeof payload === "object" && payload !== null
      ? { ...payload }
      : ({} as JwtPayload);

  if (typeof payloadCopy !== "object" || payloadCopy === null) {
    throw new JsonWebTokenError("Payload must be a non-null object");
  }

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

  return payloadCopy;
}

/**
 * Build JWT header (can be used by both HMAC and RSA)
 */
export function buildHeader(
  algorithm: string,
  options: BaseSignOptions = {}
): JwtHeader {
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

  return header;
}

/**
 * Parse and validate JWT structure (can be used by both HMAC and RSA)
 */
export function parseJwtToken(token: string): {
  encodedHeader: string;
  encodedPayload: string;
  signature: string;
  header: JwtHeader;
  payload: JwtPayload;
} {
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

  return {
    encodedHeader,
    encodedPayload,
    signature,
    header,
    payload,
  };
}