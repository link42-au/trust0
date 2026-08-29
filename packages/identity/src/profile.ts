import {
  CompactSign,
  compactVerify,
  decodeProtectedHeader,
  importJWK,
  type JWTPayload,
  type JWK,
} from "jose";
import { computeFingerprint } from "./keys.js";

type ProfileParams = {
  name: string;
  claims: string[];
  description?: string;
  avatarUrl?: string;
  color?: string;
  key: CryptoKey;
  publicJWK: JsonWebKey;
  fingerprint: string;
};

type ParsedProfile = {
  name: string;
  claims: string[];
  description?: string;
  avatarUrl?: string;
  color?: string;
  fingerprint: string;
  publicJWK: JsonWebKey;
};

type RequestParams = {
  action: "create" | "update" | "delete";
  profileJws?: string;
  aspeUri?: string;
  key: CryptoKey;
  publicJWK: JsonWebKey;
  fingerprint: string;
};

function getHeaderJwk(publicJWK: JsonWebKey): { kty: "OKP"; crv: "Ed25519"; x: string } {
  if (publicJWK.kty !== "OKP" || publicJWK.crv !== "Ed25519" || typeof publicJWK.x !== "string") {
    throw new Error("Invalid Ed25519 public JWK");
  }

  return {
    kty: "OKP",
    crv: "Ed25519",
    x: publicJWK.x,
  };
}

export async function createProfile(params: ProfileParams): Promise<string> {
  const { name, claims, description, avatarUrl, color, key, publicJWK, fingerprint } = params;

  const payload: Record<string, string | number | string[]> = {
    "http://ariadne.id/version": 0,
    "http://ariadne.id/type": "profile",
    "http://ariadne.id/name": name,
    "http://ariadne.id/claims": claims,
  };

  if (description !== undefined) {
    payload["http://ariadne.id/description"] = description;
  }

  if (avatarUrl !== undefined) {
    payload["http://ariadne.id/avatar_url"] = avatarUrl;
  }

  if (color !== undefined) {
    payload["http://ariadne.id/color"] = color;
  }

  return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      typ: "JWT",
      alg: "EdDSA",
      kid: fingerprint,
      jwk: getHeaderJwk(publicJWK),
    })
    .sign(key);
}

export async function parseProfile(jws: string): Promise<ParsedProfile> {
  const header = decodeProtectedHeader(jws);

  if (typeof header.kid !== "string") {
    throw new Error("Missing or invalid profile key id");
  }

  if (!header.jwk || typeof header.jwk !== "object") {
    throw new Error("Missing profile public JWK");
  }

  const publicJWK: JsonWebKey = header.jwk;
  const fingerprint = await computeFingerprint(publicJWK);

  if (fingerprint !== header.kid) {
    throw new Error("Profile fingerprint mismatch");
  }

  const key = await importJWK(publicJWK as JWK, "EdDSA");
  const { payload } = await compactVerify(jws, key);
  const decodedPayload = JSON.parse(new TextDecoder().decode(payload)) as JWTPayload;

  if (decodedPayload["http://ariadne.id/type"] !== "profile") {
    throw new Error("Invalid profile payload type");
  }

  if (decodedPayload["http://ariadne.id/version"] !== 0) {
    throw new Error("Unsupported profile payload version");
  }

  const exp = decodedPayload.exp;
  if (exp !== undefined) {
    if (typeof exp !== "number") {
      throw new Error("Invalid profile expiration");
    }

    const now = Math.floor(Date.now() / 1000);
    if (exp <= now) {
      throw new Error("Profile has expired");
    }
  }

  const name = decodedPayload["http://ariadne.id/name"];
  const claims = decodedPayload["http://ariadne.id/claims"];
  const description = decodedPayload["http://ariadne.id/description"];

  if (typeof name !== "string") {
    throw new Error("Invalid profile name");
  }

  if (!Array.isArray(claims) || !claims.every((claim) => typeof claim === "string")) {
    throw new Error("Invalid profile claims");
  }

  if (description !== undefined && typeof description !== "string") {
    throw new Error("Invalid profile description");
  }

  const avatarUrl = decodedPayload["http://ariadne.id/avatar_url"];
  const color = decodedPayload["http://ariadne.id/color"];

  if (avatarUrl !== undefined && typeof avatarUrl !== "string") {
    throw new Error("Invalid profile avatar URL");
  }

  if (color !== undefined && typeof color !== "string") {
    throw new Error("Invalid profile color");
  }

  return {
    name,
    claims,
    description,
    avatarUrl,
    color,
    fingerprint,
    publicJWK,
  };
}

export async function createRequest(params: RequestParams): Promise<string> {
  const { action, profileJws, aspeUri, key, publicJWK, fingerprint } = params;

  if ((action === "create" || action === "update") && typeof profileJws !== "string") {
    throw new Error("profileJws is required for create/update requests");
  }

  if ((action === "update" || action === "delete") && typeof aspeUri !== "string") {
    throw new Error("aspeUri is required for update/delete requests");
  }

  const payload: Record<string, string | number> = {
    "http://ariadne.id/version": 0,
    "http://ariadne.id/type": "request",
    "http://ariadne.id/action": action,
    iat: Math.floor(Date.now() / 1000),
  };

  if (profileJws !== undefined) {
    payload["http://ariadne.id/profile_jws"] = profileJws;
  }

  if (aspeUri !== undefined) {
    payload["http://ariadne.id/aspe_uri"] = aspeUri;
  }

  return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      typ: "JWT",
      alg: "EdDSA",
      kid: fingerprint,
      jwk: getHeaderJwk(publicJWK),
    })
    .sign(key);
}

type ParsedRequest = {
  action: "create" | "update" | "delete";
  profileJws?: string;
  aspeUri?: string;
  fingerprint: string;
  publicJWK: JsonWebKey;
  iat: number;
};

export async function parseRequest(jws: string): Promise<ParsedRequest> {
  const header = decodeProtectedHeader(jws);

  if (typeof header.kid !== "string") {
    throw new Error("Missing or invalid request key id");
  }

  if (!header.jwk || typeof header.jwk !== "object") {
    throw new Error("Missing request public JWK");
  }

  const publicJWK: JsonWebKey = header.jwk;
  const fingerprint = await computeFingerprint(publicJWK);

  if (fingerprint !== header.kid) {
    throw new Error("Request fingerprint mismatch");
  }

  const key = await importJWK(publicJWK as JWK, "EdDSA");
  const { payload } = await compactVerify(jws, key);
  const decoded = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;

  if (decoded["http://ariadne.id/type"] !== "request") {
    throw new Error("Invalid request payload type");
  }

  if (decoded["http://ariadne.id/version"] !== 0) {
    throw new Error("Unsupported request version");
  }

  const action = decoded["http://ariadne.id/action"];
  if (action !== "create" && action !== "update" && action !== "delete") {
    throw new Error("Invalid request action");
  }

  const iat = decoded.iat;
  if (typeof iat !== "number") {
    throw new Error("Missing or invalid iat");
  }

  // SPEC DEVIATION (APC-001): Ariadne ASP spec says 60 seconds.
  // We use 300s (5 min) for clock skew and mobile/high-latency clients.
  // See: dev/spec/proposed-changes.md#apc-001
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - iat) > 300) {
    throw new Error("Request expired or clock skew too large");
  }

  return {
    action,
    profileJws: typeof decoded["http://ariadne.id/profile_jws"] === "string" ? decoded["http://ariadne.id/profile_jws"] : undefined,
    aspeUri: typeof decoded["http://ariadne.id/aspe_uri"] === "string" ? decoded["http://ariadne.id/aspe_uri"] : undefined,
    fingerprint,
    publicJWK,
    iat,
  };
}
