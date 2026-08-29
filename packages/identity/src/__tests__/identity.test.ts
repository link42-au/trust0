import { CompactSign, compactVerify, decodeProtectedHeader, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import {
  computeFingerprint,
  createProfile,
  createRequest,
  generateIdentityKey,
  parseProfile,
} from "../index.js";

describe("identity", () => {
  it("generateIdentityKey returns valid Ed25519 keys and public JWK", async () => {
    const result = await generateIdentityKey();

    expect(result.privateKey.type).toBe("private");
    expect(result.privateKey.algorithm.name).toBe("Ed25519");
    expect(result.publicKey.type).toBe("public");
    expect(result.publicKey.algorithm.name).toBe("Ed25519");

    expect(result.publicJWK.kty).toBe("OKP");
    expect(result.publicJWK.crv).toBe("Ed25519");
    expect(typeof result.publicJWK.x).toBe("string");
  });

  it("computeFingerprint returns 26-char uppercase base32", async () => {
    const { publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    expect(fingerprint).toMatch(/^[A-Z2-7]{26}$/);
  });

  it("computeFingerprint is deterministic", async () => {
    const { publicJWK } = await generateIdentityKey();

    const fp1 = await computeFingerprint(publicJWK);
    const fp2 = await computeFingerprint(publicJWK);

    expect(fp1).toBe(fp2);
  });

  it("createProfile returns compact JWS", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profile = await createProfile({
      name: "alice",
      claims: ["https://example.com/claims/email"],
      description: "test profile",
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    expect(profile.split(".")).toHaveLength(3);
  });

  it("parseProfile round-trips a created profile", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profile = await createProfile({
      name: "alice",
      claims: ["claim:a", "claim:b"],
      description: "hello",
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    const parsed = await parseProfile(profile);

    expect(parsed.name).toBe("alice");
    expect(parsed.claims).toEqual(["claim:a", "claim:b"]);
    expect(parsed.description).toBe("hello");
    expect(parsed.fingerprint).toBe(fingerprint);
    expect(parsed.publicJWK.x).toBe(publicJWK.x);
  });

  it("createProfile includes avatar and color, parseProfile round-trips them", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profile = await createProfile({
      name: "alice",
      claims: ["claim:a"],
      description: "hello",
      avatarUrl: "https://example.com/avatar.jpg",
      color: "#FF5733",
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    const parsed = await parseProfile(profile);

    expect(parsed.name).toBe("alice");
    expect(parsed.avatarUrl).toBe("https://example.com/avatar.jpg");
    expect(parsed.color).toBe("#FF5733");
  });

  it("parseProfile handles profiles without avatar/color (backward compat)", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profile = await createProfile({
      name: "bob",
      claims: ["claim:x"],
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    const parsed = await parseProfile(profile);

    expect(parsed.name).toBe("bob");
    expect(parsed.avatarUrl).toBeUndefined();
    expect(parsed.color).toBeUndefined();
  });

  it("parseProfile rejects tampered JWS payload", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profile = await createProfile({
      name: "alice",
      claims: ["claim:a"],
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    const [headerPart, payloadPart, signaturePart] = profile.split(".");
    const lastChar = payloadPart[payloadPart.length - 1];
    const replacementChar = lastChar === "A" ? "B" : "A";
    const tamperedPayload = `${payloadPart.slice(0, -1)}${replacementChar}`;
    const tampered = `${headerPart}.${tamperedPayload}.${signaturePart}`;

    await expect(parseProfile(tampered)).rejects.toThrow();
  });

  it("parseProfile rejects expired profiles when exp is present", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const expiredProfile = await new CompactSign(new TextEncoder().encode(JSON.stringify({
      "http://ariadne.id/version": 0,
      "http://ariadne.id/type": "profile",
      "http://ariadne.id/name": "alice",
      "http://ariadne.id/claims": ["claim:a"],
      exp: Math.floor(Date.now() / 1000) - 60,
    })))
      .setProtectedHeader({ typ: "JWT", alg: "EdDSA", kid: fingerprint, jwk: { kty: "OKP", crv: "Ed25519", x: publicJWK.x! } })
      .sign(privateKey);

    await expect(parseProfile(expiredProfile)).rejects.toThrow("Profile has expired");
  });

  it("createRequest produces valid JWS with expected payload", async () => {
    const { privateKey, publicJWK } = await generateIdentityKey();
    const fingerprint = await computeFingerprint(publicJWK);

    const profileJws = await createProfile({
      name: "alice",
      claims: ["claim:a"],
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    const requestJws = await createRequest({
      action: "update",
      profileJws,
      aspeUri: "https://aspe.example.com/profiles/alice",
      key: privateKey,
      publicJWK,
      fingerprint,
    });

    expect(requestJws.split(".")).toHaveLength(3);

    const header = decodeProtectedHeader(requestJws);
    const verifyKey = await importJWK(publicJWK, "EdDSA");
    const { payload } = await compactVerify(requestJws, verifyKey);
    const parsedPayload = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;

    expect(header.kid).toBe(fingerprint);
    expect(parsedPayload["http://ariadne.id/type"]).toBe("request");
    expect(parsedPayload["http://ariadne.id/action"]).toBe("update");
    expect(parsedPayload["http://ariadne.id/profile_jws"]).toBe(profileJws);
    expect(parsedPayload["http://ariadne.id/aspe_uri"]).toBe("https://aspe.example.com/profiles/alice");
    expect(typeof parsedPayload.iat).toBe("number");
  });
});
