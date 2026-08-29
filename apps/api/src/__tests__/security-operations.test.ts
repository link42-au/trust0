import {
	computeFingerprint,
	computeIdentityId,
	createChainLink,
	generateIdentityKey,
} from "@trust0/identity";
import { describe, expect, it, vi } from "vitest";
import {
	emailChallengePublicResponse,
	parseBoundAspeUriFingerprint,
} from "../aspe";
import type { AtomicBatch } from "../atomic";
import { executeAtomicBatch } from "../atomic";
import {
	getImportConflict,
	IMPORT_ATTESTATIONS_POLICY,
	validateImportedChain,
} from "../export";
import type { ApiDb } from "../identity-state";

async function makeIdentity() {
	const key = await generateIdentityKey();
	return {
		...key,
		fingerprint: await computeFingerprint(key.publicJWK),
	};
}

async function makeGenesis() {
	const identity = await makeIdentity();
	const linkJws = await createChainLink({
		seqno: 0,
		prev: null,
		type: "key_init",
		body: { fingerprint: identity.fingerprint },
		key: identity.privateKey,
		publicJWK: identity.publicJWK,
		fingerprint: identity.fingerprint,
	});
	return { identity, linkJws };
}

describe("atomic D1 operations", () => {
	it("submits all writes in one D1 batch", async () => {
		const batch = vi.fn().mockResolvedValue([]);
		const db = { batch } as unknown as ApiDb;
		const statements = [{ id: 1 }, { id: 2 }] as unknown as AtomicBatch;

		await executeAtomicBatch(db, statements);

		expect(batch).toHaveBeenCalledTimes(1);
		expect(batch).toHaveBeenCalledWith(statements);
	});

	it("propagates a failed batch and never retries statements individually", async () => {
		const failure = new Error("D1 batch rolled back");
		const batch = vi.fn().mockRejectedValue(failure);
		const db = { batch } as unknown as ApiDb;
		const statements = [{ id: 1 }, { id: 2 }] as unknown as AtomicBatch;

		await expect(executeAtomicBatch(db, statements)).rejects.toBe(failure);
		expect(batch).toHaveBeenCalledTimes(1);
	});

	it("rejects an empty batch before reaching D1", async () => {
		const batch = vi.fn();
		const db = { batch } as unknown as ApiDb;

		await expect(
			executeAtomicBatch(db, [] as unknown as AtomicBatch),
		).rejects.toThrow("Atomic batch must contain at least one statement");
		expect(batch).not.toHaveBeenCalled();
	});
});

describe("ASPE host binding", () => {
	const fingerprint = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	it("accepts the configured host case-insensitively", () => {
		expect(
			parseBoundAspeUriFingerprint(
				`aspe:TRUST0.EXAMPLE:${fingerprint.toLowerCase()}`,
				"trust0.example",
			),
		).toBe(fingerprint);
	});

	it("rejects a validly shaped URI for another host", () => {
		expect(
			parseBoundAspeUriFingerprint(
				`aspe:attacker.example:${fingerprint}`,
				"trust0.example",
			),
		).toBeNull();
	});

	it("preserves configurable self-host authorities with ports", () => {
		expect(
			parseBoundAspeUriFingerprint(
				`aspe:localhost:8788:${fingerprint}`,
				"localhost:8788",
			),
		).toBe(fingerprint);
	});

	it.each([
		`aspe:trust0.example:${fingerprint.slice(1)}`,
		`aspe:trust0.example:${fingerprint}/profile`,
		`ASPE:trust0.example:${fingerprint}`,
	])("rejects a URI rejected by the canonical parser: %s", (uri) => {
		expect(parseBoundAspeUriFingerprint(uri, "trust0.example")).toBeNull();
	});
});

describe("identity import validation", () => {
	it("accepts a verified genesis chain and derives its identity ID", async () => {
		const { identity, linkJws } = await makeGenesis();
		const result = await validateImportedChain(
			[{ seqno: 0, type: "key_init", linkJws }],
			identity.fingerprint,
		);

		expect(result.identityId).toBe(await computeIdentityId(linkJws));
		expect(result.links).toHaveLength(1);
	});

	it("rejects unsigned metadata tampering around a valid chain link", async () => {
		const { identity, linkJws } = await makeGenesis();

		await expect(
			validateImportedChain(
				[{ seqno: 1, type: "proof_add", linkJws }],
				identity.fingerprint,
			),
		).rejects.toThrow("Chain link metadata does not match signed content");
	});

	it("rejects a tampered signed chain link", async () => {
		const { identity, linkJws } = await makeGenesis();
		const parts = linkJws.split(".");
		parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
		const tampered = parts.join(".");

		await expect(
			validateImportedChain(
				[{ seqno: 0, type: "key_init", linkJws: tampered }],
				identity.fingerprint,
			),
		).rejects.toThrow();
	});

	it("rejects duplicate links before persistence", async () => {
		const { identity, linkJws } = await makeGenesis();

		await expect(
			validateImportedChain(
				[
					{ seqno: 0, type: "key_init", linkJws },
					{ seqno: 0, type: "key_init", linkJws },
				],
				identity.fingerprint,
			),
		).rejects.toThrow("Duplicate sigchain seqno 0");
	});

	it("rejects a claimed identity ID that differs from the signed chain", async () => {
		const { identity, linkJws } = await makeGenesis();

		await expect(
			validateImportedChain(
				[{ seqno: 0, type: "key_init", linkJws }],
				identity.fingerprint,
				"A".repeat(52),
			),
		).rejects.toThrow("Imported identity ID does not match sigchain");
	});

	it("rejects a profile not authorized by the imported chain", async () => {
		const { linkJws } = await makeGenesis();
		const outsider = await makeIdentity();

		await expect(
			validateImportedChain(
				[{ seqno: 0, type: "key_init", linkJws }],
				outsider.fingerprint,
			),
		).rejects.toThrow("Profile fingerprint is not authorized by the sigchain");
	});

	it("reports duplicate user, fingerprint, and identity imports", () => {
		expect(getImportConflict(true, false, false)).toContain(
			"User already has a profile",
		);
		expect(getImportConflict(false, true, false)).toContain(
			"fingerprint already exists",
		);
		expect(getImportConflict(false, false, true)).toContain(
			"Identity already exists",
		);
		expect(getImportConflict(false, false, false)).toBeNull();
	});
});

describe("non-portable server evidence", () => {
	it("requires imported attestations to be recreated locally", () => {
		expect(IMPORT_ATTESTATIONS_POLICY).toContain("were ignored");
		expect(IMPORT_ATTESTATIONS_POLICY).toContain("re-attestation is required");
	});

	it("does not expose the emailed challenge in the API response", () => {
		const response = emailChallengePublicResponse(
			"person@example.com",
			new Date("2030-01-01T00:00:00.000Z"),
		);

		expect(response).toEqual({
			email: "person@example.com",
			expiresAt: "2030-01-01T00:00:00.000Z",
		});
		expect(JSON.stringify(response)).not.toContain("challenge");
	});
});
