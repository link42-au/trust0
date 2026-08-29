import {
	computeFingerprint,
	computeIdentityId,
	computeLinkHash,
	createChainLink,
	generateIdentityKey,
} from "@trust0/identity";
import { describe, expect, it, vi } from "vitest";
import {
	classifyKeyRotationRecovery,
	detectKeyRotationRecovery,
	executeKeyRotation,
	type KeyRotationOperations,
	KeyRotationProfileUpdateError,
	type KeyRotationRecovery,
	type KeyRotationRecoveryOperations,
	resumeKeyRotation,
	type StoredIdentity,
} from "../../../web/src/lib/identity";

const identity = (fingerprint: string): StoredIdentity => ({
	privateKey: {} as CryptoKey,
	publicKey: {} as CryptoKey,
	publicJWK: { kty: "OKP", crv: "Ed25519", x: `${fingerprint}-x` },
	fingerprint,
});

const realIdentity = async (): Promise<StoredIdentity> => {
	const keys = await generateIdentityKey();
	return {
		...keys,
		fingerprint: await computeFingerprint(keys.publicJWK),
	};
};

const makeOperations = (
	events: string[],
	overrides: Partial<KeyRotationOperations> = {},
): KeyRotationOperations => ({
	generateIdentity: async () => {
		events.push("generate");
		return identity("new-key");
	},
	appendAfterAction: vi.fn(async (signer, _identityId, type) => {
		events.push(`append:${type}:${signer.fingerprint}`);
	}),
	storeIdentity: vi.fn(async (stored) => {
		events.push(`store:${stored.fingerprint}`);
	}),
	updateProfile: vi.fn(
		async (signer, _name, _claims, _description, _avatar, _color, target) => {
			events.push(`profile:${signer.fingerprint}:${target}`);
		},
	),
	...overrides,
});

describe("web key rotation contract", () => {
	it("moves the sigchain before replacing the local key and profile", async () => {
		const events: string[] = [];
		const oldIdentity = identity("old-key");

		await expect(
			executeKeyRotation(
				oldIdentity,
				"identity-id",
				"Alice",
				["https://example.com/alice"],
				undefined,
				undefined,
				undefined,
				makeOperations(events),
			),
		).resolves.toMatchObject({ fingerprint: "new-key" });

		expect(events).toEqual([
			"generate",
			"append:key_rotate:old-key",
			"store:new-key",
			"append:profile_update:new-key",
			"profile:new-key:old-key",
		]);
	});

	it("does not replace the profile when the sigchain cannot name the new key", async () => {
		const events: string[] = [];
		const failure = new Error("profile transition rejected");
		const operations = makeOperations(events, {
			appendAfterAction: vi.fn(async (signer, _identityId, type) => {
				events.push(`append:${type}:${signer.fingerprint}`);
				if (type === "profile_update") throw failure;
			}),
		});

		const result = executeKeyRotation(
			identity("old-key"),
			"identity-id",
			"Alice",
			[],
			undefined,
			undefined,
			undefined,
			operations,
		);

		await expect(result).rejects.toMatchObject({
			identity: { fingerprint: "new-key" },
			phase: "chain-profile-update",
			targetFingerprint: "old-key",
			cause: failure,
		});
		await expect(result).rejects.toBeInstanceOf(KeyRotationProfileUpdateError);

		expect(operations.storeIdentity).toHaveBeenCalledWith(
			expect.objectContaining({ fingerprint: "new-key" }),
		);
		expect(operations.updateProfile).not.toHaveBeenCalled();
	});

	it("stops before profile_update when the new key cannot be stored", async () => {
		const events: string[] = [];
		const failure = new Error("IndexedDB unavailable");
		const operations = makeOperations(events, {
			storeIdentity: vi.fn(async () => {
				events.push("store:failed");
				throw failure;
			}),
		});

		await expect(
			executeKeyRotation(
				identity("old-key"),
				"identity-id",
				"Alice",
				[],
				undefined,
				undefined,
				undefined,
				operations,
			),
		).rejects.toBe(failure);

		expect(operations.appendAfterAction).toHaveBeenCalledTimes(1);
		expect(operations.appendAfterAction).toHaveBeenCalledWith(
			expect.objectContaining({ fingerprint: "old-key" }),
			"identity-id",
			"key_rotate",
			expect.objectContaining({ new_fingerprint: "new-key" }),
		);
		expect(operations.updateProfile).not.toHaveBeenCalled();
		expect(events).toEqual([
			"generate",
			"append:key_rotate:old-key",
			"store:failed",
		]);
	});

	it("retains and reports the new usable key when profile replacement fails", async () => {
		const events: string[] = [];
		const failure = new Error("ASPE unavailable");
		const operations = makeOperations(events, {
			updateProfile: vi.fn(async () => {
				events.push("profile:failed");
				throw failure;
			}),
		});

		const result = executeKeyRotation(
			identity("old-key"),
			"identity-id",
			"Alice",
			[],
			undefined,
			undefined,
			undefined,
			operations,
		);

		await expect(result).rejects.toMatchObject({
			name: "KeyRotationProfileUpdateError",
			identity: { fingerprint: "new-key" },
			phase: "public-profile-update",
			targetFingerprint: "old-key",
			cause: failure,
		});
		await expect(result).rejects.toBeInstanceOf(KeyRotationProfileUpdateError);
		expect(events).toEqual([
			"generate",
			"append:key_rotate:old-key",
			"store:new-key",
			"append:profile_update:new-key",
			"profile:failed",
		]);
	});

	it("preserves optional profile fields while rotating", async () => {
		const events: string[] = [];
		const operations = makeOperations(events);

		await executeKeyRotation(
			identity("old-key"),
			"identity-id",
			"Alice",
			[],
			"Bio",
			"https://example.com/avatar.png",
			"#008877",
			operations,
		);

		expect(operations.updateProfile).toHaveBeenCalledWith(
			expect.objectContaining({ fingerprint: "new-key" }),
			"Alice",
			[],
			"Bio",
			"https://example.com/avatar.png",
			"#008877",
			"old-key",
		);
	});
});

const makeRecoveryOperations = (
	events: string[],
	recovery: KeyRotationRecovery | null,
	overrides: Partial<KeyRotationRecoveryOperations> = {},
): KeyRotationRecoveryOperations => ({
	fetchChain: vi.fn(async () => {
		events.push("fetch");
		return {
			identityId: "identity-id",
			fingerprint: "old-key",
			links: [],
		};
	}),
	detectKeyRotationRecovery: vi.fn(async () => {
		events.push("inspect");
		return recovery;
	}),
	appendAfterAction: vi.fn(async (signer, _identityId, type) => {
		events.push(`append:${type}:${signer.fingerprint}`);
	}),
	updateProfile: vi.fn(
		async (signer, _name, _claims, _description, _avatar, _color, target) => {
			events.push(`profile:${signer.fingerprint}:${target}`);
		},
	),
	...overrides,
});

describe("interrupted key rotation recovery", () => {
	it("infers the pending step after reload from verified chain state", () => {
		const activeFingerprints = new Set(["old-key", "new-key"]);

		expect(
			classifyKeyRotationRecovery("new-key", "old-key", {
				activeFingerprints,
				currentProfileFingerprint: "old-key",
			}),
		).toEqual({
			phase: "chain-profile-update",
			targetFingerprint: "old-key",
		});

		expect(
			classifyKeyRotationRecovery("new-key", "old-key", {
				activeFingerprints,
				currentProfileFingerprint: "new-key",
			}),
		).toEqual({
			phase: "public-profile-update",
			targetFingerprint: "old-key",
		});

		expect(
			classifyKeyRotationRecovery("old-key", "old-key", {
				activeFingerprints,
				currentProfileFingerprint: "old-key",
			}),
		).toBeNull();
	});

	it("verifies the signed chain when inferring recovery after reload", async () => {
		const oldIdentity = await realIdentity();
		const newIdentity = await realIdentity();
		const genesis = await createChainLink({
			seqno: 0,
			prev: null,
			type: "key_init",
			body: { fingerprint: oldIdentity.fingerprint },
			key: oldIdentity.privateKey,
			publicJWK: oldIdentity.publicJWK,
			fingerprint: oldIdentity.fingerprint,
		});
		const rotationPrev = await computeLinkHash(genesis);
		const rotation = await createChainLink({
			seqno: 1,
			prev: rotationPrev,
			type: "key_rotate",
			body: { new_fingerprint: newIdentity.fingerprint },
			key: oldIdentity.privateKey,
			publicJWK: oldIdentity.publicJWK,
			fingerprint: oldIdentity.fingerprint,
		});

		const identityId = await computeIdentityId(genesis);
		await expect(
			detectKeyRotationRecovery(newIdentity, oldIdentity.fingerprint, {
				identityId,
				fingerprint: oldIdentity.fingerprint,
				links: [genesis, rotation].map((linkJws, seqno) => ({
					seqno,
					type: seqno === 0 ? "key_init" : "key_rotate",
					linkJws,
					prevHash: seqno === 0 ? null : rotationPrev,
					createdAt: new Date(0).toISOString(),
				})),
			}),
		).resolves.toEqual({
			phase: "chain-profile-update",
			targetFingerprint: oldIdentity.fingerprint,
		});
	});

	it("appends the missing transition before replacing the public profile", async () => {
		const events: string[] = [];
		const operations = makeRecoveryOperations(events, {
			phase: "chain-profile-update",
			targetFingerprint: "old-key",
		});

		await resumeKeyRotation(
			identity("new-key"),
			"identity-id",
			"old-key",
			{ name: "Alice", claims: [] },
			operations,
		);

		expect(events).toEqual([
			"fetch",
			"inspect",
			"append:profile_update:new-key",
			"profile:new-key:old-key",
		]);
	});

	it("does not append a duplicate transition when only ASPE remains", async () => {
		const events: string[] = [];
		const operations = makeRecoveryOperations(events, {
			phase: "public-profile-update",
			targetFingerprint: "old-key",
		});

		await resumeKeyRotation(
			identity("new-key"),
			"identity-id",
			"old-key",
			{ name: "Alice", claims: [] },
			operations,
		);

		expect(events).toEqual(["fetch", "inspect", "profile:new-key:old-key"]);
		expect(operations.appendAfterAction).not.toHaveBeenCalled();
	});

	it("keeps append failures resumable with the new identity and pending phase", async () => {
		const events: string[] = [];
		const failure = new Error("append unavailable");
		const operations = makeRecoveryOperations(
			events,
			{
				phase: "chain-profile-update",
				targetFingerprint: "old-key",
			},
			{
				appendAfterAction: vi.fn(async () => {
					events.push("append:failed");
					throw failure;
				}),
			},
		);

		await expect(
			resumeKeyRotation(
				identity("new-key"),
				"identity-id",
				"old-key",
				{ name: "Alice", claims: [] },
				operations,
			),
		).rejects.toMatchObject({
			identity: { fingerprint: "new-key" },
			phase: "chain-profile-update",
			targetFingerprint: "old-key",
			cause: failure,
		});
		expect(operations.updateProfile).not.toHaveBeenCalled();
	});

	it("keeps ASPE retries resumable without changing the completed chain phase", async () => {
		const events: string[] = [];
		const failure = new Error("ASPE unavailable");
		const operations = makeRecoveryOperations(
			events,
			{
				phase: "public-profile-update",
				targetFingerprint: "old-key",
			},
			{
				updateProfile: vi.fn(async () => {
					events.push("profile:failed");
					throw failure;
				}),
			},
		);

		await expect(
			resumeKeyRotation(
				identity("new-key"),
				"identity-id",
				"old-key",
				{ name: "Alice", claims: [] },
				operations,
			),
		).rejects.toMatchObject({
			identity: { fingerprint: "new-key" },
			phase: "public-profile-update",
			targetFingerprint: "old-key",
			cause: failure,
		});
		expect(operations.appendAfterAction).not.toHaveBeenCalled();
	});
});
