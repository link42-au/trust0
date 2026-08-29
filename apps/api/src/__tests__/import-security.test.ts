import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import {
	computeFingerprint,
	computeLinkHash,
	createChainLink,
	createProfile,
	generateIdentityKey,
} from "@trust0/identity";
import { drizzle } from "drizzle-orm/d1";
import { CompactSign } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../db/schema";
import type { ApiDb } from "../identity-state";
import type { Env } from "../types";

type MockContext = {
	set: (key: string, value: unknown) => void;
	get: (key: string) => unknown;
	json: (body: unknown, status?: number) => Response;
	req: { header: (name: string) => string | undefined };
};

const routeState = vi.hoisted(() => ({
	userId: "user-a",
	sessionId: "session-a",
	db: null as unknown,
}));

vi.mock("../middleware/session", () => ({
	sessionMiddleware: async (
		context: MockContext,
		next: () => Promise<void>,
	) => {
		context.set("user", {
			id: context.req.header("x-test-user") || routeState.userId,
		});
		context.set("session", {
			id: context.req.header("x-test-session") || routeState.sessionId,
		});
		context.set("db", routeState.db);
		await next();
	},
	requireAuth: async (context: MockContext, next: () => Promise<void>) => {
		if (!context.get("user")) {
			return context.json({ error: "Unauthorized" }, 401);
		}
		await next();
	},
}));

import {
	assertSupportedImportChainLength,
	chunkImportChainRows,
	computeImportBundleDigest,
	createImportProofClaims,
	exportRoutes,
	IMPORT_CHAIN_INSERT_ROWS,
	IMPORT_PROOF_TYPE,
	MAX_IMPORT_CHAIN_LINKS,
	persistGuardedImport,
	verifyImportProof,
} from "../export";

type Bundle = Parameters<typeof computeImportBundleDigest>[0];

type BoundStatement = {
	query: string;
	params: SQLInputValue[];
};

const successResult = (changes: number) => ({
	success: true as const,
	results: [],
	meta: {
		changed_db: changes > 0,
		changes,
		duration: 0,
		last_row_id: 0,
		rows_read: 0,
		rows_written: changes,
		size_after: 0,
	},
});

class SqliteD1Adapter {
	readonly sqlite = new DatabaseSync(":memory:");
	readonly batchParameterCounts: number[][] = [];
	readonly batchStatementCounts: number[] = [];
	private verificationReadBarrier: Promise<void> | null = null;
	private releaseVerificationReads: (() => void) | null = null;
	private synchronizedVerificationReads = 0;
	private batchQueue = Promise.resolve();

	constructor() {
		this.sqlite.exec(`
			create table crypto_profile (
				fingerprint text primary key,
				profile_jws text not null,
				user_id text not null,
				identity_id text,
				created_at integer not null,
				updated_at integer not null
			);
			create table sigchain_link (
				id text primary key,
				identity_id text not null,
				fingerprint text not null,
				seqno integer not null,
				link_type text not null,
				link_jws text not null,
				prev_hash text,
				created_at integer not null
			);
			create table verification (
				id text primary key,
				identifier text not null,
				value text not null,
				expires_at integer not null,
				created_at integer,
				updated_at integer
			);
		`);
	}

	synchronizeNextTwoVerificationReads() {
		this.verificationReadBarrier = new Promise((resolve) => {
			this.releaseVerificationReads = resolve;
		});
	}

	prepare(query: string) {
		const bind = (...params: SQLInputValue[]) => {
			const statement = { query, params };
			return {
				...statement,
				all: async () => await this.all(statement),
				raw: async () =>
					(await this.all(statement)).results.map((row) => Object.values(row)),
				run: async () => this.run(statement),
			};
		};

		return { bind } as unknown as D1PreparedStatement;
	}

	async batch(statements: D1PreparedStatement[]) {
		const bound = statements as unknown as BoundStatement[];
		this.batchStatementCounts.push(bound.length);
		this.batchParameterCounts.push(
			bound.map((statement) => statement.params.length),
		);
		const execute = async () => {
			this.sqlite.exec("begin immediate");
			try {
				const results = bound.map((statement) => this.run(statement));
				this.sqlite.exec("commit");
				return results;
			} catch (error) {
				this.sqlite.exec("rollback");
				throw error;
			}
		};
		const queued = this.batchQueue.then(execute, execute);
		this.batchQueue = queued.then(
			() => undefined,
			() => undefined,
		);
		return await queued;
	}

	close() {
		this.sqlite.close();
	}

	private async all(statement: BoundStatement) {
		const results = this.sqlite
			.prepare(statement.query)
			.all(...statement.params) as Record<string, unknown>[];

		if (
			this.verificationReadBarrier &&
			statement.query.includes('from "verification"')
		) {
			this.synchronizedVerificationReads += 1;
			if (this.synchronizedVerificationReads === 2) {
				this.releaseVerificationReads?.();
			}
			await this.verificationReadBarrier;
		}

		return { success: true, results, meta: successResult(0).meta };
	}

	private run(statement: BoundStatement) {
		const result = this.sqlite
			.prepare(statement.query)
			.run(...statement.params);
		return successResult(Number(result.changes));
	}
}

async function makeBundle(): Promise<{
	bundle: Bundle;
	privateKey: CryptoKey;
	publicJWK: JsonWebKey;
	fingerprint: string;
}> {
	const { privateKey, publicJWK } = await generateIdentityKey();
	const fingerprint = await computeFingerprint(publicJWK);
	const profileJws = await createProfile({
		name: "Portable person",
		claims: [],
		key: privateKey,
		publicJWK,
		fingerprint,
	});
	const linkJws = await createChainLink({
		seqno: 0,
		prev: null,
		type: "key_init",
		body: { fingerprint },
		key: privateKey,
		publicJWK,
		fingerprint,
	});
	return {
		bundle: {
			version: 1,
			profile: { fingerprint, profileJws },
			chain: [{ seqno: 0, type: "key_init", linkJws }],
		},
		privateKey,
		publicJWK,
		fingerprint,
	};
}

async function makeSharedIdentityBundles(): Promise<{
	first: Awaited<ReturnType<typeof makeBundle>>;
	second: Awaited<ReturnType<typeof makeBundle>>;
}> {
	const firstKey = await generateIdentityKey();
	const firstFingerprint = await computeFingerprint(firstKey.publicJWK);
	const secondKey = await generateIdentityKey();
	const secondFingerprint = await computeFingerprint(secondKey.publicJWK);
	const genesisJws = await createChainLink({
		seqno: 0,
		prev: null,
		type: "key_init",
		body: { fingerprint: firstFingerprint },
		key: firstKey.privateKey,
		publicJWK: firstKey.publicJWK,
		fingerprint: firstFingerprint,
	});
	const rotationJws = await createChainLink({
		seqno: 1,
		prev: await computeLinkHash(genesisJws),
		type: "key_rotate",
		body: { new_fingerprint: secondFingerprint },
		key: firstKey.privateKey,
		publicJWK: firstKey.publicJWK,
		fingerprint: firstFingerprint,
	});
	const chain = [
		{ seqno: 0, type: "key_init", linkJws: genesisJws },
		{ seqno: 1, type: "key_rotate", linkJws: rotationJws },
	];
	const firstProfileJws = await createProfile({
		name: "First current profile",
		claims: [],
		key: firstKey.privateKey,
		publicJWK: firstKey.publicJWK,
		fingerprint: firstFingerprint,
	});
	const secondProfileJws = await createProfile({
		name: "Second current profile",
		claims: [],
		key: secondKey.privateKey,
		publicJWK: secondKey.publicJWK,
		fingerprint: secondFingerprint,
	});

	return {
		first: {
			bundle: {
				version: 1,
				profile: {
					fingerprint: firstFingerprint,
					profileJws: firstProfileJws,
				},
				chain,
			},
			privateKey: firstKey.privateKey,
			publicJWK: firstKey.publicJWK,
			fingerprint: firstFingerprint,
		},
		second: {
			bundle: {
				version: 1,
				profile: {
					fingerprint: secondFingerprint,
					profileJws: secondProfileJws,
				},
				chain,
			},
			privateKey: secondKey.privateKey,
			publicJWK: secondKey.publicJWK,
			fingerprint: secondFingerprint,
		},
	};
}

async function signProof(
	claims: ReturnType<typeof createImportProofClaims>,
	privateKey: CryptoKey,
	fingerprint: string,
): Promise<string> {
	return await new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
		.setProtectedHeader({
			typ: IMPORT_PROOF_TYPE,
			alg: "EdDSA",
			kid: fingerprint,
		})
		.sign(privateKey);
}

async function issueChallenge(
	bundle: Bundle,
	identity = { userId: routeState.userId, sessionId: routeState.sessionId },
) {
	const response = await exportRoutes.request(
		"/api/identity/import/challenge",
		{
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-test-user": identity.userId,
				"x-test-session": identity.sessionId,
			},
			body: JSON.stringify({ bundle }),
		},
		TEST_BINDINGS,
	);
	expect(response.status).toBe(201);
	return (await response.json()) as {
		challenge: ReturnType<typeof createImportProofClaims>;
		expiresAt: string;
	};
}

async function submitImport(
	bundle: Bundle,
	proof: string,
	identity = { userId: routeState.userId, sessionId: routeState.sessionId },
) {
	return await exportRoutes.request(
		"/api/identity/import",
		{
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-test-user": identity.userId,
				"x-test-session": identity.sessionId,
			},
			body: JSON.stringify({ ...bundle, proof }),
		},
		TEST_BINDINGS,
	);
}

const TEST_BINDINGS: Env["Bindings"] = {
	DB: {} as D1Database,
	AUTH_SECRET: "test",
	AUTH_URL: "https://trust0.example",
	ALLOWED_ORIGINS: "https://trust0.example",
	GITHUB_CLIENT_ID: "test",
	GITHUB_CLIENT_SECRET: "test",
	RESEND_API_KEY: "test",
	EMAIL_FROM: "test@example.com",
	BOT_API_KEY: "test",
	ASPE_DOMAIN: "trust0.example",
};

let adapter: SqliteD1Adapter;

beforeEach(() => {
	routeState.userId = "user-a";
	routeState.sessionId = "session-a";
	adapter = new SqliteD1Adapter();
	routeState.db = drizzle(adapter as unknown as D1Database, { schema });
});

afterEach(() => {
	adapter.close();
});

describe("identity import proof", () => {
	it("binds a valid signature to user, session, authority, bundle, and nonce", async () => {
		const { bundle, privateKey, publicJWK, fingerprint } = await makeBundle();
		const digest = await computeImportBundleDigest(bundle);
		const claims = createImportProofClaims(
			"user-a",
			"session-a",
			"trust0.example",
			digest,
			"ab".repeat(32),
			new Date("2030-01-01T00:00:00.000Z"),
		);
		const proof = await signProof(claims, privateKey, fingerprint);

		await expect(
			verifyImportProof(
				proof,
				publicJWK,
				fingerprint,
				claims,
				new Date("2030-01-01T00:01:00.000Z"),
			),
		).resolves.toBeUndefined();
	});

	it("rejects public replay without the imported private key", async () => {
		const owner = await makeBundle();
		const attacker = await generateIdentityKey();
		const claims = createImportProofClaims(
			"user-a",
			"session-a",
			"trust0.example",
			await computeImportBundleDigest(owner.bundle),
			"cd".repeat(32),
		);
		const forged = await signProof(
			claims,
			attacker.privateKey,
			owner.fingerprint,
		);

		await expect(
			verifyImportProof(forged, owner.publicJWK, owner.fingerprint, claims),
		).rejects.toThrow();
	});

	it("rejects cross-session, changed-bundle, and expired proof claims", async () => {
		const owner = await makeBundle();
		const claims = createImportProofClaims(
			"user-a",
			"session-a",
			"trust0.example",
			await computeImportBundleDigest(owner.bundle),
			"ef".repeat(32),
			new Date("2030-01-01T00:00:00.000Z"),
		);
		const proof = await signProof(claims, owner.privateKey, owner.fingerprint);

		await expect(
			verifyImportProof(proof, owner.publicJWK, owner.fingerprint, {
				...claims,
				sessionId: "session-b",
			}),
		).rejects.toThrow("not bound");
		await expect(
			verifyImportProof(proof, owner.publicJWK, owner.fingerprint, {
				...claims,
				bundleDigest: `sha256:${"x".repeat(43)}`,
			}),
		).rejects.toThrow("not bound");
		await expect(
			verifyImportProof(proof, owner.publicJWK, owner.fingerprint, {
				...claims,
				authority: "attacker.example",
			}),
		).rejects.toThrow("not bound");
		await expect(
			verifyImportProof(
				proof,
				owner.publicJWK,
				owner.fingerprint,
				claims,
				new Date("2030-01-01T00:06:00.000Z"),
			),
		).rejects.toThrow("expired");
	});
});

describe("identity import bundle limits", () => {
	it("uses a deterministic digest and excludes ignored attestations", async () => {
		const { bundle } = await makeBundle();
		const first = await computeImportBundleDigest(bundle);
		const second = await computeImportBundleDigest({
			...bundle,
			attestations: [
				{
					type: "discord",
					value: "untrusted",
					attestedBy: "another-instance",
					attestedAt: "2030-01-01T00:00:00.000Z",
				},
			],
		});

		expect(first).toBe(second);
		expect(first).toMatch(/^sha256:[A-Za-z0-9_-]{43}$/);
	});

	it("accepts the bounded maximum and rejects one link above it", () => {
		expect(() =>
			assertSupportedImportChainLength(MAX_IMPORT_CHAIN_LINKS - 1),
		).not.toThrow();
		expect(() =>
			assertSupportedImportChainLength(MAX_IMPORT_CHAIN_LINKS),
		).not.toThrow();
		expect(() =>
			assertSupportedImportChainLength(MAX_IMPORT_CHAIN_LINKS + 1),
		).toThrow(`${MAX_IMPORT_CHAIN_LINKS}-link import limit`);
	});

	it("chunks the maximum chain into bound-parameter-safe multi-row inserts", () => {
		const rows = Array.from(
			{ length: MAX_IMPORT_CHAIN_LINKS },
			(_, index) => index,
		);
		const chunks = chunkImportChainRows(rows);

		expect(chunks.flat()).toEqual(rows);
		expect(chunks).toHaveLength(
			Math.ceil(MAX_IMPORT_CHAIN_LINKS / IMPORT_CHAIN_INSERT_ROWS),
		);
		expect(
			chunks.every((chunk) => chunk.length <= IMPORT_CHAIN_INSERT_ROWS),
		).toBe(true);
	});

	it("executes the maximum guarded import below D1 query and parameter limits", async () => {
		const now = new Date();
		const expiresAt = Math.floor(now.getTime() / 1000) + 300;
		adapter.sqlite
			.prepare("insert into verification values (?, ?, ?, ?, ?, ?)")
			.run(
				"challenge-id",
				"challenge-identifier",
				"challenge-value",
				expiresAt,
				Math.floor(now.getTime() / 1000),
				Math.floor(now.getTime() / 1000),
			);
		const links = Array.from(
			{ length: MAX_IMPORT_CHAIN_LINKS },
			(_, index) => ({
				id: `link-${index}`,
				fingerprint: "A".repeat(26),
				seqno: index,
				type: index === 0 ? "key_init" : "proof_add",
				linkJws: `jws-${index}`,
				prevHash: index === 0 ? null : `link-${index - 1}`,
			}),
		);

		await expect(
			persistGuardedImport(routeState.db as ApiDb, {
				challengeId: "challenge-id",
				challengeIdentifier: "challenge-identifier",
				challengeValue: "challenge-value",
				profile: {
					fingerprint: "A".repeat(26),
					profileJws: "profile-jws",
					userId: "user-a",
					identityId: "identity-a",
				},
				links,
				now,
			}),
		).resolves.toBe(true);
		expect(adapter.batchStatementCounts).toEqual([7]);
		expect(Math.max(...adapter.batchParameterCounts[0])).toBeLessThanOrEqual(
			100,
		);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: MAX_IMPORT_CHAIN_LINKS });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from verification")
				.get(),
		).toEqual({ count: 0 });
	});
});

describe("identity import routes", () => {
	it("consumes a challenge atomically and persists all links in one insert", async () => {
		const owner = await makeBundle();
		const { challenge } = await issueChallenge(owner.bundle);
		const proof = await signProof(
			challenge,
			owner.privateKey,
			owner.fingerprint,
		);

		const response = await submitImport(owner.bundle, proof);
		expect(response.status).toBe(201);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from crypto_profile")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from verification")
				.get(),
		).toEqual({ count: 0 });
	});

	it("accepts a chainless legacy bundle only with its profile key proof", async () => {
		const owner = await makeBundle();
		const legacyBundle = { ...owner.bundle, chain: [] };
		const challengeResponse = await issueChallenge(legacyBundle);
		expect(JSON.stringify(challengeResponse)).not.toContain("email");
		const proof = await signProof(
			challengeResponse.challenge,
			owner.privateKey,
			owner.fingerprint,
		);

		const response = await submitImport(legacyBundle, proof);
		expect(response.status).toBe(201);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from crypto_profile")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: 0 });
	});

	it("keeps one challenge per user and lets a new session invalidate the old proof", async () => {
		const owner = await makeBundle();
		const firstIdentity = { userId: "user-a", sessionId: "session-a" };
		const secondIdentity = { userId: "user-a", sessionId: "session-b" };
		const first = await issueChallenge(owner.bundle, firstIdentity);
		const firstProof = await signProof(
			first.challenge,
			owner.privateKey,
			owner.fingerprint,
		);
		const second = await issueChallenge(owner.bundle, secondIdentity);

		expect(second.challenge.nonce).not.toBe(first.challenge.nonce);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from verification")
				.get(),
		).toEqual({ count: 1 });
		const staleResponse = await submitImport(
			owner.bundle,
			firstProof,
			firstIdentity,
		);
		expect(staleResponse.status).toBe(409);
		expect(await staleResponse.json()).toMatchObject({
			error: expect.stringContaining("another session"),
		});

		const currentProof = await signProof(
			second.challenge,
			owner.privateKey,
			owner.fingerprint,
		);
		expect(
			(await submitImport(owner.bundle, currentProof, secondIdentity)).status,
		).toBe(201);
	});

	it("rejects a challenge from another authenticated session", async () => {
		const owner = await makeBundle();
		const { challenge } = await issueChallenge(owner.bundle);
		const proof = await signProof(
			challenge,
			owner.privateKey,
			owner.fingerprint,
		);
		routeState.sessionId = "session-b";

		const response = await submitImport(owner.bundle, proof);
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({
			error: expect.stringContaining("another session"),
		});
	});

	it("rejects replay after successful import even if the profile is removed", async () => {
		const owner = await makeBundle();
		const { challenge } = await issueChallenge(owner.bundle);
		const proof = await signProof(
			challenge,
			owner.privateKey,
			owner.fingerprint,
		);
		const first = await submitImport(owner.bundle, proof);
		expect(first.status).toBe(201);

		adapter.sqlite.exec(
			"delete from sigchain_link; delete from crypto_profile;",
		);
		const replay = await submitImport(owner.bundle, proof);
		expect(replay.status).toBe(409);
		expect(await replay.json()).toMatchObject({
			error: expect.stringContaining("missing"),
		});
	});

	it("returns one success and one conflict for concurrent identical imports", async () => {
		const owner = await makeBundle();
		const { challenge } = await issueChallenge(owner.bundle);
		const proof = await signProof(
			challenge,
			owner.privateKey,
			owner.fingerprint,
		);
		adapter.synchronizeNextTwoVerificationReads();

		const responses = await Promise.all([
			submitImport(owner.bundle, proof),
			submitImport(owner.bundle, proof),
		]);
		expect(responses.map((response) => response.status).sort()).toEqual([
			201, 409,
		]);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from crypto_profile")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from verification")
				.get(),
		).toEqual({ count: 0 });
	});

	it("allows one concurrent different import for the same user across sessions", async () => {
		const first = await makeBundle();
		const second = await makeBundle();
		const firstIdentity = { userId: "user-a", sessionId: "session-a" };
		const secondIdentity = { userId: "user-a", sessionId: "session-b" };
		const firstChallenge = await issueChallenge(first.bundle, firstIdentity);
		const firstProof = await signProof(
			firstChallenge.challenge,
			first.privateKey,
			first.fingerprint,
		);
		const secondChallenge = await issueChallenge(second.bundle, secondIdentity);
		const secondProof = await signProof(
			secondChallenge.challenge,
			second.privateKey,
			second.fingerprint,
		);

		const responses = await Promise.all([
			submitImport(first.bundle, firstProof, firstIdentity),
			submitImport(second.bundle, secondProof, secondIdentity),
		]);
		expect(responses.map((response) => response.status).sort()).toEqual([
			201, 409,
		]);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from crypto_profile")
				.get(),
		).toEqual({ count: 1 });
	});

	it("allows one concurrent profile for the same identity across users", async () => {
		const { first, second } = await makeSharedIdentityBundles();
		const firstIdentity = { userId: "user-a", sessionId: "session-a" };
		const secondIdentity = { userId: "user-b", sessionId: "session-b" };
		const firstChallenge = await issueChallenge(first.bundle, firstIdentity);
		const secondChallenge = await issueChallenge(second.bundle, secondIdentity);
		const firstProof = await signProof(
			firstChallenge.challenge,
			first.privateKey,
			first.fingerprint,
		);
		const secondProof = await signProof(
			secondChallenge.challenge,
			second.privateKey,
			second.fingerprint,
		);
		adapter.synchronizeNextTwoVerificationReads();

		const responses = await Promise.all([
			submitImport(first.bundle, firstProof, firstIdentity),
			submitImport(second.bundle, secondProof, secondIdentity),
		]);
		expect(responses.map((response) => response.status).sort()).toEqual([
			201, 409,
		]);
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from crypto_profile")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare(
					"select count(distinct identity_id) as count from sigchain_link",
				)
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: 2 });
	});
});
