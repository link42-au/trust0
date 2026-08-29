import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import {
	computeFingerprint,
	computeIdentityId,
	computeLinkHash,
	createChainLink,
	createProfile,
	createRequest,
	generateIdentityKey,
} from "@trust0/identity";
import { drizzle } from "drizzle-orm/d1";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../db/schema";
import type { Env } from "../types";

type MockContext = {
	set: (key: string, value: unknown) => void;
	get: (key: string) => unknown;
	json: (body: unknown, status?: number) => Response;
};

type BoundStatement = {
	query: string;
	params: SQLInputValue[];
};

const routeState = vi.hoisted(() => ({
	db: null as unknown,
}));

vi.mock("../middleware/session", () => ({
	sessionMiddleware: async (
		context: MockContext,
		next: () => Promise<void>,
	) => {
		context.set("user", { id: "user-a" });
		context.set("session", { id: "session-a" });
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

import { aspeRoutes } from "../aspe";

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
	private readonly profileReadBarriers: Array<{
		fingerprints: Set<string>;
		promise: Promise<void>;
		release: () => void;
		firstRead: Promise<void>;
		notifyFirstRead: () => void;
		reads: number;
	}> = [];
	private batchQueue = Promise.resolve();

	constructor() {
		this.sqlite.exec(`
			pragma foreign_keys = on;
			create table crypto_profile (
				fingerprint text primary key,
				profile_jws text not null,
				user_id text not null,
				identity_id text,
				created_at integer not null,
				updated_at integer not null
			);
			create table username (
				username text primary key,
				fingerprint text not null references crypto_profile(fingerprint),
				claimed_at integer not null
			);
			create table attestation (
				id text primary key,
				fingerprint text not null references crypto_profile(fingerprint),
				type text not null,
				platform text,
				platform_user_id text,
				platform_username text,
				value text not null,
				attested_by text not null,
				attested_at integer not null,
				expires_at integer
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
		`);
	}

	synchronizeNextTwoProfileReads(...fingerprints: string[]) {
		let release = () => {};
		let notifyFirstRead = () => {};
		const promise = new Promise<void>((resolve) => {
			release = resolve;
		});
		const firstRead = new Promise<void>((resolve) => {
			notifyFirstRead = resolve;
		});
		this.profileReadBarriers.push({
			fingerprints: new Set(fingerprints),
			promise,
			release,
			firstRead,
			notifyFirstRead,
			reads: 0,
		});
	}

	async waitForProfileRead(fingerprint: string) {
		const barrier = this.profileReadBarriers.find((candidate) =>
			candidate.fingerprints.has(fingerprint),
		);
		if (!barrier) throw new Error(`No read barrier for ${fingerprint}`);
		await barrier.firstRead;
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

		if (statement.query.includes('from "crypto_profile"')) {
			for (const barrier of this.profileReadBarriers) {
				if (
					!statement.params.some(
						(param) =>
							typeof param === "string" && barrier.fingerprints.has(param),
					)
				) {
					continue;
				}
				barrier.reads += 1;
				barrier.notifyFirstRead();
				if (barrier.reads === 2) barrier.release();
				await barrier.promise;
				break;
			}
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

type TestIdentity = Awaited<ReturnType<typeof generateIdentityKey>> & {
	fingerprint: string;
};

let adapter: SqliteD1Adapter;

beforeEach(() => {
	adapter = new SqliteD1Adapter();
	routeState.db = drizzle(adapter as unknown as D1Database, { schema });
});

afterEach(() => {
	adapter.close();
});

async function makeIdentity(): Promise<TestIdentity> {
	const key = await generateIdentityKey();
	return {
		...key,
		fingerprint: await computeFingerprint(key.publicJWK),
	};
}

async function rotationRequest(oldFingerprint: string, identity: TestIdentity) {
	const profileJws = await createProfile({
		name: "Rotated identity",
		claims: [],
		key: identity.privateKey,
		publicJWK: identity.publicJWK,
		fingerprint: identity.fingerprint,
	});
	const requestJws = await createRequest({
		action: "update",
		profileJws,
		aspeUri: `aspe:trust0.example:${oldFingerprint}`,
		key: identity.privateKey,
		publicJWK: identity.publicJWK,
		fingerprint: identity.fingerprint,
	});

	return await aspeRoutes.request(
		"/.well-known/aspe/post/",
		{
			method: "POST",
			headers: { "content-type": "text/plain" },
			body: requestJws,
		},
		TEST_BINDINGS,
	);
}

describe("concurrent profile key rotation", () => {
	it("commits one rotation and rejects the stale serialized batch without partial rows", async () => {
		const oldIdentity = await makeIdentity();
		const firstRotation = await makeIdentity();
		const secondRotation = await makeIdentity();
		const genesis = await createChainLink({
			seqno: 0,
			prev: null,
			type: "key_init",
			body: { fingerprint: oldIdentity.fingerprint },
			key: oldIdentity.privateKey,
			publicJWK: oldIdentity.publicJWK,
			fingerprint: oldIdentity.fingerprint,
		});
		const rotateFirst = await createChainLink({
			seqno: 1,
			prev: await computeLinkHash(genesis),
			type: "key_rotate",
			body: { new_fingerprint: firstRotation.fingerprint },
			key: oldIdentity.privateKey,
			publicJWK: oldIdentity.publicJWK,
			fingerprint: oldIdentity.fingerprint,
		});
		const updateFirst = await createChainLink({
			seqno: 2,
			prev: await computeLinkHash(rotateFirst),
			type: "profile_update",
			body: { profile_fingerprint: firstRotation.fingerprint },
			key: firstRotation.privateKey,
			publicJWK: firstRotation.publicJWK,
			fingerprint: firstRotation.fingerprint,
		});
		const rotateSecond = await createChainLink({
			seqno: 3,
			prev: await computeLinkHash(updateFirst),
			type: "key_rotate",
			body: { new_fingerprint: secondRotation.fingerprint },
			key: firstRotation.privateKey,
			publicJWK: firstRotation.publicJWK,
			fingerprint: firstRotation.fingerprint,
		});
		const updateSecond = await createChainLink({
			seqno: 4,
			prev: await computeLinkHash(rotateSecond),
			type: "profile_update",
			body: { profile_fingerprint: secondRotation.fingerprint },
			key: secondRotation.privateKey,
			publicJWK: secondRotation.publicJWK,
			fingerprint: secondRotation.fingerprint,
		});
		const identityId = await computeIdentityId(genesis);
		const now = Math.floor(Date.now() / 1000);

		adapter.sqlite
			.prepare("insert into crypto_profile values (?, ?, ?, ?, ?, ?)")
			.run(
				oldIdentity.fingerprint,
				"old-profile-jws",
				"user-a",
				identityId,
				now,
				now,
			);
		adapter.sqlite
			.prepare("insert into username values (?, ?, ?)")
			.run("alice", oldIdentity.fingerprint, now);
		adapter.sqlite
			.prepare(
				"insert into attestation values (?, ?, ?, null, null, null, ?, ?, ?, null)",
			)
			.run(
				"proof-a",
				oldIdentity.fingerprint,
				"website",
				"https://example.com/alice",
				"trust0.example",
				now,
			);
		const seedChainLink = async (
			seqno: number,
			fingerprint: string,
			type: string,
			linkJws: string,
			prevHash: string | null,
		) => {
			adapter.sqlite
				.prepare("insert into sigchain_link values (?, ?, ?, ?, ?, ?, ?, ?)")
				.run(
					await computeLinkHash(linkJws),
					identityId,
					fingerprint,
					seqno,
					type,
					linkJws,
					prevHash,
					now,
				);
		};
		await seedChainLink(0, oldIdentity.fingerprint, "key_init", genesis, null);
		await seedChainLink(
			1,
			oldIdentity.fingerprint,
			"key_rotate",
			rotateFirst,
			await computeLinkHash(genesis),
		);
		await seedChainLink(
			2,
			firstRotation.fingerprint,
			"profile_update",
			updateFirst,
			await computeLinkHash(rotateFirst),
		);

		adapter.synchronizeNextTwoProfileReads(
			firstRotation.fingerprint,
			secondRotation.fingerprint,
		);

		const firstResponse = rotationRequest(
			oldIdentity.fingerprint,
			firstRotation,
		);
		await adapter.waitForProfileRead(firstRotation.fingerprint);
		await seedChainLink(
			3,
			firstRotation.fingerprint,
			"key_rotate",
			rotateSecond,
			await computeLinkHash(updateFirst),
		);
		await seedChainLink(
			4,
			secondRotation.fingerprint,
			"profile_update",
			updateSecond,
			await computeLinkHash(rotateSecond),
		);
		const responses = await Promise.all([
			firstResponse,
			rotationRequest(oldIdentity.fingerprint, secondRotation),
		]);
		expect(responses[0].status).toBe(409);
		expect(responses[1].status).toBe(200);
		expect(await responses[0].json()).toEqual({
			error: "Profile changed concurrently. Refetch it and retry.",
		});
		expect(await responses[1].json()).toMatchObject({
			fingerprint: secondRotation.fingerprint,
		});
		expect(
			adapter.sqlite
				.prepare("select fingerprint, user_id, identity_id from crypto_profile")
				.all(),
		).toEqual([
			{
				fingerprint: secondRotation.fingerprint,
				user_id: "user-a",
				identity_id: identityId,
			},
		]);
		expect(
			adapter.sqlite.prepare("select fingerprint from username").get(),
		).toEqual({ fingerprint: secondRotation.fingerprint });
		expect(
			adapter.sqlite.prepare("select fingerprint from attestation").get(),
		).toEqual({ fingerprint: secondRotation.fingerprint });
	});
});
