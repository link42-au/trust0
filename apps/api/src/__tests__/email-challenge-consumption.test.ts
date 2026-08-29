import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { computeFingerprint, generateIdentityKey } from "@trust0/identity";
import { drizzle } from "drizzle-orm/d1";
import { CompactSign } from "jose";
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
		context.set("user", {
			id: "user-a",
			email: "person@example.com",
			emailVerified: true,
		});
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
			create table verification (
				id text primary key,
				identifier text not null,
				value text not null,
				expires_at integer not null,
				created_at integer,
				updated_at integer
			);
			create table attestation (
				id text primary key,
				fingerprint text not null,
				type text not null,
				platform text,
				platform_user_id text,
				platform_username text,
				value text not null,
				attested_by text not null,
				attested_at integer not null,
				expires_at integer
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
	adapter = new SqliteD1Adapter();
	routeState.db = drizzle(adapter as unknown as D1Database, { schema });
});

afterEach(() => {
	adapter.close();
});

async function seedSignedChallenge(challenge: string) {
	const identity = await generateIdentityKey();
	const fingerprint = await computeFingerprint(identity.publicJWK);
	const now = Math.floor(Date.now() / 1000);
	adapter.sqlite
		.prepare("insert into crypto_profile values (?, ?, ?, null, ?, ?)")
		.run(fingerprint, "profile-jws", "user-a", now, now);
	adapter.sqlite
		.prepare("insert into verification values (?, ?, ?, ?, ?, ?)")
		.run(
			`identity-email:${fingerprint}`,
			`identity-email:${fingerprint}`,
			challenge,
			now + 900,
			now,
			now,
		);

	const signedChallenge = await new CompactSign(
		new TextEncoder().encode(challenge),
	)
		.setProtectedHeader({
			alg: "EdDSA",
			kid: fingerprint,
			jwk: identity.publicJWK,
		})
		.sign(identity.privateKey);

	return { fingerprint, signedChallenge };
}

const verify = async (signedChallenge: string) =>
	await aspeRoutes.request(
		"/api/identity/email/verify",
		{
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ signedChallenge }),
		},
		TEST_BINDINGS,
	);

describe("one-time email challenge consumption", () => {
	it("allows only one of two verifiers that read the same challenge to attest", async () => {
		const { fingerprint, signedChallenge } = await seedSignedChallenge(
			"concurrent-challenge",
		);
		adapter.synchronizeNextTwoVerificationReads();

		const responses = await Promise.all([
			verify(signedChallenge),
			verify(signedChallenge),
		]);
		const statuses = responses.map((response) => response.status).sort();
		const conflict = responses.find((response) => response.status === 409);

		expect(statuses).toEqual([200, 409]);
		expect(await conflict?.json()).toEqual({
			error:
				"Challenge already consumed or no longer valid. Request a new one.",
		});
		expect(
			adapter.sqlite
				.prepare(
					"select count(*) as count from attestation where fingerprint = ?",
				)
				.get(fingerprint),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from verification")
				.get(),
		).toEqual({ count: 0 });
	});
});
