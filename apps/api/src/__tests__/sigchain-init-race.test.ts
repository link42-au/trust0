import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import {
	computeFingerprint,
	createChainLink,
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
}));

import { sigchainRoutes } from "../sigchain";

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
	private profileReads = 0;
	private releaseProfileReads = () => {};
	private readonly profileReadsSynchronized = new Promise<void>((resolve) => {
		this.releaseProfileReads = resolve;
	});
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
		`);
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
			this.profileReads += 1;
			if (this.profileReads === 2) this.releaseProfileReads();
			await this.profileReadsSynchronized;
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

describe("concurrent sigchain initialization", () => {
	it("creates only the winning genesis and returns a conflict for the loser", async () => {
		const key = await generateIdentityKey();
		const fingerprint = await computeFingerprint(key.publicJWK);
		const genesisLinks = await Promise.all(
			["first", "second"].map(
				async (nonce) =>
					await createChainLink({
						seqno: 0,
						prev: null,
						type: "key_init",
						body: { fingerprint, nonce },
						key: key.privateKey,
						publicJWK: key.publicJWK,
						fingerprint,
					}),
			),
		);
		const now = Math.floor(Date.now() / 1000);
		adapter.sqlite
			.prepare("insert into crypto_profile values (?, ?, ?, null, ?, ?)")
			.run(fingerprint, "profile-jws", "user-a", now, now);

		const responses = await Promise.all(
			genesisLinks.map(
				async (genesisLinkJws) =>
					await sigchainRoutes.request(
						"/api/identity/chain/init",
						{
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({ genesisLinkJws }),
						},
						TEST_BINDINGS,
					),
			),
		);
		const statuses = responses.map((response) => response.status).sort();
		const winnerIndex = responses.findIndex(
			(response) => response.status === 201,
		);
		const winner = responses[winnerIndex];
		const conflict = responses.find((response) => response.status === 409);
		const winnerBody = (await winner?.json()) as { identityId: string };

		expect(statuses).toEqual([201, 409]);
		expect(await conflict?.json()).toEqual({
			error: "Chain already initialized for this profile",
		});
		expect(
			adapter.sqlite
				.prepare(
					"select identity_id, link_jws from sigchain_link order by identity_id",
				)
				.all(),
		).toEqual([
			{
				identity_id: winnerBody.identityId,
				link_jws: genesisLinks[winnerIndex],
			},
		]);
		expect(
			adapter.sqlite
				.prepare("select identity_id from crypto_profile where fingerprint = ?")
				.get(fingerprint),
		).toEqual({ identity_id: winnerBody.identityId });
		expect(
			adapter.sqlite
				.prepare("select count(*) as count from sigchain_link")
				.get(),
		).toEqual({ count: 1 });
		expect(
			adapter.sqlite
				.prepare(`
					select count(*) as count
					from sigchain_link as link
					left join crypto_profile as profile
						on profile.identity_id = link.identity_id
					where profile.fingerprint is null
				`)
				.get(),
		).toEqual({ count: 0 });
	});
});
