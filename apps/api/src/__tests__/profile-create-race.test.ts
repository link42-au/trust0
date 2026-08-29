import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import {
	computeFingerprint,
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
	readonly writes: string[] = [];
	private userReadCount = 0;
	private releaseUserReads = () => {};
	private readonly userReadsReady = new Promise<void>((resolve) => {
		this.releaseUserReads = resolve;
	});

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

	close() {
		this.sqlite.close();
	}

	private async all(statement: BoundStatement) {
		const results = this.sqlite
			.prepare(statement.query)
			.all(...statement.params) as Record<string, unknown>[];

		if (
			statement.query.startsWith("select") &&
			statement.query.includes('from "crypto_profile"') &&
			statement.query.includes('"user_id" = ?') &&
			statement.params.includes("user-a")
		) {
			this.userReadCount += 1;
			if (this.userReadCount === 2) this.releaseUserReads();
			await this.userReadsReady;
		}

		return { success: true, results, meta: successResult(0).meta };
	}

	private run(statement: BoundStatement) {
		if (statement.query.startsWith("insert")) {
			this.writes.push(statement.query);
		}
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

async function createSignedProfileRequest(name: string): Promise<{
	fingerprint: string;
	requestJws: string;
}> {
	const key = await generateIdentityKey();
	const fingerprint = await computeFingerprint(key.publicJWK);
	const profileJws = await createProfile({
		name,
		claims: [],
		key: key.privateKey,
		publicJWK: key.publicJWK,
		fingerprint,
	});
	const requestJws = await createRequest({
		action: "create",
		profileJws,
		key: key.privateKey,
		publicJWK: key.publicJWK,
		fingerprint,
	});

	return { fingerprint, requestJws };
}

async function postCreate(requestJws: string): Promise<Response> {
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

describe("concurrent profile creation", () => {
	it("atomically allows only one profile for an authenticated user", async () => {
		const first = await createSignedProfileRequest("First identity");
		const second = await createSignedProfileRequest("Second identity");

		const responses = await Promise.all([
			postCreate(first.requestJws),
			postCreate(second.requestJws),
		]);
		const statuses = responses.map((response) => response.status).sort();

		expect(statuses).toEqual([201, 409]);
		await expect(
			responses.find((response) => response.status === 409)?.json(),
		).resolves.toEqual({ error: "User or fingerprint already has a profile." });
		expect(
			adapter.sqlite
				.prepare("select fingerprint, user_id from crypto_profile")
				.all(),
		).toEqual([
			{
				fingerprint: expect.stringMatching(
					new RegExp(`^(${first.fingerprint}|${second.fingerprint})$`),
				),
				user_id: "user-a",
			},
		]);
		expect(adapter.writes).toHaveLength(2);
		for (const write of adapter.writes) {
			expect(write).toContain('insert into "crypto_profile"');
			expect(write.match(/not exists/g)).toHaveLength(2);
			expect(write).toContain('"user_id" = ?');
			expect(write).toContain('"fingerprint" = ?');
		}
	});
});
