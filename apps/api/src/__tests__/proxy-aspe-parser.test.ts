import {
	computeFingerprint,
	createProfile,
	createRequest,
	generateIdentityKey,
} from "@trust0/identity";
import { describe, expect, it, vi } from "vitest";
import { aspeUriToProfileUrl } from "../../../proxy/src/index";
import type { Env } from "../types";

type MockContext = {
	set: (key: string, value: unknown) => void;
	get: (key: string) => unknown;
	json: (body: unknown, status?: number) => Response;
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

const FINGERPRINT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

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

describe("proxy ASPE URI parsing", () => {
	it("maps a canonical public authority and normalizes the fingerprint", () => {
		expect(
			aspeUriToProfileUrl(`aspe:trust0.example:${FINGERPRINT.toLowerCase()}`),
		).toBe(`https://trust0.example/.well-known/aspe/id/${FINGERPRINT}`);
	});

	it("preserves a localhost development authority with a port", () => {
		expect(aspeUriToProfileUrl(`aspe:localhost:8788:${FINGERPRINT}`)).toBe(
			`https://localhost:8788/.well-known/aspe/id/${FINGERPRINT}`,
		);
	});

	it.each([
		["missing authority", `aspe::${FINGERPRINT}`],
		["wrong fingerprint length", `aspe:trust0.example:${FINGERPRINT.slice(1)}`],
		["wrong fingerprint alphabet", `aspe:trust0.example:${"A".repeat(25)}0`],
		["uppercase scheme", `ASPE:trust0.example:${FINGERPRINT}`],
		["suffix path", `aspe:trust0.example:${FINGERPRINT}/profile`],
	])("rejects %s", (_case, uri) => {
		expect(aspeUriToProfileUrl(uri)).toBeNull();
	});

	it("accepts the URI returned by the API create route", async () => {
		const key = await generateIdentityKey();
		const fingerprint = await computeFingerprint(key.publicJWK);
		const profileJws = await createProfile({
			name: "Proxy contract test",
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

		const limit = vi.fn().mockResolvedValue([]);
		const insertSelect = vi.fn().mockResolvedValue({ meta: { changes: 1 } });
		routeState.db = {
			select: vi.fn(() => ({
				from: vi.fn(() => ({
					where: vi.fn(() => ({ limit })),
				})),
			})),
			insert: vi.fn(() => ({ select: insertSelect })),
		};

		const response = await aspeRoutes.request(
			"/.well-known/aspe/post/",
			{
				method: "POST",
				headers: { "content-type": "text/plain" },
				body: requestJws,
			},
			TEST_BINDINGS,
		);
		const payload = (await response.json()) as {
			fingerprint: string;
			uri: string;
		};

		expect(response.status).toBe(201);
		expect(payload).toEqual({
			fingerprint,
			uri: `aspe:trust0.example:${fingerprint}`,
		});
		expect(aspeUriToProfileUrl(payload.uri)).toBe(
			`https://trust0.example/.well-known/aspe/id/${fingerprint}`,
		);
		expect(limit).toHaveBeenCalledTimes(2);
		expect(insertSelect).toHaveBeenCalledTimes(1);
	});
});
