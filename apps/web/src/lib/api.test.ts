import { afterEach, describe, expect, it, vi } from "vitest";
import { signedInMe } from "../../tests/fixtures/auth";
import { getMe } from "./api";

describe("getMe", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("returns the deterministic signed-in user", async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(JSON.stringify(signedInMe), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(getMe()).resolves.toEqual(signedInMe);
		expect(fetchMock).toHaveBeenCalledWith("http://localhost:8788/api/me", {
			credentials: "include",
		});
	});

	it("returns signed-out state for an unauthorized response", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				new Response(JSON.stringify({ error: "Unauthorized" }), {
					status: 401,
					headers: { "Content-Type": "application/json" },
				}),
			),
		);

		await expect(getMe()).resolves.toBeNull();
	});

	it("fails closed to signed-out state when the API is unreachable", async () => {
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

		await expect(getMe()).resolves.toBeNull();
	});
});
