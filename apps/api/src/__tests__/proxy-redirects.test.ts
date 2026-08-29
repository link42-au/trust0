import { afterEach, describe, expect, it, vi } from "vitest";
import proxyApp, { fetchWithTimeout } from "../../../proxy/src/index";

const FINGERPRINT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PROFILE_PATH = `/.well-known/aspe/id/${FINGERPRINT}`;
const ASPE_PATH = `/api/3/get/aspe?aspeUri=${encodeURIComponent(
	`aspe:public.example:${FINGERPRINT}`,
)}`;
const TEST_BINDINGS = { ALLOWED_ORIGINS: "https://trust0.example" };
const originalFetch = globalThis.fetch;

const requestAspe = async (): Promise<Response> =>
	await proxyApp.request(ASPE_PATH, undefined, TEST_BINDINGS);

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	globalThis.fetch = originalFetch;
});

describe("proxy redirect handling", () => {
	it("rejects a public-host redirect to loopback before a second fetch", async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(null, {
				status: 302,
				headers: { Location: "https://127.0.0.1/private" },
			}),
		);
		vi.stubGlobal("fetch", fetchMock);

		const response = await requestAspe();

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toEqual({
			error:
				"Unsafe redirect: Requests to private/internal hosts are not allowed",
		});
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(fetchMock).toHaveBeenCalledWith(
			`https://public.example${PROFILE_PATH}`,
			expect.objectContaining({ redirect: "manual" }),
		);
	});

	it("follows a safe relative redirect with manual redirect mode", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(null, {
					status: 302,
					headers: { Location: "/profiles/current" },
				}),
			)
			.mockResolvedValueOnce(
				new Response("signed-profile", {
					status: 200,
					headers: { "Content-Type": "application/asp+jwt" },
				}),
			);
		vi.stubGlobal("fetch", fetchMock);

		const response = await requestAspe();

		expect(response.status).toBe(200);
		await expect(response.text()).resolves.toBe("signed-profile");
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(fetchMock.mock.calls[0]?.[0]).toBe(
			`https://public.example${PROFILE_PATH}`,
		);
		expect(fetchMock.mock.calls[1]?.[0]).toBe(
			"https://public.example/profiles/current",
		);
		for (const [, init] of fetchMock.mock.calls) {
			expect(init).toEqual(expect.objectContaining({ redirect: "manual" }));
		}
	});

	it("rejects a redirect loop before repeating a fetch", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(null, {
					status: 302,
					headers: { Location: "/hop" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(null, {
					status: 302,
					headers: { Location: PROFILE_PATH },
				}),
			);
		vi.stubGlobal("fetch", fetchMock);

		const response = await requestAspe();

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toEqual({
			error: "Redirect loop detected",
		});
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it("rejects a redirect chain that exceeds the hop limit", async () => {
		const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => {
			const hop = fetchMock.mock.calls.length;
			return new Response(null, {
				status: 302,
				headers: { Location: `/hop-${hop}` },
			});
		});
		vi.stubGlobal("fetch", fetchMock);

		const response = await requestAspe();

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toEqual({
			error: "Too many redirects",
		});
		expect(fetchMock).toHaveBeenCalledTimes(6);
		for (const [, init] of fetchMock.mock.calls) {
			expect(init).toEqual(expect.objectContaining({ redirect: "manual" }));
		}
	});

	it("strips credentials on cross-origin redirects", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(null, {
					status: 302,
					headers: { Location: "https://redirect.example/final" },
				}),
			)
			.mockResolvedValueOnce(new Response("ok", { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		const response = await fetchWithTimeout("https://public.example/resource", {
			headers: {
				Authorization: "Bearer secret",
				Cookie: "session=secret",
				"X-Test": "preserved",
			},
		});

		expect(await response.text()).toBe("ok");
		expect(fetchMock).toHaveBeenCalledTimes(2);
		const redirectedInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
		const redirectedHeaders = new Headers(redirectedInit.headers);
		expect(redirectedHeaders.get("authorization")).toBeNull();
		expect(redirectedHeaders.get("cookie")).toBeNull();
		expect(redirectedHeaders.get("x-test")).toBe("preserved");
		expect(redirectedInit.redirect).toBe("manual");
	});
});
