import { Hono } from "hono";
import { cors } from "hono/cors";

// ── Types ────────────────────────────────────────────────────────────────────

type Env = {
	Bindings: {
		ALLOWED_ORIGINS: string;
	};
};

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_RESPONSE_SIZE = 1_048_576; // 1 MB
const FETCH_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;

/** RFC 1918 / loopback / link-local prefixes that must never be proxied to. */
const PRIVATE_HOST_PATTERNS = [
	/^localhost$/i,
	/^127\./,
	/^10\./,
	/^172\.(1[6-9]|2\d|3[01])\./,
	/^192\.168\./,
	/^0\./,
	/^\[::1\]/,
	/^\[fc/i,
	/^\[fd/i,
	/^\[fe80:/i,
];

// ── Helpers ──────────────────────────────────────────────────────────────────

const isPrivateHost = (hostname: string): boolean =>
	PRIVATE_HOST_PATTERNS.some((re) => re.test(hostname));

const requireHttps = (url: string): URL => {
	const parsed = new URL(url);
	if (parsed.protocol !== "https:") {
		throw new Error("Only HTTPS URLs are allowed");
	}
	if (isPrivateHost(parsed.hostname)) {
		throw new Error("Requests to private/internal hosts are not allowed");
	}
	return parsed;
};

export const aspeUriToProfileUrl = (aspeUri: string): string | null => {
	if (!aspeUri.startsWith("aspe:")) return null;

	const fingerprintSeparator = aspeUri.lastIndexOf(":");
	if (fingerprintSeparator <= "aspe:".length) return null;

	const authority = aspeUri.slice("aspe:".length, fingerprintSeparator);
	const fingerprint = aspeUri.slice(fingerprintSeparator + 1);
	if (!/^[a-zA-Z2-7]{26}$/.test(fingerprint)) return null;

	const authorityMatch = authority.match(
		/^([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)(?::(\d{1,5}))?$/,
	);
	if (!authorityMatch) return null;

	const hostname = authorityMatch[1];
	const labels = hostname.split(".");
	if (
		hostname.length > 253 ||
		labels.some(
			(label) =>
				label.length > 63 ||
				!/^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$/.test(label),
		)
	) {
		return null;
	}

	const port = authorityMatch[2];
	if (port && Number.parseInt(port, 10) > 65_535) return null;

	return `https://${authority}/.well-known/aspe/id/${fingerprint.toUpperCase()}`;
};

export const fetchWithTimeout = async (
	input: RequestInfo,
	init?: RequestInit,
): Promise<Response> => {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

	try {
		let requestUrl = requireHttps(
			typeof input === "string" ? input : input.url,
		);
		requestUrl.hash = "";
		let requestInit: RequestInit = { ...init };
		const visited = new Set<string>([requestUrl.toString()]);

		for (let redirectCount = 0; ; redirectCount += 1) {
			const res = await fetch(requestUrl.toString(), {
				...requestInit,
				redirect: "manual",
				signal: controller.signal,
			});

			if (![301, 302, 303, 307, 308].includes(res.status)) {
				return res;
			}
			if (redirectCount >= MAX_REDIRECTS) {
				throw new Error("Too many redirects");
			}

			const location = res.headers.get("location");
			if (!location) {
				throw new Error("Redirect response is missing a Location header");
			}

			let redirectUrl: URL;
			try {
				redirectUrl = requireHttps(new URL(location, requestUrl).toString());
			} catch (err) {
				const message =
					err instanceof Error ? err.message : "Invalid redirect URL";
				throw new Error(`Unsafe redirect: ${message}`);
			}
			redirectUrl.hash = "";

			const normalizedRedirectUrl = redirectUrl.toString();
			if (visited.has(normalizedRedirectUrl)) {
				throw new Error("Redirect loop detected");
			}
			visited.add(normalizedRedirectUrl);

			const method = (requestInit.method || "GET").toUpperCase();
			const headers = new Headers(requestInit.headers);
			const switchToGet =
				(res.status === 303 && method !== "GET" && method !== "HEAD") ||
				((res.status === 301 || res.status === 302) && method === "POST");
			if (switchToGet) {
				for (const header of [
					"content-encoding",
					"content-language",
					"content-length",
					"content-location",
					"content-type",
				]) {
					headers.delete(header);
				}
				requestInit = {
					...requestInit,
					method: "GET",
					body: undefined,
					headers,
				};
			}
			if (requestUrl.origin !== redirectUrl.origin) {
				headers.delete("authorization");
				headers.delete("cookie");
				headers.delete("proxy-authorization");
				requestInit = { ...requestInit, headers };
			}

			await res.body?.cancel();
			requestUrl = redirectUrl;
		}
	} finally {
		clearTimeout(timer);
	}
};

const enforceSize = async (res: Response): Promise<string> => {
	const contentLength = res.headers.get("content-length");
	if (contentLength && Number.parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
		throw new Error("Response too large");
	}

	const body = await res.text();
	if (body.length > MAX_RESPONSE_SIZE) {
		throw new Error("Response too large");
	}
	return body;
};

// ── App ──────────────────────────────────────────────────────────────────────

const app = new Hono<Env>();

// ── CORS middleware ──────────────────────────────────────────────────────────

app.use("*", async (c, next) => {
	const origins = c.env.ALLOWED_ORIGINS
		? c.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
		: [];

	const corsMiddleware = cors({
		origin: origins,
		allowMethods: ["GET", "OPTIONS"],
		allowHeaders: ["Content-Type"],
	});

	return corsMiddleware(c, next);
});

// Note: Real rate limiting should be configured at the Cloudflare level
// (Rate Limiting Rules or Workers Rate Limiting API). No fake headers.

// ── GET /api/3/get/http ──────────────────────────────────────────────────────

app.get("/api/3/get/http", async (c) => {
	const url = c.req.query("url");
	if (!url) {
		return c.json({ error: "Missing 'url' parameter" }, 400);
	}

	try {
		const parsed = requireHttps(url);

		const res = await fetchWithTimeout(parsed.toString(), {
			headers: {
				"User-Agent": "identity-proxy/0.1",
			},
		});

		if (!res.ok) {
			return c.json(
				{ error: `Upstream returned ${res.status}` },
				res.status as any,
			);
		}

		const body = await enforceSize(res);
		const contentType = res.headers.get("content-type") || "text/plain";

		// doipjs consumes the proxy response via fetcher.http which expects
		// either parsed JSON or raw text depending on the proof format.
		// Return the body as-is with the original content-type so axios
		// in doipjs can parse it correctly.
		return new Response(body, {
			headers: {
				"Content-Type": contentType,
			},
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		return c.json({ error: message }, 400);
	}
});

// ── GET /api/3/get/dns ───────────────────────────────────────────────────────

app.get("/api/3/get/dns", async (c) => {
	const domain = c.req.query("domain");
	if (!domain) {
		return c.json({ error: "Missing 'domain' parameter" }, 400);
	}

	// Domain validation — alphanumeric, hyphens, dots, max 253 chars (RFC 1035)
	if (domain.length > 253 || !/^[a-zA-Z0-9.-]+$/.test(domain)) {
		return c.json({ error: "Invalid domain" }, 400);
	}

	try {
		const res = await fetchWithTimeout(
			`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`,
			{
				headers: {
					Accept: "application/dns-json",
				},
			},
		);

		if (!res.ok) {
			return c.json({ error: `DNS query failed: ${res.status}` }, 502);
		}

		const dnsData = (await res.json()) as {
			Answer?: Array<{ data: string }>;
		};

		// Transform to the format doipjs dns fetcher returns:
		// { domain, records: { txt: [["record1"], ["record2"]] } }
		// dns.resolveTxt returns an array of arrays (each TXT record can have
		// multiple strings that get concatenated).
		const txtRecords: string[][] = (dnsData.Answer || [])
			.filter((a: any) => a.type === 16) // TXT record type
			.map((a: any) => {
				// DNS-over-HTTPS returns TXT data with quotes — strip them
				const cleaned = (a.data as string).replace(/^"|"$/g, "");
				return [cleaned];
			});

		return c.json({
			domain,
			records: {
				txt: txtRecords,
			},
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		return c.json({ error: message }, 400);
	}
});

// ── GET /api/3/get/activitypub ───────────────────────────────────────────────

app.get("/api/3/get/activitypub", async (c) => {
	const url = c.req.query("url");
	if (!url) {
		return c.json({ error: "Missing 'url' parameter" }, 400);
	}

	try {
		const parsed = requireHttps(url);

		const res = await fetchWithTimeout(parsed.toString(), {
			headers: {
				Accept: "application/activity+json",
				"User-Agent": "identity-proxy/0.1",
			},
		});

		if (!res.ok) {
			return c.json(
				{ error: `Upstream returned ${res.status}` },
				res.status as any,
			);
		}

		const body = await enforceSize(res);

		return new Response(body, {
			headers: {
				"Content-Type": "application/activity+json",
			},
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		return c.json({ error: message }, 400);
	}
});

// ── GET /api/3/get/graphql ───────────────────────────────────────────────────

app.get("/api/3/get/graphql", async (c) => {
	const url = c.req.query("url");
	const query = c.req.query("query");

	if (!url) {
		return c.json({ error: "Missing 'url' parameter" }, 400);
	}
	if (!query) {
		return c.json({ error: "Missing 'query' parameter" }, 400);
	}

	try {
		const parsed = requireHttps(url);

		let jsonData: unknown;
		try {
			jsonData = JSON.parse(decodeURIComponent(query));
		} catch {
			return c.json({ error: "Invalid GraphQL query object" }, 400);
		}

		const res = await fetchWithTimeout(parsed.toString(), {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"User-Agent": "identity-proxy/0.1",
			},
			body: JSON.stringify(jsonData),
		});

		if (!res.ok) {
			return c.json(
				{ error: `Upstream returned ${res.status}` },
				res.status as any,
			);
		}

		const body = await enforceSize(res);

		return new Response(body, {
			headers: {
				"Content-Type": "application/json",
			},
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		return c.json({ error: message }, 400);
	}
});

// ── GET /api/3/get/aspe ──────────────────────────────────────────────────────

app.get("/api/3/get/aspe", async (c) => {
	const aspeUri = c.req.query("aspeUri");
	if (!aspeUri) {
		return c.json({ error: "Missing 'aspeUri' parameter" }, 400);
	}

	const profileUrl = aspeUriToProfileUrl(aspeUri);
	if (!profileUrl) {
		return c.json({ error: "Invalid ASPE URI" }, 400);
	}

	try {
		const url = requireHttps(profileUrl);
		const res = await fetchWithTimeout(url.toString(), {
			headers: {
				Accept: "application/asp+jwt",
				"User-Agent": "identity-proxy/0.1",
			},
		});

		if (!res.ok) {
			return c.json(
				{ error: `Upstream returned ${res.status}` },
				res.status as any,
			);
		}

		const body = await enforceSize(res);

		return new Response(body, {
			headers: {
				"Content-Type":
					res.headers.get("content-type") || "application/asp+jwt",
			},
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		return c.json({ error: message }, 400);
	}
});

// ── Health check ─────────────────────────────────────────────────────────────

app.get("/health", (c) => c.json({ status: "ok" }));

export default app;
