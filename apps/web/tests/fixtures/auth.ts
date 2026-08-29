import type { Page } from "@playwright/test";
import type { MeResponse } from "../../src/lib/api";

export const signedInMe: MeResponse = {
	user: {
		id: "test-user-42",
		name: "Trust0 Test User",
		email: "trust0-test@example.invalid",
		emailVerified: true,
		image: null,
		createdAt: "2026-01-01T00:00:00.000Z",
		updatedAt: "2026-01-01T00:00:00.000Z",
	},
};

export async function mockGetMe(
	page: Page,
	me: MeResponse | null,
): Promise<void> {
	await page.route("**/api/**", async (route) => {
		const requestUrl = new URL(route.request().url());
		if (requestUrl.pathname !== "/api/me") {
			await route.abort("blockedbyclient");
			return;
		}

		if (me === null) {
			await route.fulfill({
				status: 401,
				contentType: "application/json",
				body: JSON.stringify({ error: "Unauthorized" }),
			});
			return;
		}

		await route.fulfill({
			status: 200,
			contentType: "application/json",
			body: JSON.stringify(me),
		});
	});
}

export async function mockAuthSession(
	page: Page,
	initialMe: MeResponse | null,
): Promise<void> {
	let currentMe = initialMe;
	await page.route("**/api/**", async (route) => {
		const request = route.request();
		const pathname = new URL(request.url()).pathname;
		if (pathname === "/api/me") {
			if (currentMe === null) {
				await route.fulfill({
					status: 401,
					contentType: "application/json",
					body: JSON.stringify({ error: "Unauthorized" }),
				});
				return;
			}
			await route.fulfill({
				status: 200,
				contentType: "application/json",
				body: JSON.stringify(currentMe),
			});
			return;
		}

		if (pathname === "/api/auth/sign-out" && request.method() === "POST") {
			currentMe = null;
			await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
			return;
		}

		await route.abort("blockedbyclient");
	});
}
