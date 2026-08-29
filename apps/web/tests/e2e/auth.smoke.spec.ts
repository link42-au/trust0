import { expect, test } from "@playwright/test";
import { mockGetMe, signedInMe } from "../fixtures/auth";

test("shows signed-out navigation and landing action", async ({ page }) => {
	await mockGetMe(page, null);
	await page.goto("/");

	await expect(
		page.getByRole("button", { name: "Sign in with GitHub", exact: true }),
	).toBeVisible();
	await expect(
		page.getByRole("button", {
			name: "Get Started — Sign in with GitHub",
			exact: true,
		}),
	).toBeVisible();
});

test("shows signed-in navigation and landing action", async ({ page }) => {
	await mockGetMe(page, signedInMe);
	await page.goto("/");

	await expect(
		page.getByRole("button", { name: /Trust0 Test User/ }),
	).toBeVisible();
	await expect(
		page.getByRole("link", { name: "My Identity", exact: true }),
	).toBeVisible();
	await expect(
		page.getByRole("button", { name: "Go to My Identity", exact: true }),
	).toBeVisible();
});
