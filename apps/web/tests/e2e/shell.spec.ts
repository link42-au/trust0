import { expect, test, type Locator, type Page } from "@playwright/test";
import { mockAuthSession, mockGetMe, signedInMe } from "../fixtures/auth";

async function expectInsideViewport(page: Page, locators: Locator[]): Promise<void> {
	const rectangles = [];
	for (const locator of locators) {
		const rect = await locator.boundingBox();
		expect(rect).not.toBeNull();
		if (rect) rectangles.push(rect);
	}
	for (const rect of rectangles) {
		expect(rect.x).toBeGreaterThanOrEqual(0);
		expect(rect.x + rect.width).toBeLessThanOrEqual(320);
	}
	for (let first = 0; first < rectangles.length; first += 1) {
		for (let second = first + 1; second < rectangles.length; second += 1) {
			const horizontalOverlap = rectangles[first].x < rectangles[second].x + rectangles[second].width && rectangles[first].x + rectangles[first].width > rectangles[second].x;
			const verticalOverlap = rectangles[first].y < rectangles[second].y + rectangles[second].height && rectangles[first].y + rectangles[first].height > rectangles[second].y;
			expect(horizontalOverlap && verticalOverlap).toBe(false);
		}
	}
	await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

test("keeps signed-out shell actions and canonical resource links", async ({ page }) => {
	await mockGetMe(page, null);
	await page.goto("/");

	await expect(page.getByRole("link", { name: "Trust0 home" })).toHaveAttribute("href", "/");
	await expect(page.getByRole("button", { name: "Sign in with GitHub", exact: true })).toBeVisible();
	await expect(page.getByRole("navigation", { name: "Trust0", exact: true })).toHaveCount(0);

	const resources = page.getByRole("navigation", { name: "Trust0 resources" });
	await expect(resources.getByRole("link", { name: "Source" })).toHaveAttribute("href", "https://github.com/link42-au/trust0");
	await expect(resources.getByRole("link", { name: "Docs" })).toHaveAttribute("href", "https://github.com/link42-au/trust0/tree/main/docs");
	await expect(resources.getByRole("link", { name: "AGPL-3.0" })).toHaveAttribute("href", "https://github.com/link42-au/trust0/blob/main/LICENSE");

	const signInRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/auth/sign-in/social");
	await page.getByRole("button", { name: "Sign in with GitHub", exact: true }).click();
	const request = await signInRequest;
	expect(request.method()).toBe("POST");
	expect(request.postDataJSON()).toEqual({
		provider: "github",
		callbackURL: "http://127.0.0.1:4373/identity",
	});
});

test("preserves signed-in dashboard, signing, and public-profile routes", async ({ page }) => {
	await mockGetMe(page, signedInMe);
	await page.goto("/identity");

	const navigation = page.getByRole("navigation", { name: "Trust0", exact: true });
	const dashboard = navigation.getByRole("link", { name: "My Identity" });
	const signing = navigation.getByRole("link", { name: "Sign" });
	await expect(dashboard).toHaveAttribute("href", "/identity");
	await expect(signing).toHaveAttribute("href", "/identity/sign");
	await expect(dashboard).toHaveAttribute("aria-current", "page");

	await page.goto("/identity/sign");
	await expect(signing).toHaveAttribute("aria-current", "page");
	await expect(dashboard).not.toHaveAttribute("aria-current", "page");

	const response = await page.goto("/identity/profile/not-found");
	expect(response?.status()).toBe(200);
	await expect(page.getByRole("link", { name: "Trust0 home" })).toBeVisible();
	await expect(page.locator("#main-content")).toBeVisible();
});

test("supports account-menu keyboard traversal, dismissal, and focus return", async ({ page }) => {
	await mockGetMe(page, signedInMe);
	await page.goto("/");

	const trigger = page.getByRole("button", { name: /Account menu for Trust0 Test User/ });
	await expect(trigger).toHaveAttribute("aria-haspopup", "menu");
	await expect(trigger).toHaveAttribute("aria-expanded", "false");
	await trigger.focus();
	await page.keyboard.press("ArrowDown");

	const menu = page.getByRole("menu", { name: "Account" });
	const dashboard = menu.getByRole("menuitem", { name: "Identity Dashboard" });
	const signing = menu.getByRole("menuitem", { name: "Sign Document" });
	const signOut = menu.getByRole("menuitem", { name: "Sign out" });
	await expect(trigger).toHaveAttribute("aria-expanded", "true");
	await expect(dashboard).toBeFocused();
	await page.keyboard.press("ArrowDown");
	await expect(signing).toBeFocused();
	await page.keyboard.press("End");
	await expect(signOut).toBeFocused();
	await page.keyboard.press("Home");
	await expect(dashboard).toBeFocused();
	await page.keyboard.press("Escape");
	await expect(menu).toBeHidden();
	await expect(trigger).toHaveAttribute("aria-expanded", "false");
	await expect(trigger).toBeFocused();

	await trigger.click();
	await expect(menu).toBeVisible();
	await page.locator("#main-content").click({ position: { x: 1, y: 1 } });
	await expect(menu).toBeHidden();
	await expect(trigger).toHaveAttribute("aria-expanded", "false");
});

test("keeps account routes working and clears the shell on sign out", async ({ page }) => {
	await mockAuthSession(page, signedInMe);
	await page.goto("/");

	const trigger = page.getByRole("button", { name: /Account menu for Trust0 Test User/ });
	await trigger.click();
	await page.getByRole("menuitem", { name: "Sign Document" }).click();
	await expect(page).toHaveURL(/\/identity\/sign$/);

	await trigger.click();
	await page.getByRole("menuitem", { name: "Identity Dashboard" }).click();
	await expect(page).toHaveURL(/\/identity$/);

	await trigger.click();
	await page.getByRole("menuitem", { name: "Sign out" }).click();
	await expect(page).toHaveURL("http://127.0.0.1:4373/");
	await expect(page.getByRole("button", { name: "Sign in with GitHub", exact: true })).toBeVisible();
	await expect(trigger).toHaveCount(0);
});

for (const session of [
	{ name: "signed-out", me: null },
	{ name: "signed-in", me: signedInMe },
] as const) {
	test(`fits the ${session.name} header and menu at 320px`, async ({ page }, testInfo) => {
		await page.setViewportSize({ width: 320, height: 720 });
		await mockGetMe(page, session.me);
		await page.goto("/");

		const controls = [
			page.getByRole("link", { name: "Trust0 home" }),
			page.getByRole("button", { name: "Toggle color theme" }),
		];
		if (session.me) {
			controls.push(
				page.getByRole("link", { name: "My Identity" }),
				page.getByRole("link", { name: "Sign", exact: true }),
				page.getByRole("button", { name: /Account menu for Trust0 Test User/ }),
			);
		} else {
			controls.push(page.getByRole("button", { name: "Sign in with GitHub", exact: true }));
		}
		await expectInsideViewport(page, controls);

		if (session.me) {
			await page.getByRole("button", { name: /Account menu for Trust0 Test User/ }).click();
			const menuRect = await page.getByRole("menu", { name: "Account" }).boundingBox();
			expect(menuRect).not.toBeNull();
			if (menuRect) {
				expect(menuRect.x).toBeGreaterThanOrEqual(0);
				expect(menuRect.x + menuRect.width).toBeLessThanOrEqual(320);
			}
		}
		await page.screenshot({ path: testInfo.outputPath(`shell-${session.name}-320.png`) });
	});
}
