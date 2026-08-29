import { expect, test } from "@playwright/test";
import { mockGetMe } from "../fixtures/auth";

const PRODUCTS = [
	["link42", "https://link42.app"],
	["rule1", "https://rule1.link42.app"],
	["patch8", "https://patch8.link42.app"],
	["threat10", "https://threat10.link42.app"],
	["trust0", "https://trust0.link42.app"],
] as const;

test("links the five products in canonical order and marks Trust0 current", async ({ page }) => {
	await mockGetMe(page, null);
	await page.goto("/");

	const banner = page.getByRole("navigation", { name: "Link42 products" });
	const links = banner.getByRole("link");
	await expect(links).toHaveCount(PRODUCTS.length);
	for (const [index, [label, href]] of PRODUCTS.entries()) {
		await expect(links.nth(index)).toHaveText(label);
		await expect(links.nth(index)).toHaveAttribute("href", href);
	}
	await expect(links.filter({ hasText: "trust0" })).toHaveAttribute("aria-current", "page");
	await expect(banner.locator('[aria-current="page"]')).toHaveCount(1);
});

test("keeps every product keyboard reachable with a visible focus state", async ({ page }) => {
	await mockGetMe(page, null);
	await page.goto("/");

	const links = page.getByRole("navigation", { name: "Link42 products" }).getByRole("link");
	for (let index = 0; index < PRODUCTS.length; index += 1) {
		await page.keyboard.press("Tab");
		await expect(links.nth(index)).toBeFocused();
	}
	await expect.poll(() => links.last().evaluate((element) => getComputedStyle(element).outlineWidth)).toBe("3px");
});

for (const viewport of [
	{ name: "mobile", width: 320, height: 720 },
	{ name: "desktop", width: 1280, height: 800 },
] as const) {
	test(`fits the ${viewport.name} viewport without overlap or clipping`, async ({ page }, testInfo) => {
		await page.setViewportSize({ width: viewport.width, height: viewport.height });
		await mockGetMe(page, null);
		await page.goto("/");

		const banner = page.getByRole("navigation", { name: "Link42 products" });
		const links = banner.getByRole("link");
		const rectangles = await links.evaluateAll((elements) => elements.map((element) => {
			const rect = element.getBoundingClientRect();
			return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom };
		}));
		for (const rect of rectangles) {
			expect(rect.left).toBeGreaterThanOrEqual(0);
			expect(rect.right).toBeLessThanOrEqual(viewport.width);
		}
		for (let first = 0; first < rectangles.length; first += 1) {
			for (let second = first + 1; second < rectangles.length; second += 1) {
				const horizontalOverlap = rectangles[first].left < rectangles[second].right && rectangles[first].right > rectangles[second].left;
				const verticalOverlap = rectangles[first].top < rectangles[second].bottom && rectangles[first].bottom > rectangles[second].top;
				expect(horizontalOverlap && verticalOverlap, `${PRODUCTS[first][0]} overlaps ${PRODUCTS[second][0]}`).toBe(false);
			}
		}
		await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
		await page.screenshot({ path: testInfo.outputPath(`platform-banner-${viewport.name}.png`) });
	});
}
