import { expect, test } from "@playwright/test";
import { mockGetMe } from "../fixtures/auth";

test("applies the dark system theme before the first interactive frame", async ({ page }) => {
	await page.emulateMedia({ colorScheme: "dark" });
	await page.addInitScript(() => {
		requestAnimationFrame(() => {
			document.documentElement.dataset.themeAtFirstFrame =
				document.documentElement.getAttribute("data-theme") ?? "missing";
		});
	});
	await mockGetMe(page, null);
	await page.goto("/");

	await expect.poll(() => page.evaluate(() => document.documentElement.dataset.themeAtFirstFrame)).toBe("dark");
	await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
	await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).backgroundColor)).toBe("rgb(17, 17, 16)");
	await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).fontFamily)).toContain("Geist");
});

test("persists an explicit light theme across reloads", async ({ page }) => {
	await page.emulateMedia({ colorScheme: "dark" });
	await mockGetMe(page, null);
	await page.goto("/");
	await page.getByRole("button", { name: "Toggle color theme" }).click();

	await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
	await expect.poll(() => page.evaluate(() => localStorage.getItem("link42-theme"))).toBe("light");
	await expect.poll(() => page.evaluate(() => document.cookie)).toContain("theme=light");
	await page.reload();
	await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
	await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).backgroundColor)).toBe("rgb(255, 255, 255)");
});

test("keeps focus visible and suppresses motion when requested", async ({ page }) => {
	await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
	await mockGetMe(page, null);
	await page.goto("/");
	const toggle = page.getByRole("button", { name: "Toggle color theme" });
	await toggle.focus();

	await expect(toggle).toBeFocused();
	await expect.poll(() => toggle.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe("solid");
	await expect.poll(() => toggle.evaluate((element) => getComputedStyle(element).outlineWidth)).toBe("3px");
	await expect.poll(() => toggle.evaluate((element) => Number.parseFloat(getComputedStyle(element).transitionDuration))).toBeLessThan(0.001);
});
