import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	applyTheme,
	getAppliedTheme,
	initializeTheme,
	parseTheme,
	readThemeCookie,
	resolveTheme,
	toggleTheme,
	watchSystemTheme,
} from "./theme";

type ThemeHarness = {
	attributes: Map<string, string>;
	cookieWrites: string[];
	storage: Map<string, string>;
	emitSystemTheme: (dark: boolean) => void;
};

function contrastRatio(first: string, second: string): number {
	const luminance = (hex: string) => {
		const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
		const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
		return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
	};
	const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
	return (values[0] + 0.05) / (values[1] + 0.05);
}

function readThemeTokens(css: string, theme: "light" | "dark"): Record<string, string> {
	const block = css.match(new RegExp(`\\[data-theme="${theme}"\\] \\{([\\s\\S]*?)\\n\\}`))?.[1] ?? "";
	return Object.fromEntries([...block.matchAll(/--([\w-]+):\s*(#[\da-f]{6})/gi)].map((match) => [match[1], match[2]]));
}

function installThemeHarness(initialTheme: string | null = null): ThemeHarness {
	const attributes = new Map<string, string>();
	if (initialTheme) attributes.set("data-theme", initialTheme);
	const root = {
		style: { colorScheme: "" },
		getAttribute: (name: string) => attributes.get(name) ?? null,
		setAttribute: (name: string, value: string) => attributes.set(name, value),
	};
	let cookie = "";
	const cookieWrites: string[] = [];
	const documentStub = { documentElement: root } as unknown as Document;
	Object.defineProperty(documentStub, "cookie", {
		get: () => cookie,
		set: (value: string) => {
			cookieWrites.push(value);
			cookie = value;
		},
	});

	const storage = new Map<string, string>();
	const listeners = new Set<(event: MediaQueryListEvent) => void>();
	let systemDark = false;
	const mediaQuery = {
		get matches() { return systemDark; },
		addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
		removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
	};

	vi.stubGlobal("document", documentStub);
	vi.stubGlobal("localStorage", {
		getItem: (key: string) => storage.get(key) ?? null,
		setItem: (key: string, value: string) => storage.set(key, value),
	});
	vi.stubGlobal("window", {
		location: { hostname: "trust0.link42.app", protocol: "https:" },
		matchMedia: () => mediaQuery,
	});

	return {
		attributes,
		cookieWrites,
		storage,
		emitSystemTheme: (dark: boolean) => {
			systemDark = dark;
			for (const listener of listeners) listener({ matches: dark } as MediaQueryListEvent);
		},
	};
}

describe("theme foundation", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("accepts only supported themes and resolves cookie, storage, then system preference", () => {
		expect(parseTheme("light")).toBe("light");
		expect(parseTheme("dark")).toBe("dark");
		expect(parseTheme("sepia")).toBeNull();
		expect(readThemeCookie("session=x; theme=dark; other=y")).toBe("dark");
		expect(resolveTheme("light", "dark", true)).toBe("light");
		expect(resolveTheme(null, "dark", false)).toBe("dark");
		expect(resolveTheme(null, null, true)).toBe("dark");
	});

	it("runs the startup resolver before Svelte content can render", () => {
		const template = readFileSync(new URL("../app.html", import.meta.url), "utf8");
		const scriptStart = template.indexOf("<script>");
		expect(template).toContain('<html lang="en" data-theme="light">');
		expect(template).toContain("localStorage.getItem('link42-theme')");
		expect(template).toContain("prefers-color-scheme: dark");
		expect(scriptStart).toBeGreaterThan(0);
		expect(scriptStart).toBeLessThan(template.indexOf("%sveltekit.head%"));
		expect(scriptStart).toBeLessThan(template.indexOf("<body"));
	});

	it("uses the startup-applied theme without overwriting persistence", () => {
		const harness = installThemeHarness("dark");
		expect(initializeTheme()).toBe("dark");
		expect(getAppliedTheme()).toBe("dark");
		expect(harness.attributes.get("data-theme")).toBe("dark");
		expect(harness.cookieWrites).toEqual([]);
		expect(harness.storage.size).toBe(0);
	});

	it("persists a toggle for the shared Link42 domain", () => {
		const harness = installThemeHarness("dark");
		expect(toggleTheme()).toBe("light");
		expect(harness.attributes.get("data-theme")).toBe("light");
		expect(harness.storage.get("link42-theme")).toBe("light");
		expect(harness.cookieWrites.at(-1)).toContain("theme=light");
		expect(harness.cookieWrites.at(-1)).toContain("domain=.link42.app");
		expect(harness.cookieWrites.at(-1)).toContain("Secure");
	});

	it("tracks system changes only until a user preference is saved", () => {
		const harness = installThemeHarness("light");
		const stop = watchSystemTheme();
		harness.emitSystemTheme(true);
		expect(harness.attributes.get("data-theme")).toBe("dark");
		applyTheme("light");
		harness.emitSystemTheme(true);
		expect(harness.attributes.get("data-theme")).toBe("light");
		stop();
	});

	it("keeps shared text, action, and status foregrounds at AA contrast", () => {
		const css = readFileSync(new URL("../app.css", import.meta.url), "utf8");
		for (const theme of ["light", "dark"] as const) {
			const tokens = readThemeTokens(css, theme);
			for (const [foreground, background] of [
				["text", "bg"],
				["text-dim", "bg"],
				["accent", "bg"],
				["accent-contrast", "accent"],
				["status-on-red", "red"],
				["status-on-blue", "blue"],
			]) {
				expect(contrastRatio(tokens[foreground], tokens[background]), `${theme} ${foreground}/${background}`).toBeGreaterThanOrEqual(4.5);
			}
			expect(contrastRatio("#000000", tokens.green), `${theme} green badge`).toBeGreaterThanOrEqual(4.5);
			expect(contrastRatio("#000000", tokens.amber), `${theme} amber badge`).toBeGreaterThanOrEqual(4.5);
		}
	});
});
