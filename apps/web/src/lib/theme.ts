export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "link42-theme";
const THEME_MAX_AGE = 60 * 60 * 24 * 365;

export function parseTheme(value: string | null | undefined): Theme | null {
	return value === "light" || value === "dark" ? value : null;
}

export function readThemeCookie(cookie: string): Theme | null {
	return parseTheme(cookie.match(/(?:^|;\s*)theme=(light|dark)/)?.[1]);
}

export function resolveTheme(
	cookieTheme: Theme | null,
	storedTheme: Theme | null,
	prefersDark: boolean,
): Theme {
	return cookieTheme ?? storedTheme ?? (prefersDark ? "dark" : "light");
}

function readStoredTheme(): Theme | null {
	try {
		return parseTheme(localStorage.getItem(THEME_STORAGE_KEY));
	} catch {
		return null;
	}
}

export function hasPersistedTheme(): boolean {
	return readThemeCookie(document.cookie) !== null || readStoredTheme() !== null;
}

export function getAppliedTheme(): Theme {
	return parseTheme(document.documentElement.getAttribute("data-theme")) ?? resolveTheme(
		readThemeCookie(document.cookie),
		readStoredTheme(),
		window.matchMedia("(prefers-color-scheme: dark)").matches,
	);
}

export function applyTheme(theme: Theme, persist = true): Theme {
	document.documentElement.setAttribute("data-theme", theme);
	document.documentElement.style.colorScheme = theme;
	if (!persist) return theme;

	try {
		localStorage.setItem(THEME_STORAGE_KEY, theme);
	} catch {
		/* Cookie persistence still works when storage is unavailable. */
	}

	const hostname = window.location.hostname;
	const sharedDomain = hostname === "link42.app" || hostname.endsWith(".link42.app")
		? ";domain=.link42.app"
		: "";
	const secure = window.location.protocol === "https:" ? ";Secure" : "";
	document.cookie = `theme=${theme};path=/;max-age=${THEME_MAX_AGE};SameSite=Lax${sharedDomain}${secure}`;
	return theme;
}

export function initializeTheme(): Theme {
	return applyTheme(getAppliedTheme(), false);
}

export function toggleTheme(): Theme {
	return applyTheme(getAppliedTheme() === "dark" ? "light" : "dark");
}

export function watchSystemTheme(): () => void {
	const query = window.matchMedia("(prefers-color-scheme: dark)");
	const handleChange = (event: MediaQueryListEvent) => {
		if (!hasPersistedTheme()) applyTheme(event.matches ? "dark" : "light", false);
	};
	query.addEventListener("change", handleChange);
	return () => query.removeEventListener("change", handleChange);
}
