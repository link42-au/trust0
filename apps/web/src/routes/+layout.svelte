<script lang="ts">
	import "../app.css";
	import { onMount, tick } from "svelte";
	import { page } from "$app/state";
	import { getMe, signInWithGitHub, signOut, type MeResponse } from "$lib/api";
	import { initializeTheme, toggleTheme, watchSystemTheme } from "$lib/theme";

	let { children } = $props();
	let me = $state<MeResponse | null>(null);
	let showMenu = $state(false);
	let signingIn = $state(false);
	let accountMenuRoot: HTMLDivElement | null = $state(null);
	let accountButton: HTMLButtonElement | null = $state(null);
	let accountMenu: HTMLDivElement | null = $state(null);

	onMount(() => {
		initializeTheme();
		return watchSystemTheme();
	});

	onMount(async () => {
		me = await getMe();
	});

	async function handleSignIn() {
		signingIn = true;
		try {
			await signInWithGitHub();
		} catch {
			signingIn = false;
		}
	}

	async function handleSignOut() {
		await closeAccountMenu(false);
		await signOut();
		me = null;
	}

	function isDashboardPath(pathname: string): boolean {
		return pathname === "/identity" || (
			pathname.startsWith("/identity/") &&
			pathname !== "/identity/sign" &&
			!pathname.startsWith("/identity/profile/")
		);
	}

	function getAccountMenuItems(): HTMLElement[] {
		return accountMenu
			? Array.from(accountMenu.querySelectorAll<HTMLElement>('[role="menuitem"]'))
			: [];
	}

	async function openAccountMenu(focusPosition?: "first" | "last") {
		showMenu = true;
		await tick();
		const items = getAccountMenuItems();
		if (focusPosition === "first") items[0]?.focus();
		if (focusPosition === "last") items.at(-1)?.focus();
	}

	async function closeAccountMenu(returnFocus = false) {
		showMenu = false;
		await tick();
		if (returnFocus) accountButton?.focus();
	}

	async function toggleAccountMenu() {
		if (showMenu) await closeAccountMenu();
		else await openAccountMenu();
	}

	async function handleAccountButtonKeydown(event: KeyboardEvent) {
		if (event.key === "ArrowDown" || event.key === "ArrowUp") {
			event.preventDefault();
			await openAccountMenu(event.key === "ArrowDown" ? "first" : "last");
		}
	}

	async function handleAccountMenuKeydown(event: KeyboardEvent) {
		const items = getAccountMenuItems();
		const currentIndex = items.indexOf(document.activeElement as HTMLElement);
		if (event.key === "Escape") {
			event.preventDefault();
			event.stopPropagation();
			await closeAccountMenu(true);
			return;
		}
		if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
		event.preventDefault();
		if (event.key === "Home") items[0]?.focus();
		else if (event.key === "End") items.at(-1)?.focus();
		else if (event.key === "ArrowDown") items[(currentIndex + 1 + items.length) % items.length]?.focus();
		else items[(currentIndex - 1 + items.length) % items.length]?.focus();
	}

	function handleAccountFocusOut(event: FocusEvent) {
		const nextTarget = event.relatedTarget;
		if (nextTarget instanceof Node && accountMenuRoot?.contains(nextTarget)) return;
		showMenu = false;
	}

	function handleWindowClick(event: MouseEvent) {
		if (!showMenu) return;
		const target = event.target;
		if (target instanceof Node && accountMenuRoot?.contains(target)) return;
		showMenu = false;
	}

	async function handleWindowKeydown(event: KeyboardEvent) {
		if (event.key === "Escape" && showMenu) {
			event.preventDefault();
			await closeAccountMenu(true);
		}
	}
</script>

<svelte:window onclick={handleWindowClick} onkeydown={handleWindowKeydown} />

<a href="#main-content" class="skip-link">Skip to content</a>

<div class="site-shell">
	<nav class="platform-banner" aria-label="Link42 products">
		<div class="platform-products">
			<a class="platform-product" href="https://link42.app">link42</a>
			<a class="platform-product" href="https://rule1.link42.app">rule1</a>
			<a class="platform-product" href="https://patch8.link42.app">patch8</a>
			<a class="platform-product" href="https://threat10.link42.app">threat10</a>
			<a class="platform-product platform-product-current" href="https://trust0.link42.app" aria-current="page">trust0</a>
		</div>
	</nav>

	<header class="site-header">
		<div class="header-inner">
			<div class="header-primary">
				<a href="/" class="logo" aria-label="Trust0 home">
					<span class="logo-text">trust<span class="logo-zero">0</span></span>
				</a>
				{#if me}
					<nav class="app-navigation" aria-label="Trust0">
						<a
							href="/identity"
							class:active={isDashboardPath(page.url.pathname)}
							aria-current={isDashboardPath(page.url.pathname) ? "page" : undefined}
						>My Identity</a>
						<a
							href="/identity/sign"
							class:active={page.url.pathname === "/identity/sign"}
							aria-current={page.url.pathname === "/identity/sign" ? "page" : undefined}
						>Sign</a>
					</nav>
				{/if}
			</div>

			<div class="header-actions">
				<button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle color theme" title="Toggle color theme">
					<span class="theme-icon theme-icon-light" aria-hidden="true">☾</span>
					<span class="theme-icon theme-icon-dark" aria-hidden="true">☀</span>
				</button>
				{#if me}
					<div class="user-menu" bind:this={accountMenuRoot} onfocusout={handleAccountFocusOut}>
						<button
							class="user-btn"
							bind:this={accountButton}
							onclick={toggleAccountMenu}
							onkeydown={handleAccountButtonKeydown}
							aria-label="Account menu for {me.user.name}"
							aria-haspopup="menu"
							aria-expanded={showMenu}
							aria-controls="account-menu"
						>
							{#if me.user.image}
								<img src={me.user.image} alt="" class="user-avatar" />
							{:else}
								<span class="user-initial" aria-hidden="true">{me.user.name.charAt(0).toUpperCase()}</span>
							{/if}
							<span class="user-name">{me.user.name}</span>
							<span class="chevron" aria-hidden="true">▾</span>
						</button>
						{#if showMenu}
							<div
								class="account-menu"
								id="account-menu"
								role="menu"
								aria-label="Account"
								tabindex="-1"
								bind:this={accountMenu}
								onkeydown={handleAccountMenuKeydown}
							>
								<div class="account-summary">
									<div class="account-name">{me.user.name}</div>
									<div class="account-email">{me.user.email}</div>
								</div>
								<div class="menu-separator" role="separator"></div>
								<a href="/identity" class="menu-item" role="menuitem" tabindex="-1" onclick={() => closeAccountMenu()}>Identity Dashboard</a>
								<a href="/identity/sign" class="menu-item" role="menuitem" tabindex="-1" onclick={() => closeAccountMenu()}>Sign Document</a>
								<div class="menu-separator" role="separator"></div>
								<button class="menu-item danger" role="menuitem" tabindex="-1" onclick={handleSignOut}>Sign out</button>
							</div>
						{/if}
					</div>
				{:else}
					<button class="btn-login" onclick={handleSignIn} disabled={signingIn}>
						{signingIn ? "Redirecting..." : "Sign in with GitHub"}
					</button>
				{/if}
			</div>
		</div>
	</header>

	<main id="main-content" class="container site-main" tabindex="-1">
		{@render children()}
	</main>

	<footer class="site-footer">
		<div class="footer-content">
			<p class="footer-attribution"><strong>trust0</strong> — open-source cryptographic identity for Link42</p>
			<nav class="footer-links" aria-label="Trust0 resources">
				<a href="https://github.com/link42-au/trust0">Source</a>
				<span class="sep" aria-hidden="true">·</span>
				<a href="https://github.com/link42-au/trust0/tree/main/docs">Docs</a>
				<span class="sep" aria-hidden="true">·</span>
				<a href="https://ariadne.id">Ariadne specification</a>
				<span class="sep" aria-hidden="true">·</span>
				<a href="https://github.com/link42-au/trust0/blob/main/LICENSE">AGPL-3.0</a>
			</nav>
		</div>
	</footer>
</div>

<style>
	.platform-banner {
		background: var(--bg-subtle);
		border-bottom: 1px solid var(--border);
	}

	.platform-products {
		max-width: 960px;
		min-height: 42px;
		margin: 0 auto;
		padding: 6px 24px;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.platform-product {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-height: 30px;
		padding: 4px 10px;
		border: 1px solid transparent;
		border-radius: 7px;
		color: var(--text-dim);
		font-family: var(--font-mono);
		font-size: 0.7rem;
		font-weight: 500;
		line-height: 1;
		text-decoration: none;
		white-space: nowrap;
	}

	.platform-product:hover {
		background: var(--bg-hover);
		color: var(--text);
		text-decoration: none;
	}

	.platform-product-current {
		background: var(--bg-card);
		border-color: var(--border-strong);
		box-shadow: inset 0 -2px var(--accent);
		color: var(--text);
		font-weight: 600;
	}

	.skip-link {
		position: fixed;
		top: -48px;
		left: 0;
		padding: 8px 16px;
		border-radius: 0 0 8px 0;
		background: var(--accent);
		color: var(--accent-contrast);
		font-size: 0.875rem;
		text-decoration: none;
		z-index: 400;
	}

	.skip-link:focus { top: 0; }

	.site-shell {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
	}

	.site-header {
		position: sticky;
		top: 0;
		background: var(--bg);
		border-bottom: 1px solid var(--border);
		z-index: 100;
	}

	.header-inner {
		max-width: 960px;
		min-height: 54px;
		margin: 0 auto;
		padding: 0 24px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	.header-primary,
	.header-actions,
	.app-navigation {
		display: flex;
		align-items: center;
	}

	.header-primary { min-width: 0; }
	.header-actions { flex-shrink: 0; gap: 8px; }

	.logo { text-decoration: none; color: var(--text); }

	.logo-text {
		font-size: 1.25rem;
		font-weight: 700;
		letter-spacing: -0.03em;
		font-family: var(--font-mono);
	}

	.logo-zero { color: var(--accent); }

	.app-navigation {
		gap: 4px;
		margin-left: 24px;
	}

	.app-navigation a {
		padding: 7px 9px;
		border-radius: 6px;
		color: var(--text-mid);
		font-family: var(--font-mono);
		font-size: 0.78rem;
		font-weight: 500;
		line-height: 1;
		text-decoration: none;
		white-space: nowrap;
	}

	.app-navigation a:hover {
		background: var(--bg-hover);
		color: var(--text);
		text-decoration: none;
	}

	.app-navigation a.active {
		background: var(--bg-subtle);
		box-shadow: inset 0 -2px var(--accent);
		color: var(--text);
		font-weight: 600;
	}

	.theme-toggle {
		display: inline-grid;
		place-items: center;
		width: 32px;
		height: 32px;
		padding: 0;
		border: 1px solid var(--border);
		border-radius: 6px;
		background: transparent;
		color: var(--text-mid);
		font-size: 0.95rem;
	}

	.theme-toggle:hover { background: var(--bg-hover); opacity: 1; }
	:global([data-theme="light"]) .theme-icon-dark { display: none; }
	:global([data-theme="dark"]) .theme-icon-light { display: none; }

	.btn-login {
		height: 32px;
		padding: 0 12px;
		border: 1px solid var(--border);
		border-radius: 6px;
		background: transparent;
		color: var(--text-mid);
		font-weight: 500;
		font-size: 0.8rem;
		cursor: pointer;
		font-family: var(--font-sans);
	}

	.btn-login:hover { background: var(--bg-hover); color: var(--text); opacity: 1; }
	.btn-login:disabled { opacity: 0.6; cursor: wait; }

	/* ── User menu ──────────────────────────────── */

	.user-menu { position: relative; }

	.user-btn {
		display: flex;
		align-items: center;
		gap: 6px;
		height: 32px;
		padding: 3px 8px;
		border: 1px solid var(--border);
		border-radius: 6px;
		background: transparent;
		color: var(--text-mid);
		cursor: pointer;
		font-size: 0.75rem;
		font-family: var(--font-sans);
	}

	.user-btn:hover { background: var(--bg-hover); color: var(--text); opacity: 1; }

	.user-avatar,
	.user-initial {
		width: 22px;
		height: 22px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.user-avatar {
		object-fit: cover;
	}

	.user-initial {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--accent);
		color: var(--accent-contrast);
		font-size: 0.65rem;
		font-weight: 700;
	}

	.user-name {
		max-width: 140px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.chevron { font-size: 0.7rem; color: var(--text-dim); }

	.account-menu {
		position: absolute;
		top: calc(100% + 6px);
		right: 0;
		width: min(240px, calc(100vw - 16px));
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 4px;
		box-shadow: var(--shadow-md);
		z-index: 150;
	}

	.account-summary { padding: 8px 10px; }
	.account-name { font-weight: 600; font-size: 0.8rem; }
	.account-email {
		margin-top: 2px;
		color: var(--text-dim);
		font-size: 0.7rem;
		overflow-wrap: anywhere;
	}

	.menu-separator {
		height: 1px;
		margin: 4px 0;
		background: var(--border);
	}

	.menu-item {
		display: flex;
		align-items: center;
		width: 100%;
		min-height: 34px;
		padding: 7px 10px;
		border: 0;
		border-radius: 5px;
		background: transparent;
		color: var(--text-mid);
		font-family: var(--font-sans);
		font-size: 0.75rem;
		font-weight: 500;
		line-height: 1.2;
		text-align: left;
		text-decoration: none;
		cursor: pointer;
	}

	.menu-item:hover,
	.menu-item:focus-visible { background: var(--bg-hover); color: var(--text); opacity: 1; }
	.menu-item.danger { color: var(--red); }
	.menu-item.danger:hover,
	.menu-item.danger:focus-visible { background: var(--red-bg); color: var(--red); }

	/* ── Main + Footer ──────────────────────────── */

	.site-main {
		width: 100%;
		flex: 1;
		padding-top: 32px;
		padding-bottom: 64px;
	}

	.site-footer {
		border-top: 1px solid var(--border);
		padding: 16px;
		background: var(--bg);
		text-align: center;
		font-family: var(--font-mono);
		font-size: 0.7rem;
		color: var(--text-dim);
	}

	.footer-content {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 6px;
	}

	.footer-attribution strong { color: var(--text-mid); font-weight: 600; }
	.footer-links { display: flex; flex-wrap: wrap; justify-content: center; gap: 6px; }
	.footer-links a { color: var(--text-dim); }
	.footer-links a:hover { color: var(--text-mid); }
	.sep { color: var(--border-strong); }

	@media (max-width: 640px) {
		.header-inner { padding-inline: 16px; gap: 8px; }
		.app-navigation { margin-left: 16px; }
		.user-name,
		.chevron { display: none; }
		.user-btn { width: 32px; padding: 3px 4px; justify-content: center; }
	}

	@media (max-width: 420px) {
		.platform-products {
			display: grid;
			grid-template-columns: repeat(5, minmax(0, 1fr));
			gap: 6px;
			padding: 6px 8px;
		}

		.platform-product {
			min-width: 0;
			padding-inline: 2px;
			font-size: 0.625rem;
		}

		.header-inner { min-height: 50px; padding-inline: 8px; }
		.logo-text { font-size: 1.05rem; }
		.app-navigation { margin-left: 8px; gap: 0; }
		.app-navigation a { padding: 6px 5px; font-size: 0.66rem; }
		.header-actions { gap: 4px; }
		.theme-toggle { width: 30px; height: 30px; }
		.btn-login { height: 30px; padding-inline: 9px; font-size: 0.72rem; }
		.site-main { padding-top: 24px; padding-bottom: 48px; }
		.site-footer { padding-inline: 12px; }
	}
</style>
