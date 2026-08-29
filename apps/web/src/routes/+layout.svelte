<script lang="ts">
	import "../app.css";
	import { onMount } from "svelte";
	import { getMe, signInWithGitHub, signOut, type MeResponse } from "$lib/api";
	import { initializeTheme, toggleTheme, watchSystemTheme } from "$lib/theme";

	let { children } = $props();
	let me = $state<MeResponse | null>(null);
	let showMenu = $state(false);
	let signingIn = $state(false);

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
		showMenu = false;
		await signOut();
		me = null;
	}
</script>

<nav class="topbar">
	<div class="topbar-inner">
		<a href="/" class="logo">
			<span class="logo-text">trust<span class="logo-zero">0</span></span>
		</a>
		<div class="nav-links">
			<button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle color theme" title="Toggle color theme">
				<span class="theme-icon theme-icon-light" aria-hidden="true">☾</span>
				<span class="theme-icon theme-icon-dark" aria-hidden="true">☀</span>
			</button>
			{#if me}
				<a href="/identity">My Identity</a>
				<a href="/identity/sign">Sign</a>
				<div class="user-menu">
					<button class="user-btn" onclick={() => { showMenu = !showMenu; }}>
						{#if me.user.image}
							<img src={me.user.image} alt="" class="user-avatar" />
						{/if}
						<span class="user-name">{me.user.name}</span>
						<span class="chevron">▾</span>
					</button>
					{#if showMenu}
						<div class="dropdown">
							<div class="dropdown-header">
								<div class="dropdown-name">{me.user.name}</div>
								<div class="dropdown-email">{me.user.email}</div>
							</div>
							<hr class="dropdown-sep" />
							<a href="/identity" class="dropdown-item" onclick={() => { showMenu = false; }}>Identity Dashboard</a>
							<a href="/identity/sign" class="dropdown-item" onclick={() => { showMenu = false; }}>Sign Document</a>
							<hr class="dropdown-sep" />
							<button class="dropdown-item danger" onclick={handleSignOut}>Sign Out</button>
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
</nav>

<main class="container">
	{@render children()}
</main>

<footer class="site-footer">
	<div class="container">
		<p>trust0 — open source cryptographic identity</p>
		<p class="footer-links">
			<a href="https://github.com/wan0net/trust0">Source</a>
			<span class="sep">·</span>
			<a href="https://ariadne.id">Ariadne Spec</a>
			<span class="sep">·</span>
			<a href="https://wan0.net/trust0/docs/">Docs</a>
			<span class="sep">·</span>
			AGPL-3.0
		</p>
	</div>
</footer>

<style>
	.topbar {
		border-bottom: 1px solid var(--border);
		padding: 12px 24px;
		position: sticky;
		top: 0;
		background: var(--bg);
		z-index: 100;
	}

	.topbar-inner {
		max-width: 960px;
		margin: 0 auto;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.logo { text-decoration: none; color: var(--text); }

	.logo-text {
		font-size: 1.25rem;
		font-weight: 700;
		letter-spacing: -0.03em;
		font-family: var(--font-mono);
	}

	.logo-zero { color: var(--accent); }

	.nav-links {
		display: flex;
		align-items: center;
		gap: 16px;
		font-size: 0.875rem;
	}

	.nav-links a { color: var(--text-dim); text-decoration: none; }
	.nav-links a:hover { color: var(--text); }

	.theme-toggle {
		display: inline-grid;
		place-items: center;
		width: 34px;
		height: 34px;
		padding: 0;
		border: 1px solid var(--border-strong);
		border-radius: 6px;
		background: var(--bg-subtle);
		color: var(--text);
		font-size: 1rem;
	}

	.theme-toggle:hover { background: var(--bg-hover); opacity: 1; }
	:global([data-theme="light"]) .theme-icon-dark { display: none; }
	:global([data-theme="dark"]) .theme-icon-light { display: none; }

	.btn-login {
		padding: 8px 16px;
		border: 1px solid var(--border);
		border-radius: 6px;
		background: transparent;
		color: var(--text);
		font-weight: 500;
		font-size: 0.875rem;
		cursor: pointer;
		font-family: var(--font-sans);
	}

	.btn-login:hover { background: var(--bg-subtle); }
	.btn-login:disabled { opacity: 0.6; cursor: wait; }

	/* ── User menu ──────────────────────────────── */

	.user-menu { position: relative; }

	.user-btn {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 8px;
		border: 1px solid var(--border);
		border-radius: 6px;
		background: transparent;
		color: var(--text);
		cursor: pointer;
		font-size: 0.8rem;
		font-family: var(--font-sans);
	}

	.user-btn:hover { background: var(--bg-subtle); }

	.user-avatar {
		width: 24px;
		height: 24px;
		border-radius: 50%;
		object-fit: cover;
	}

	.user-name { color: var(--text-dim); }
	.chevron { font-size: 0.7rem; color: var(--text-dim); }

	.dropdown {
		position: absolute;
		top: calc(100% + 8px);
		right: 0;
		min-width: 220px;
		background: var(--bg-subtle);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 8px 0;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
	}

	.dropdown-header { padding: 8px 16px; }
	.dropdown-name { font-weight: 600; font-size: 0.85rem; }
	.dropdown-email { font-size: 0.75rem; color: var(--text-dim); }

	.dropdown-sep {
		border: none;
		border-top: 1px solid var(--border);
		margin: 4px 0;
	}

	.dropdown-item {
		display: block;
		width: 100%;
		padding: 8px 16px;
		font-size: 0.8rem;
		color: var(--text-dim);
		text-decoration: none;
		background: none;
		border: none;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
	}

	.dropdown-item:hover { background: var(--bg-hover, #1a1a1a); color: var(--text); }
	.dropdown-item.danger { color: var(--red); }
	.dropdown-item.danger:hover { background: rgba(239, 68, 68, 0.1); }

	/* ── Main + Footer ──────────────────────────── */

	main {
		padding-top: 32px;
		padding-bottom: 64px;
		min-height: calc(100vh - 180px);
	}

	.site-footer {
		border-top: 1px solid var(--border);
		padding: 24px;
		text-align: center;
		font-size: 0.8rem;
		color: var(--text-dim);
	}

	.footer-links { margin-top: 4px; }
	.footer-links a { color: var(--text-dim); }
	.sep { margin: 0 4px; opacity: 0.3; }
</style>
