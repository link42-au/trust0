<script lang="ts">
	import { onMount } from "svelte";
	import { getMe, type MeResponse } from "$lib/api";
	import {
		getStoredIdentity,
		generateAndStoreIdentity,
		fetchMyProfile,
		uploadProfile,
		updateProfile,
		claimUsername,
		requestEmailChallenge,
		verifyEmailChallenge,
		exportEncryptedBackup,
		importEncryptedBackup,
		initializeChain,
		fetchChain,
		appendAfterAction,
		rotateKey,
		detectKeyRotationRecovery,
		resumeKeyRotation,
		KeyRotationProfileUpdateError,
		type ChainLink,
		type ChainResponse,
		type KeyRotationRecovery,
		type MyProfile,
		type StoredIdentity
	} from "$lib/identity";
	import { parseProfile } from "@trust0/identity";

	let me = $state<MeResponse | null>(null);
	let identity = $state<StoredIdentity | null>(null);
	let serverProfile = $state<MyProfile | null>(null);
	let parsedClaims = $state<string[]>([]);
	let profileName = $state("");
	let profileDescription = $state<string | undefined>(undefined);
	let profileAvatarUrl = $state<string | undefined>(undefined);
	let profileColor = $state<string | undefined>(undefined);
	let qrSvg = $state("");
	let loading = $state(true);
	let generating = $state(false);
	let creatingProfile = $state(false);
	let error = $state<string | null>(null);

	// Edit profile state
	let editing = $state(false);
	let editName = $state("");
	let editDescription = $state<string | undefined>(undefined);
	let editAvatarUrl = $state<string | undefined>(undefined);
	let editColor = $state<string | undefined>(undefined);
	let saving = $state(false);

	// Form state
	let newName = $state("");
	let newDescription = $state("");
	let usernameInput = $state("");
	let claimingUsername = $state(false);

	// Key backup/import state
	let showExport = $state(false);
	let showImport = $state(false);
	let exportPassphrase = $state("");
	let exportResult = $state("");
	let exporting = $state(false);
	let importPassphrase = $state("");
	let importData = $state("");
	let importing = $state(false);
	let importError = $state<string | null>(null);

	// Email attestation state
	let attestingEmail = $state(false);

	// SSH export state
	let showSshKey = $state(false);
	let sshPublicKey = $state("");

	// Key rotation state
	let rotating = $state(false);
	let showRotateConfirm = $state(false);
	let rotationRecovery = $state<KeyRotationRecovery | null>(null);
	let recoveringRotation = $state(false);
	let rotationRecoveryNotice = $state<string | null>(null);

	// Paper key state
	let showPaperKey = $state(false);
	let paperKeyWords = $state("");

	// Chain state
	let identityId: string | null = $state(null);
	let chain: ChainResponse | null = $state(null);
	let chainLoading: boolean = $state(false);

	onMount(async () => {
		me = await getMe();
		if (!me) {
			loading = false;
			return;
		}

		identity = await getStoredIdentity();
		serverProfile = await fetchMyProfile();

		if (serverProfile) {
			try {
				const parsed = await parseProfile(serverProfile.profileJws);
				parsedClaims = parsed.claims;
				profileName = parsed.name;
				profileDescription = parsed.description;
				profileAvatarUrl = parsed.avatarUrl;
				profileColor = parsed.color;
			} catch {
				/* ignore parse errors */
			}
		}

		// Generate QR code for profile URL
		if (serverProfile) {
			try {
				// @ts-ignore — qrcode-svg has no type declarations
				const QRCode = (await import("qrcode-svg")).default;
				const profileUrl = `https://trust0.app/identity/profile/${serverProfile.username || identity!.fingerprint}`;
				const qr = new QRCode({ content: profileUrl, width: 128, height: 128, padding: 0, join: true });
				qrSvg = qr.svg();
			} catch { /* QR generation is supplementary */ }
		}

		// During interrupted rotation, the server still indexes the old fingerprint.
		if (identity) {
			try {
				const chainLookup = serverProfile && serverProfile.fingerprint !== identity.fingerprint
					? serverProfile.fingerprint
					: identity.fingerprint;
				chain = await fetchChain(chainLookup);
				if (chain) {
					identityId = chain.identityId;
					if (serverProfile) rotationRecovery = await detectKeyRotationRecovery(identity, serverProfile.fingerprint, chain);
				}
			} catch (err) {
				console.error("Chain fetch failed:", err);
			}
		}

		loading = false;
	});

	async function handleGenerateKey() {
		generating = true;
		error = null;
		try {
			identity = await generateAndStoreIdentity();
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to generate key";
		}
		generating = false;
	}

	async function handleCreateProfile() {
		if (!identity || !newName.trim()) return;
		creatingProfile = true;
		error = null;
		try {
			await uploadProfile(identity, newName.trim(), [], newDescription.trim() || undefined);
			serverProfile = await fetchMyProfile();
			if (serverProfile) {
				const parsed = await parseProfile(serverProfile.profileJws);
				parsedClaims = parsed.claims;
				profileName = parsed.name;
			}
			// Initialize sigchain
			try {
				const result = await initializeChain(identity!);
				identityId = result.identityId;
				chain = await fetchChain(identityId);
			} catch (err) {
				console.error("Chain init failed:", err);
			}
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to create profile";
		}
		creatingProfile = false;
	}

	async function handleClaimUsername() {
		if (!identity || !usernameInput.trim()) return;
		claimingUsername = true;
		error = null;
		try {
			await claimUsername(usernameInput.trim(), identity.fingerprint);
			serverProfile = await fetchMyProfile();
			if (identityId && identity) {
				try {
					await appendAfterAction(identity, identityId, "username_claim", { username: usernameInput });
					chain = await fetchChain(identityId);
				} catch (err) {
					console.error("Chain append failed:", err);
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to claim username";
		}
		claimingUsername = false;
	}

	async function copyFingerprint() {
		if (identity) {
			await navigator.clipboard.writeText(identity.fingerprint);
		}
	}

	async function handleAttestEmail() {
		if (!identity || !serverProfile) return;
		attestingEmail = true;
		error = null;
		try {
			// Step 1: Request challenge (server sends email only)
			const { email } = await requestEmailChallenge();

			const challenge = window.prompt(
				`Check ${email} for your verification challenge, then paste it here to continue.`,
			)?.trim();

			if (!challenge) {
				throw new Error("Email verification cancelled");
			}

			// Step 2: Sign challenge with identity key and submit
			const { email: verifiedEmail } = await verifyEmailChallenge(identity, challenge);

			// Step 3: Add mailto: claim to profile
			const mailtoUri = `mailto:${verifiedEmail}`;
			if (!parsedClaims.includes(mailtoUri)) {
				const updatedClaims = [...parsedClaims, mailtoUri];
				await updateProfile(identity, profileName, updatedClaims, profileDescription, profileAvatarUrl, profileColor);
				parsedClaims = updatedClaims;
			}
			if (identityId && identity) {
				try {
					await appendAfterAction(identity, identityId, "proof_add", { claim_uri: mailtoUri });
					chain = await fetchChain(identityId);
				} catch (err) {
					console.error("Chain append failed:", err);
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : "Email attestation failed";
		}
		attestingEmail = false;
	}

	function startEditing() {
		editName = profileName;
		editDescription = profileDescription;
		editAvatarUrl = profileAvatarUrl;
		editColor = profileColor ?? "#000000";
		editing = true;
	}

	async function handleSaveProfile() {
		if (!identity || !editName.trim()) return;
		if (rotationRecovery) {
			error = "Finish the pending key rotation before editing your profile.";
			return;
		}
		saving = true;
		error = null;
		try {
			await updateProfile(identity, editName.trim(), parsedClaims, editDescription?.trim() || undefined, editAvatarUrl?.trim() || undefined, editColor || undefined, serverProfile?.fingerprint);
			serverProfile = await fetchMyProfile();
			if (serverProfile) {
				const parsed = await parseProfile(serverProfile.profileJws);
				profileName = parsed.name;
				profileDescription = parsed.description;
				profileAvatarUrl = parsed.avatarUrl;
				profileColor = parsed.color;
				parsedClaims = parsed.claims;
			}
			if (identityId && identity) {
				try {
					await appendAfterAction(identity, identityId, "profile_update", { profile_fingerprint: identity.fingerprint });
					chain = await fetchChain(identityId);
				} catch (err) {
					console.error("Chain append failed:", err);
				}
			}
			editing = false;
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to save profile";
		}
		saving = false;
	}

	async function handleRemoveClaim(claimUri: string) {
		if (!identity) return;
		error = null;
		const newClaims = parsedClaims.filter(c => c !== claimUri);
		try {
			await updateProfile(identity, profileName, newClaims, profileDescription, profileAvatarUrl, profileColor);
			parsedClaims = newClaims;
			serverProfile = await fetchMyProfile();
			if (identityId && identity) {
				try {
					await appendAfterAction(identity, identityId, "proof_revoke", { claim_uri: claimUri });
					chain = await fetchChain(identityId);
				} catch (err) {
					console.error("Chain append failed:", err);
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to remove claim";
		}
	}

	async function handleRotateKey() {
		if (!identity || !identityId) return;
		rotating = true;
		error = null;
		try {
			const newIdentity = await rotateKey(
				identity,
				identityId,
				profileName,
				parsedClaims,
				profileDescription,
				profileAvatarUrl,
				profileColor,
			);
			identity = newIdentity;
			serverProfile = await fetchMyProfile();
			if (serverProfile) {
				const parsed = await parseProfile(serverProfile.profileJws);
				parsedClaims = parsed.claims;
				profileName = parsed.name;
			}
			chain = await fetchChain(identityId);
			rotationRecovery = null;
			rotationRecoveryNotice = "Key rotation complete. Your public profile now uses the new key.";
			showRotateConfirm = false;
		} catch (e) {
			if (e instanceof KeyRotationProfileUpdateError) {
				identity = e.identity;
				chain = await fetchChain(identityId);
				rotationRecovery = { phase: e.phase, targetFingerprint: e.targetFingerprint };
				showRotateConfirm = false;
				error = null;
			} else {
				error = e instanceof Error ? e.message : "Key rotation failed";
			}
		}
		rotating = false;
	}

	async function handleResumeKeyRotation() {
		if (!identity || !identityId || !serverProfile || !rotationRecovery) return;
		recoveringRotation = true;
		error = null;
		rotationRecoveryNotice = null;
		try {
			await resumeKeyRotation(identity, identityId, serverProfile.fingerprint, {
				name: profileName,
				claims: parsedClaims,
				description: profileDescription,
				avatarUrl: profileAvatarUrl,
				color: profileColor,
			});
			serverProfile = await fetchMyProfile();
			if (!serverProfile) throw new Error("The updated profile could not be loaded");
			const parsed = await parseProfile(serverProfile.profileJws);
			parsedClaims = parsed.claims;
			profileName = parsed.name;
			profileDescription = parsed.description;
			profileAvatarUrl = parsed.avatarUrl;
			profileColor = parsed.color;
			chain = await fetchChain(identityId);
			rotationRecovery = null;
			rotationRecoveryNotice = "Key rotation complete. Your public profile now uses the new key.";
		} catch (e) {
			if (e instanceof KeyRotationProfileUpdateError) {
				identity = e.identity;
				rotationRecovery = { phase: e.phase, targetFingerprint: e.targetFingerprint };
			}
			error = e instanceof Error ? e.message : "Key rotation recovery failed";
		}
		recoveringRotation = false;
	}

	async function handleShowPaperKey() {
		if (!identity) return;
		error = null;
		try {
			const fullJwk = await crypto.subtle.exportKey("jwk", identity.privateKey);
			const { keyToMnemonic } = await import("@trust0/identity");
			paperKeyWords = keyToMnemonic(fullJwk);
			showPaperKey = true;
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to generate paper key";
		}
	}

	async function handleExportSshKey() {
		if (!identity) return;
		const { jwkToSshPublicKey } = await import("@trust0/identity");
		sshPublicKey = jwkToSshPublicKey(identity.publicJWK, `identity-${identity.fingerprint.slice(0, 8)}`);
		showSshKey = true;
	}

	async function handleExportBackup() {
		if (exportPassphrase.length < 8) return;
		exporting = true;
		error = null;
		try {
			exportResult = await exportEncryptedBackup(exportPassphrase);
		} catch (e) {
			error = e instanceof Error ? e.message : "Export failed";
		}
		exporting = false;
	}

	async function copyExportResult() {
		await navigator.clipboard.writeText(exportResult);
	}

	async function handleImportBackup() {
		if (!importData.trim() || !importPassphrase) return;
		importing = true;
		importError = null;
		try {
			identity = await importEncryptedBackup(importData.trim(), importPassphrase);
			serverProfile = await fetchMyProfile();
			if (serverProfile) {
				const parsed = await parseProfile(serverProfile.profileJws);
				parsedClaims = parsed.claims;
				profileName = parsed.name;
			}
			showImport = false;
			importData = "";
			importPassphrase = "";
		} catch (e) {
			importError = e instanceof Error ? e.message : "Import failed";
		}
		importing = false;
	}

	async function handleExportProfile() {
		if (!identity || !serverProfile) return;

		const exportData = {
			version: 1,
			exportedAt: new Date().toISOString(),
			identity: {
				fingerprint: identity.fingerprint,
				identityId: identityId || null,
				username: serverProfile.username || null,
			},
			profile: {
				name: profileName,
				description: profileDescription || null,
				claims: parsedClaims,
			},
			profileJws: serverProfile.profileJws,
			chain: chain ? {
				linkCount: chain.links.length,
				links: chain.links.map(l => ({ seqno: l.seqno, type: l.type, createdAt: l.createdAt })),
			} : null,
			publicKey: {
				kty: identity.publicJWK.kty,
				crv: identity.publicJWK.crv,
				x: identity.publicJWK.x,
			},
		};

		const json = JSON.stringify(exportData, null, 2);
		const blob = new Blob([json], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `identity-${identity.fingerprint.slice(0, 8)}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

{#if loading}
	<div class="empty-state"><p aria-busy="true">Loading...</p></div>
{:else if !me}
	<div class="empty-state">
		<h2>Sign in to get started</h2>
		<p>You need to sign in before you can create your identity.</p>
		<a href="/" style="color: var(--accent);">Go to home page</a>
	</div>
{:else if !identity}
	<!-- ── Onboarding Step 1: Create your key ──────────────────── -->
	<div class="onboarding">
		<div class="onboarding-step">
			<div class="step-indicator">
				<span class="step-dot active">1</span>
				<span class="step-line"></span>
				<span class="step-dot">2</span>
				<span class="step-line"></span>
				<span class="step-dot">3</span>
			</div>
			<h1>Create your identity</h1>
			<p class="onboarding-desc">
				Your identity is based on a unique cryptographic key generated in your browser.
				Your private key never leaves your device — not even we can see it.
			</p>

			{#if error}
				<div class="error-state" style="color: var(--red); margin-bottom: 16px;">{error}</div>
			{/if}

			<button class="cta-btn" onclick={handleGenerateKey} aria-busy={generating} disabled={generating}>
				{generating ? "Generating..." : "Create My Identity"}
			</button>

			<div class="onboarding-alt">
				<p>Already have a backup?</p>
				{#if !showImport}
					<button class="outline btn-sm" onclick={() => { showImport = true; importError = null; importData = ""; importPassphrase = ""; }}>
						Restore from backup
					</button>
				{:else}
					<form onsubmit={(e) => { e.preventDefault(); handleImportBackup(); }} class="import-form">
						<label>
							Backup data
							<textarea bind:value={importData} placeholder="Paste your backup here" rows="3" required style="font-family: monospace; font-size: 11px;"></textarea>
						</label>
						<label>
							Passphrase
							<input type="password" bind:value={importPassphrase} placeholder="Enter passphrase" required />
						</label>
						{#if importError}
							<p style="color: var(--red); font-size: 13px;">{importError}</p>
						{/if}
						<div style="display: flex; gap: 8px;">
							<button type="submit" class="btn-sm" aria-busy={importing} disabled={importing || !importData.trim() || !importPassphrase}>Restore</button>
							<button type="button" class="outline btn-sm" onclick={() => { showImport = false; }}>Cancel</button>
						</div>
					</form>
				{/if}
			</div>
		</div>
	</div>
{:else if !serverProfile}
	<!-- ── Onboarding Step 2: Set up your profile ──────────────── -->
	<div class="onboarding">
		<div class="onboarding-step">
			<div class="step-indicator">
				<span class="step-dot done">✓</span>
				<span class="step-line done"></span>
				<span class="step-dot active">2</span>
				<span class="step-line"></span>
				<span class="step-dot">3</span>
			</div>
			<h1>Set up your profile</h1>
			<p class="onboarding-desc">
				Choose a display name. This is what people see when they view your verified identity.
			</p>

			{#if error}
				<div class="error-state" style="color: var(--red); margin-bottom: 16px;">{error}</div>
			{/if}

			<form onsubmit={(e) => { e.preventDefault(); handleCreateProfile(); }} class="profile-form">
				<label>
					Your name
					<input type="text" bind:value={newName} placeholder="Alice Chen" required />
				</label>
				<label>
					Short bio <span style="color: var(--text-dim); font-weight: 400;">(optional)</span>
					<textarea bind:value={newDescription} placeholder="Security researcher, open source maintainer" rows="2"></textarea>
				</label>
				<button type="submit" class="cta-btn" aria-busy={creatingProfile} disabled={creatingProfile || !newName.trim()}>
					{creatingProfile ? "Creating..." : "Create Profile"}
				</button>
			</form>

			<p class="onboarding-hint">
				Your key: <code>{identity.fingerprint.slice(0, 8)}...{identity.fingerprint.slice(-4)}</code>
			</p>
		</div>
	</div>
{:else}
	<!-- ── Onboarding Step 3 hint (shown briefly) + Full Dashboard ── -->
	{#if parsedClaims.length === 0 && !serverProfile.username}
		<div class="onboarding-banner">
			<div class="step-indicator" style="margin-bottom: 12px;">
				<span class="step-dot done">✓</span>
				<span class="step-line done"></span>
				<span class="step-dot done">✓</span>
				<span class="step-line done"></span>
				<span class="step-dot active">3</span>
			</div>
			<p><strong>Profile created!</strong> Now link your accounts to prove you own them. Pick a platform below to add your first proof.</p>
		</div>
	{/if}

	<div class="page-header">
		<h1>My Identity</h1>
		{#if serverProfile.username}
			<p><a href="/identity/profile/{serverProfile.username}" style="color: var(--accent);">trust0.app/{serverProfile.username}</a> — share this link to let anyone verify your identity.</p>
		{:else}
			<p>Manage your verified accounts and identity settings.</p>
		{/if}
	</div>

	{#if error}
		<div class="error-state" role="alert" style="color: var(--red); margin-bottom: 16px;">{error}</div>
	{/if}
	{#if rotationRecovery}
		<div class="error-state" role="status" aria-live="polite" style="margin-bottom: 16px;">
			<strong>Key rotation needs one more step.</strong>
			<p>{rotationRecovery.phase === "chain-profile-update"
				? "Your new key is safely stored, but the signed identity history still needs to name it as your profile key."
				: "Your signed identity history is ready, but your public profile still uses the previous key."}</p>
			<button class="btn-sm" onclick={handleResumeKeyRotation} aria-busy={recoveringRotation} disabled={recoveringRotation}>
				{recoveringRotation ? "Finishing..." : "Finish key rotation"}
			</button>
		</div>
	{:else if rotationRecoveryNotice}
		<div role="status" aria-live="polite" style="margin-bottom: 16px; color: var(--accent);">{rotationRecoveryNotice}</div>
	{/if}
		<div class="grid">
			<div class="card">
				<div class="card-header">Profile Info</div>
				<div class="card-body">
					<div class="profile-detail">
						<strong>Fingerprint</strong>
						<div class="fingerprint-row">
							<code>{identity.fingerprint}</code>
							<button class="btn-sm secondary" onclick={copyFingerprint}>Copy</button>
						</div>
					</div>

					{#if identityId}
						<div class="profile-detail">
							<strong>Identity ID</strong>
							<code>{identityId}</code>
						</div>
					{/if}

					{#if editing}
					<div class="profile-detail">
						<strong>Edit Profile</strong>
						<div style="display: flex; flex-direction: column; gap: 12px;">
							<label>
								Name
								<input type="text" bind:value={editName} />
							</label>
							<label>
								Description
								<textarea bind:value={editDescription} rows="3"></textarea>
							</label>
							<label>
								Avatar URL <small>(optional)</small>
								<input type="url" bind:value={editAvatarUrl} placeholder="https://example.com/avatar.jpg" />
							</label>
							<label>
								Theme Color <small>(optional)</small>
								<input type="color" bind:value={editColor} />
							</label>
							<div style="display: flex; gap: 8px;">
								<button onclick={handleSaveProfile} aria-busy={saving} disabled={saving || !editName.trim()}>Save</button>
								<button class="outline" onclick={() => editing = false} disabled={saving}>Cancel</button>
							</div>
						</div>
					</div>
				{:else}
					<div class="profile-detail">
						<strong>Name</strong>
						<div>{profileName}</div>
					</div>

					{#if profileDescription}
						<div class="profile-detail">
							<strong>Description</strong>
							<div>{profileDescription}</div>
						</div>
					{/if}

					{#if profileAvatarUrl}
						<div class="profile-detail">
							<strong>Avatar</strong>
							<img src={profileAvatarUrl} alt="Profile avatar" style="width: 64px; height: 64px; border-radius: 50%; object-fit: cover;" />
						</div>
					{/if}

					{#if profileColor}
						<div class="profile-detail">
							<strong>Theme Color</strong>
							<div style="display: flex; align-items: center; gap: 8px;">
								<span style="display: inline-block; width: 20px; height: 20px; border-radius: 4px; background: {profileColor};"></span>
								<code>{profileColor}</code>
							</div>
						</div>
					{/if}

					<div class="profile-detail" style="display: flex; gap: 8px;">
						<button class="outline btn-sm" onclick={startEditing} disabled={Boolean(rotationRecovery)}>Edit Profile</button>
						<button class="outline btn-sm" onclick={handleExportProfile}>Download Profile</button>
					</div>
				{/if}

					<div class="profile-detail">
						<strong>Username</strong>
						{#if serverProfile.username}
							<div>@{serverProfile.username}</div>
						{:else}
							<form class="inline-form" onsubmit={(e) => { e.preventDefault(); handleClaimUsername(); }}>
								<input type="text" bind:value={usernameInput} placeholder="username" required />
								<button type="submit" class="btn-sm" aria-busy={claimingUsername} disabled={claimingUsername || !usernameInput.trim()}>
									Claim
								</button>
							</form>
						{/if}
					</div>

					<div class="profile-detail">
						<strong>Created</strong>
						<div style="color: var(--text-dim); font-size: 14px;">
							{new Date(serverProfile.createdAt).toLocaleDateString()}
						</div>
					</div>

					{#if qrSvg}
						<div class="qr-section">
							<div class="qr-code">
								{@html qrSvg}
							</div>
							<p class="qr-label">Scan to view profile</p>
						</div>
					{/if}
				</div>
			</div>

			<div class="card">
				<div class="card-header">Your verified identities</div>
				<div class="card-body">
					{#if parsedClaims.length === 0}
						<p style="color: var(--text-dim);">(no claims yet)</p>
					{:else}
						<ul class="claims-list">
							{#each parsedClaims as claim}
								<li>
									<a href={claim} target="_blank" rel="noopener noreferrer">{claim}</a>
									<button class="btn-sm outline" style="margin-left: auto; font-size: 0.75rem;" onclick={() => handleRemoveClaim(claim)}>Remove</button>
								</li>
							{/each}
						</ul>
					{/if}

				<div class="actions-row" style="margin-top: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
					<a href="/identity/github" role="button" class="outline btn-sm">GitHub</a>
					<a href="/identity/gitlab" role="button" class="outline btn-sm">GitLab</a>
					<a href="/identity/sourcehut" role="button" class="outline btn-sm">Sourcehut</a>
					<a href="/identity/mastodon" role="button" class="outline btn-sm">Mastodon</a>
					<a href="/identity/bluesky" role="button" class="outline btn-sm">Bluesky</a>
					<a href="/identity/twitter" role="button" class="outline btn-sm">Twitter/X</a>
					<a href="/identity/reddit" role="button" class="outline btn-sm">Reddit</a>
					<a href="/identity/hackernews" role="button" class="outline btn-sm">Hacker News</a>
					<a href="/identity/lobsters" role="button" class="outline btn-sm">Lobsters</a>
					<a href="/identity/orcid" role="button" class="outline btn-sm">ORCID</a>
					<a href="/identity/keybase" role="button" class="outline btn-sm">Keybase</a>
					<a href="/identity/website" role="button" class="outline btn-sm">Website</a>
					<a href="/identity/dns" role="button" class="outline btn-sm">DNS</a>
					<a href="/identity/ethereum" role="button" class="outline btn-sm">Ethereum</a>
					<a href="/identity/bitcoin" role="button" class="outline btn-sm">Bitcoin</a>
					<a href="/identity/solana" role="button" class="outline btn-sm">Solana</a>
					<a href="/identity/nostr" role="button" class="outline btn-sm">Nostr</a>
					<a href="/identity/discord" role="button" class="outline btn-sm">Discord</a>
					<a href="/identity/telegram" role="button" class="outline btn-sm">Telegram</a>
					<a href="/identity/sign" role="button" class="outline btn-sm">Sign Document</a>
					<button class="outline btn-sm" onclick={handleAttestEmail} aria-busy={attestingEmail} disabled={attestingEmail}>
						Add Email
					</button>
				</div>
				</div>
			</div>

			<div class="card">
				<div class="card-header">Key Management</div>
				<div class="card-body">
					<div class="key-mgmt-section">
						{#if !showExport}
							<button class="outline btn-sm" onclick={() => { showExport = true; exportResult = ""; exportPassphrase = ""; }}>
								Export Backup
							</button>
						{:else}
							<form onsubmit={(e) => { e.preventDefault(); handleExportBackup(); }}>
								<label>
									Passphrase (min 8 characters)
									<input type="password" bind:value={exportPassphrase} placeholder="Enter passphrase" minlength="8" required />
								</label>
								<div style="display: flex; gap: 8px; margin-top: 8px;">
									<button type="submit" class="btn-sm" aria-busy={exporting} disabled={exporting || exportPassphrase.length < 8}>
										Generate Backup
									</button>
									<button type="button" class="outline btn-sm secondary" onclick={() => { showExport = false; exportResult = ""; }}>
										Cancel
									</button>
								</div>
							</form>
							{#if exportResult}
								<div style="margin-top: 12px;">
									<label>
										Backup data
										<textarea readonly bind:value={exportResult} rows="4" style="font-family: monospace; font-size: 11px; word-break: break-all;"></textarea>
									</label>
									<div style="display: flex; gap: 8px; align-items: center; margin-top: 8px;">
										<button class="btn-sm outline" onclick={copyExportResult}>Copy</button>
										<span style="color: var(--text-dim); font-size: 12px;">Store this backup securely. You'll need the passphrase to restore it.</span>
									</div>
								</div>
							{/if}
						{/if}
					</div>

					<div class="key-mgmt-section" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border, #333);">
						{#if !showImport}
							<button class="outline btn-sm" onclick={() => { showImport = true; importError = null; importData = ""; importPassphrase = ""; }}>
								Import Key
							</button>
						{:else}
							<form onsubmit={(e) => { e.preventDefault(); handleImportBackup(); }}>
								<label>
									Backup data
									<textarea bind:value={importData} placeholder="Paste your backup here" rows="4" required style="font-family: monospace; font-size: 11px; word-break: break-all;"></textarea>
								</label>
								<label>
									Passphrase
									<input type="password" bind:value={importPassphrase} placeholder="Enter passphrase" required />
								</label>
								{#if importError}
									<p style="color: var(--red); font-size: 13px; margin: 8px 0 0;">{importError}</p>
								{/if}
								<div style="display: flex; gap: 8px; margin-top: 8px;">
									<button type="submit" class="btn-sm" aria-busy={importing} disabled={importing || !importData.trim() || !importPassphrase}>
										Restore
									</button>
									<button type="button" class="outline btn-sm secondary" onclick={() => { showImport = false; importError = null; }}>
										Cancel
									</button>
								</div>
							</form>
						{/if}
					</div>

					<div class="key-mgmt-section" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border, #333);">
						<button class="outline btn-sm" onclick={handleExportSshKey}>Export SSH Key</button>
						{#if showSshKey}
							<div class="ssh-export" style="margin-top: 12px;">
								<div style="font-weight: 600; margin-bottom: 4px;">SSH Public Key</div>
								<div class="proof-box">
									<code style="font-size: 0.7rem; word-break: break-all;">{sshPublicKey}</code>
									<button class="btn-sm secondary" onclick={() => navigator.clipboard.writeText(sshPublicKey)}>Copy</button>
								</div>
								<div style="font-weight: 600; margin: 8px 0 4px;">Git Config</div>
								<pre style="font-size: 0.75rem; padding: 12px; background: var(--bg-subtle); border-radius: 8px; overflow-x: auto;">git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/identity_ed25519.pub
git config --global commit.gpgsign true</pre>
							</div>
						{/if}
					</div>

					<div class="key-mgmt-section" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border, #333);">
						{#if !showPaperKey}
							<button class="outline btn-sm" onclick={handleShowPaperKey}>Show Paper Key</button>
							<p style="color: var(--text-dim); font-size: 12px; margin-top: 4px;">
								24-word recovery phrase — write it down and store securely.
							</p>
						{:else}
							<div style="border: 1px solid var(--amber); border-radius: 8px; padding: 16px; background: var(--bg-subtle);">
								<p style="color: var(--amber); font-weight: 600; margin-bottom: 8px;">Paper Key — Write This Down</p>
								<p style="font-size: 13px; margin-bottom: 12px; color: var(--text-dim);">
									These 24 words can recover your identity. Store them offline in a safe place.
									Anyone with these words has full access to your key.
								</p>
								<div class="paper-key-grid">
									{#each paperKeyWords.split(" ") as word, i}
										<div class="paper-key-word">
											<span class="word-num">{i + 1}.</span> {word}
										</div>
									{/each}
								</div>
								<div style="display: flex; gap: 8px; margin-top: 12px;">
									<button class="btn-sm" onclick={() => navigator.clipboard.writeText(paperKeyWords)}>Copy</button>
									<button class="outline btn-sm secondary" onclick={() => { showPaperKey = false; paperKeyWords = ""; }}>Hide</button>
								</div>
							</div>
						{/if}
					</div>

					<div class="key-mgmt-section" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border, #333);">
						{#if !showRotateConfirm}
							<button class="outline btn-sm" style="color: var(--amber);" onclick={() => { showRotateConfirm = true; }}>
								Rotate Key
							</button>
							<p style="color: var(--text-dim); font-size: 12px; margin-top: 4px;">
								Generate a new key and delegate authority from the current one.
							</p>
						{:else}
							<div style="border: 1px solid var(--amber); border-radius: 8px; padding: 12px; background: var(--bg-subtle);">
								<p style="color: var(--amber); font-weight: 600; margin-bottom: 8px;">Confirm Key Rotation</p>
								<p style="font-size: 13px; margin-bottom: 12px;">
									This will generate a new Ed25519 key and transfer your identity to it.
									Your old key will remain in the sigchain as a historical record.
									Your identity ID stays the same — only the fingerprint changes.
								</p>
								<div style="display: flex; gap: 8px;">
									<button class="btn-sm" style="background: var(--amber); color: black;" onclick={handleRotateKey} aria-busy={rotating} disabled={rotating}>
										Rotate Now
									</button>
									<button class="outline btn-sm secondary" onclick={() => { showRotateConfirm = false; }} disabled={rotating}>
										Cancel
									</button>
								</div>
							</div>
						{/if}
					</div>
				</div>
			</div>

			{#if chain && chain.links.length > 0}
				<div class="card">
					<div class="card-header">Chain History</div>
					<div class="card-body">
						<p class="chain-summary">{chain.links.length} link{chain.links.length === 1 ? "" : "s"} in chain</p>
						<div class="chain-links">
							{#each chain.links as link}
								<div class="chain-link">
									<span class="link-seqno">#{link.seqno}</span>
									<span class="link-type">{link.type}</span>
									<span class="link-time">{new Date(link.createdAt).toLocaleDateString()}</span>
								</div>
							{/each}
						</div>
					</div>
				</div>
			{/if}
		</div>
	{/if}

	<style>
	/* ── Onboarding ─────────────────────────────── */

	.onboarding {
		display: flex;
		justify-content: center;
		padding: 48px 0;
	}

	.onboarding-step {
		max-width: 480px;
		text-align: center;
	}

	.onboarding-step h1 {
		font-size: 1.75rem;
		font-weight: 700;
		margin-bottom: 12px;
	}

	.onboarding-desc {
		color: var(--text-dim);
		font-size: 0.95rem;
		line-height: 1.6;
		margin-bottom: 28px;
	}

	.step-indicator {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0;
		margin-bottom: 24px;
	}

	.step-dot {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		border: 2px solid var(--border);
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-dim);
	}

	.step-dot.active {
		border-color: var(--accent);
		background: var(--accent);
		color: #000;
	}

	.step-dot.done {
		border-color: var(--green);
		background: var(--green);
		color: #000;
	}

	.step-line {
		width: 40px;
		height: 2px;
		background: var(--border);
	}

	.step-line.done {
		background: var(--green);
	}

	.cta-btn {
		background: var(--accent);
		color: #000;
		padding: 12px 32px;
		border-radius: 8px;
		font-weight: 600;
		font-size: 1rem;
		border: none;
		cursor: pointer;
		font-family: var(--font-sans);
	}

	.cta-btn:hover { opacity: 0.85; }
	.cta-btn:disabled { opacity: 0.5; cursor: wait; }

	.onboarding-alt {
		margin-top: 32px;
		padding-top: 24px;
		border-top: 1px solid var(--border);
		color: var(--text-dim);
		font-size: 0.85rem;
	}

	.onboarding-alt p { margin-bottom: 8px; }

	.import-form {
		text-align: left;
		max-width: 360px;
		margin: 12px auto 0;
	}

	.profile-form {
		text-align: left;
		max-width: 400px;
		margin: 0 auto 16px;
	}

	.onboarding-hint {
		margin-top: 16px;
		font-size: 0.8rem;
		color: var(--text-dim);
	}

	.onboarding-banner {
		text-align: center;
		padding: 24px;
		margin-bottom: 24px;
		border: 1px solid var(--accent);
		border-radius: 12px;
		background: rgba(0, 212, 170, 0.05);
	}

	.onboarding-banner p {
		font-size: 0.9rem;
		color: var(--text-dim);
	}

	/* ── Dashboard ──────────────────────────────── */

	.fingerprint-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.profile-detail {
		margin-bottom: 16px;
	}

	.profile-detail:last-child {
		margin-bottom: 0;
	}

	.profile-detail strong {
		display: block;
		font-size: 12px;
		color: var(--text-dim);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 4px;
	}

	.inline-form {
		display: flex;
		gap: 8px;
		align-items: center;
	}

	.inline-form input {
		margin-bottom: 0;
		flex: 1;
	}

	.claims-list {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.claims-list li {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
		word-break: break-all;
	}

	.chain-summary {
		color: var(--text-dim);
		margin-bottom: 0.75rem;
	}

	.chain-links {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.chain-link {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.5rem;
		background: var(--bg-secondary, #f5f5f5);
		border-radius: 4px;
		font-size: 0.875rem;
	}

	.link-seqno {
		font-weight: 600;
		color: var(--text-dim);
		min-width: 2rem;
	}

	.link-type {
		font-family: var(--font-mono, monospace);
		background: var(--accent, teal);
		color: white;
		padding: 0.125rem 0.5rem;
		border-radius: 3px;
		font-size: 0.75rem;
	}

	.link-time {
		color: var(--text-dim);
		margin-left: auto;
		font-size: 0.75rem;
	}

	.qr-section {
		display: flex;
		flex-direction: column;
		align-items: center;
		margin-top: 16px;
		padding-top: 16px;
		border-top: 1px solid var(--border);
	}

	.qr-code {
		background: white;
		padding: 8px;
		border-radius: 8px;
		border: 1px solid var(--border);
		display: inline-block;
	}

	.qr-code :global(svg) {
		width: 128px;
		height: 128px;
		display: block;
	}

	.qr-label {
		font-size: 0.75rem;
		color: var(--text-dim);
		margin-top: 8px;
	}

	.paper-key-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 6px;
		font-family: monospace;
		font-size: 13px;
	}

	.paper-key-word {
		padding: 4px 8px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 4px;
	}

	.word-num {
		color: var(--text-dim);
		font-size: 11px;
		margin-right: 2px;
	}
</style>
