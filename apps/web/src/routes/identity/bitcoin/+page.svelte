<script lang="ts">
	import { onMount } from "svelte";
	import { getMe, type MeResponse } from "$lib/api";
	import {
		getStoredIdentity, fetchMyProfile, updateProfile, appendAfterAction, fetchChain,
		type MyProfile, type StoredIdentity
	} from "$lib/identity";
	import { parseProfile } from "@trust0/identity";

	let me = $state<MeResponse | null>(null);
	let identity = $state<StoredIdentity | null>(null);
	let serverProfile = $state<MyProfile | null>(null);
	let existingClaims = $state<string[]>([]);
	let profileName = $state("");
	let profileDescription = $state<string | undefined>(undefined);
	let loading = $state(true);
	let btcAddress = $state("");
	let btcSignature = $state("");
	let adding = $state(false);
	let success = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (identity) {
			proofMessage = `I am verifying my identity.\n\naspe:trust0.app:${identity.fingerprint}`;
		}
	});

	let proofMessage = $state("");

	onMount(async () => {
		me = await getMe();
		if (!me) { loading = false; return; }
		identity = await getStoredIdentity();
		serverProfile = await fetchMyProfile();
		if (serverProfile) {
			try {
				const parsed = await parseProfile(serverProfile.profileJws);
				existingClaims = parsed.claims; profileName = parsed.name; profileDescription = parsed.description;
			} catch { /* ignore */ }
		}
		loading = false;
	});

	async function handleAddProof() {
		if (!identity || !btcAddress.trim() || !btcSignature.trim()) return;
		adding = true; error = null;
		try {
			const claimUri = `bitcoin:${btcAddress.trim()}`;
			await updateProfile(identity, profileName, [...existingClaims, claimUri], profileDescription);
			success = true;
			try {
				const chain = await fetchChain(identity.fingerprint);
				if (chain) await appendAfterAction(identity, chain.identityId, "proof_add", {
					claim_uri: claimUri,
					btc_signature: btcSignature.trim(),
					btc_message: proofMessage,
				});
			} catch (err) { console.error("Chain append failed:", err); }
		} catch (e) { error = e instanceof Error ? e.message : "Failed to add proof"; }
		adding = false;
	}

	async function copyProofMessage() {
		await navigator.clipboard.writeText(proofMessage);
	}
</script>

<div class="page-header">
	<a href="/identity" style="display: inline-block; margin-bottom: 16px;">&larr; Back to Identity</a>
	<h1>Add Bitcoin Proof</h1>
	<p>Prove ownership of a Bitcoin address by signing a message</p>
</div>

{#if loading}
	<p aria-busy="true">Loading...</p>
{:else if !me}
	<div class="empty-state"><p>Sign in first to manage your identity.</p></div>
{:else if !identity}
	<div class="empty-state"><p>Generate a key first on the Identity page.</p></div>
{:else if !serverProfile}
	<div class="empty-state"><p>Create a profile first on the Identity page.</p></div>
{:else if success}
	<div class="card">
		<div class="card-header">Done</div>
		<div class="card-body">
			<p style="color: var(--green); font-weight: 500; margin-bottom: 16px;">Bitcoin address linked successfully!</p>
			<a href="/identity" role="button" class="outline">&larr; Back to Identity</a>
		</div>
	</div>
{:else}
	{#if error}
		<div class="error-state" style="color: var(--red); margin-bottom: 16px;">{error}</div>
	{/if}

	<div class="grid">
		<div class="card">
			<div class="card-header">Step 1: Sign This Message</div>
			<div class="card-body">
				<p>Sign this message with your Bitcoin wallet (Sparrow, Electrum, or any BIP-322 compatible wallet):</p>
				<div class="proof-box" style="flex-direction: column; align-items: stretch;">
					<pre style="white-space: pre-wrap; word-break: break-all; font-size: 12px; margin: 0;">{proofMessage}</pre>
					<button class="btn-sm secondary" style="align-self: flex-end; margin-top: 8px;" onclick={copyProofMessage}>Copy Message</button>
				</div>
			</div>
		</div>

		<div class="card">
			<div class="card-header">Step 2: Paste Address & Signature</div>
			<div class="card-body">
				<form onsubmit={(e) => { e.preventDefault(); handleAddProof(); }}>
					<label>
						Bitcoin Address
						<input type="text" bind:value={btcAddress} placeholder="bc1q... or 1A1z..." required />
					</label>
					<label>
						Signature
						<textarea bind:value={btcSignature} placeholder="Paste the base64 signature here" rows="3" required style="font-family: monospace; font-size: 12px;"></textarea>
					</label>
					<button type="submit" aria-busy={adding} disabled={adding || !btcAddress.trim() || !btcSignature.trim()}>
						Link Address
					</button>
				</form>
			</div>
		</div>
	</div>
{/if}

<style>
	.proof-box { display: flex; align-items: center; gap: 8px; padding: 12px; background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px; margin: 12px 0; }
</style>
