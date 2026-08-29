<script lang="ts">
	import { onMount } from "svelte";
	import { getMe, type MeResponse } from "$lib/api";
	import {
		getStoredIdentity,
		fetchMyProfile,
		updateProfile,
		appendAfterAction,
		fetchChain,
		type MyProfile,
		type StoredIdentity
	} from "$lib/identity";
	import { parseProfile } from "@trust0/identity";

	let me = $state<MeResponse | null>(null);
	let identity = $state<StoredIdentity | null>(null);
	let serverProfile = $state<MyProfile | null>(null);
	let existingClaims = $state<string[]>([]);
	let profileName = $state("");
	let profileDescription = $state<string | undefined>(undefined);
	let loading = $state(true);
	
	let domain = $state("");
	let step = $state(1);
	let verifying = $state(false);
	let success = $state(false);
	let error = $state<string | null>(null);

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
				existingClaims = parsed.claims;
				profileName = parsed.name;
				profileDescription = parsed.description;
			} catch {
				/* ignore */
			}
		}
		loading = false;
	});

	function handleNext() {
		if (!domain.trim()) return;
		// Basic domain validation
		const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
		if (!domainRegex.test(domain.trim())) {
			error = "Please enter a valid domain name (e.g., example.com)";
			return;
		}
		error = null;
		step = 2;
	}

	async function handleVerify() {
		if (!identity || !domain.trim()) return;
		verifying = true;
		error = null;

		const PROXY_HOSTNAME = import.meta.env.VITE_PROXY_URL || "http://localhost:8790";

		try {
			const cleanDomain = domain.trim();
			const claimUri = `dns:${cleanDomain}?type=TXT`;
			const [{ Claim }, enums] = await Promise.all([
				import("@trust0/verify/claim"),
				import("@trust0/verify/enums"),
			]);

			// Use doipjs for verification (consistent with profile viewer)
			const claim = new Claim(claimUri, identity.fingerprint);
			claim.match();

			if (claim.matches.length === 0) {
				throw new Error("DNS claim URI not recognized by verification engine");
			}

			await claim.verify({
				proxy: {
					hostname: PROXY_HOSTNAME,
					policy: "adaptive",
				},
			});

			const verified = claim.status === enums.ClaimStatus.VERIFIED
				|| claim.status === enums.ClaimStatus.VERIFIED_VIA_PROXY;

			if (verified) {
				await updateProfile(
					identity,
					profileName,
					[...existingClaims, claimUri],
					profileDescription
				);
				success = true;
				step = 3;

				// Append proof_add to sigchain
				try {
					const chain = await fetchChain(identity.fingerprint);
					if (chain) {
						await appendAfterAction(identity, chain.identityId, "proof_add", { claim_uri: claimUri });
					}
				} catch (err) {
					console.error("Chain append failed:", err);
				}
			} else {
				error = "Record not found. DNS changes can take up to 48 hours to propagate. Try again later.";
			}
		} catch (e) {
			error = e instanceof Error ? e.message : "Failed to verify DNS record";
		}
		
		verifying = false;
	}

	async function copyProofText() {
		if (identity) {
			await navigator.clipboard.writeText(`aspe:trust0.app:${identity.fingerprint}`);
		}
	}
</script>

<div class="page-header">
	<a href="/identity" style="display: inline-block; margin-bottom: 16px;">← Back to Identity</a>
	<h1>Add DNS Proof</h1>
	<p>Prove ownership of a domain</p>
</div>

{#if loading}
	<p aria-busy="true">Loading...</p>
{:else if !me}
	<div class="empty-state">
		<p>Sign in first to manage your identity.</p>
	</div>
{:else if !identity}
	<div class="empty-state">
		<p>Generate a key first on the Identity page.</p>
	</div>
{:else if !serverProfile}
	<div class="empty-state">
		<p>Create a profile first on the Identity page.</p>
	</div>
{:else if success}
	<div class="card">
		<div class="card-header">Done</div>
		<div class="card-body">
			<p style="color: var(--green); font-weight: 500; margin-bottom: 16px;">
				DNS proof added successfully!
			</p>
			<a href="/identity" role="button" class="outline">← Back to Identity</a>
		</div>
	</div>
{:else}
	{#if error}
		<div class="error-state" style="color: var(--red); margin-bottom: 16px;">
			{error}
		</div>
	{/if}

	<div class="grid">
		{#if step === 1}
			<div class="card">
				<div class="card-header">Step 1: Enter Domain</div>
				<div class="card-body">
					<form onsubmit={(e) => { e.preventDefault(); handleNext(); }}>
						<label>
							Domain Name
							<input 
								type="text" 
								bind:value={domain} 
								placeholder="example.com" 
								required 
							/>
						</label>
						<button type="submit" disabled={!domain.trim()}>
							Next
						</button>
					</form>
				</div>
			</div>
		{:else if step === 2}
			<div class="card">
				<div class="card-header">Step 2: Add TXT Record</div>
				<div class="card-body">
					<p>Add this DNS record to your domain:</p>
					
					<figure>
						<table>
							<tbody>
								<tr>
									<td><strong>Host / Name</strong></td>
									<td><code>_aspe.{domain.trim()}</code></td>
								</tr>
								<tr>
									<td><strong>Type</strong></td>
									<td><code>TXT</code></td>
								</tr>
								<tr>
									<td><strong>Value</strong></td>
									<td>
										<div class="value-row">
											<code>aspe:trust0.app:{identity.fingerprint}</code>
											<button class="btn-sm secondary" onclick={copyProofText}>Copy</button>
										</div>
									</td>
								</tr>
							</tbody>
						</table>
					</figure>
					
					<div style="margin-top: 16px; display: flex; gap: 8px;">
						<button onclick={handleVerify} aria-busy={verifying} disabled={verifying}>
							Verify DNS Record
						</button>
						<button class="outline" onclick={() => { step = 1; error = null; }} disabled={verifying}>
							Back
						</button>
					</div>
				</div>
			</div>
		{/if}
	</div>
{/if}

<style>
	.value-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	
	.value-row code {
		word-break: break-all;
	}
</style>
