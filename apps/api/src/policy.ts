import type { ChainState } from "@trust0/identity";

export function assertProfileOwnedByUser(
	profileUserId: string,
	requestUserId: string,
): void {
	if (profileUserId !== requestUserId) {
		throw new Error("Profile is not owned by the authenticated user");
	}
}

export function assertAppendAuthorized(
	state: ChainState,
	signerFingerprint: string,
): void {
	if (!state.activeFingerprints.has(signerFingerprint)) {
		throw new Error("Signer is not an active key for this identity");
	}
}

export function classifyProfileUpdate(
	state: ChainState,
	currentFingerprint: string,
	signerFingerprint: string,
): "same-key" | "rotated-key" {
	if (currentFingerprint === signerFingerprint) {
		assertProfileMatchesChainState(state, currentFingerprint);
		return "same-key";
	}

	if (!state.activeFingerprints.has(signerFingerprint)) {
		throw new Error("Signer is not an active key for this identity");
	}

	if (state.currentProfileFingerprint !== signerFingerprint) {
		throw new Error(
			"New profile fingerprint is not the sigchain's current profile",
		);
	}

	assertProfileMatchesChainState(state, signerFingerprint);

	return "rotated-key";
}

export function assertProfileMatchesChainState(
	state: ChainState,
	profileFingerprint: string,
): void {
	if (
		state.currentProfileFingerprint !== null &&
		state.currentProfileFingerprint !== profileFingerprint
	) {
		throw new Error(
			"Profile fingerprint does not match the sigchain's current profile",
		);
	}

	if (!state.activeFingerprints.has(profileFingerprint)) {
		throw new Error("Profile fingerprint is not authorized by the sigchain");
	}
}

export function assertAppendPreservesProfileState(
	previousState: ChainState,
	nextState: ChainState,
	storedProfileFingerprint: string,
	linkType: string,
): void {
	assertProfileMatchesChainState(previousState, storedProfileFingerprint);

	if (nextState.currentProfileFingerprint === storedProfileFingerprint) {
		assertProfileMatchesChainState(nextState, storedProfileFingerprint);
		return;
	}

	if (
		linkType !== "profile_update" ||
		nextState.currentProfileFingerprint === null
	) {
		throw new Error("Sigchain transition would detach the stored profile");
	}

	if (!nextState.activeFingerprints.has(nextState.currentProfileFingerprint)) {
		throw new Error("Sigchain profile update targets an inactive key");
	}
}
