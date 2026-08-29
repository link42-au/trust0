export type ParsedAspeUri = {
	authority: string;
	fingerprint: string;
};

const ASPE_PREFIX = "aspe:";
const ASPE_FINGERPRINT = /^[A-Z2-7]{26}$/i;
const INVALID_AUTHORITY_CHARACTER = /[\s/?#]/;

export function parseAspeUri(uri: string): ParsedAspeUri | null {
	if (!uri.startsWith(ASPE_PREFIX)) return null;

	const fingerprintSeparator = uri.lastIndexOf(":");
	if (fingerprintSeparator < ASPE_PREFIX.length) return null;

	const authority = uri.slice(ASPE_PREFIX.length, fingerprintSeparator);
	const fingerprint = uri.slice(fingerprintSeparator + 1);
	if (!authority || INVALID_AUTHORITY_CHARACTER.test(authority)) return null;
	if (!ASPE_FINGERPRINT.test(fingerprint)) return null;

	return {
		authority,
		fingerprint: fingerprint.toUpperCase(),
	};
}
