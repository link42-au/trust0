import { describe, expect, it } from "vitest";
import { parseAspeUri } from "../index.js";

const FINGERPRINT = "QPRGVPJNWDXH4ESK2RYDTZJLTE";

describe("parseAspeUri", () => {
	it("parses a canonical ASPE URI", () => {
		expect(parseAspeUri(`aspe:trust0.example:${FINGERPRINT}`)).toEqual({
			authority: "trust0.example",
			fingerprint: FINGERPRINT,
		});
	});

	it("parses the fingerprint after a self-hosted authority port", () => {
		expect(parseAspeUri(`aspe:localhost:8788:${FINGERPRINT}`)).toEqual({
			authority: "localhost:8788",
			fingerprint: FINGERPRINT,
		});
	});

	it("normalizes a lowercase fingerprint to uppercase", () => {
		expect(
			parseAspeUri(`aspe:identity.example:${FINGERPRINT.toLowerCase()}`),
		).toEqual({
			authority: "identity.example",
			fingerprint: FINGERPRINT,
		});
	});

	it.each([
		"aspe::QPRGVPJNWDXH4ESK2RYDTZJLTE",
		"aspe:identity example:QPRGVPJNWDXH4ESK2RYDTZJLTE",
		"aspe:identity.example",
		"aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLTE:extra",
		"aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLTE/path",
		"aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLT",
		"aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLTEA",
		"aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLT0",
		"ASPE:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLTE",
		"https://identity.example/QPRGVPJNWDXH4ESK2RYDTZJLTE",
	])("rejects an invalid ASPE URI: %s", (uri) => {
		expect(parseAspeUri(uri)).toBeNull();
	});
});
