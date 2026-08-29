import {
	computeLinkHash,
	parseChainLink,
	parseProfile,
	verifyChain,
} from "@trust0/identity";
import { and, asc, eq, gt, sql } from "drizzle-orm";
import { Hono } from "hono";
import {
	compactVerify,
	decodeProtectedHeader,
	importJWK,
	type JWK,
} from "jose";
import { encode as base64urlEncode } from "jose/base64url";
import * as schema from "./db/schema";
import type { ApiDb } from "./identity-state";
import {
	type AuthEnv,
	requireAuth,
	sessionMiddleware,
} from "./middleware/session";
import { assertProfileMatchesChainState } from "./policy";

const exportApi = new Hono<AuthEnv>();

type ImportedChainLink = { seqno: number; type: string; linkJws: string };

type ImportBundle = {
	version: number;
	profile: { fingerprint: string; profileJws: string; identityId?: string };
	chain: ImportedChainLink[];
	attestations?: Array<{
		type: string;
		platform?: string;
		platformUsername?: string;
		value: string;
		attestedBy: string;
		attestedAt: string;
	}>;
};

export type ImportProofClaims = {
	version: 1;
	type: "trust0.identity.import";
	userId: string;
	sessionId: string;
	authority: string;
	bundleDigest: string;
	nonce: string;
	iat: number;
	exp: number;
};

type NormalizedChainLink = {
	id: string;
	fingerprint: string;
	seqno: number;
	type: string;
	linkJws: string;
	prevHash: string | null;
};

export const IMPORT_ATTESTATIONS_POLICY =
	"Imported attestations are untrusted and were ignored; re-attestation is required on this instance.";
export const IMPORT_PROOF_TYPE = "trust0-import-proof+jwt";
export const IMPORT_PROOF_TTL_SECONDS = 5 * 60;
// D1's free-plan Worker invocation limit is 50 queries. Import validation and
// conflict checks need their own queries, so keep the supported chain bounded
// below that ceiling and persist it with a few multi-row statements.
export const MAX_IMPORT_CHAIN_LINKS = 40;
// Each sigchain row binds eight values. Ten rows stay below D1's 100-bound-
// parameter limit while avoiding one statement per imported link.
export const IMPORT_CHAIN_INSERT_ROWS = 10;

const importChallengeId = (userId: string): string =>
	`identity-import:${JSON.stringify(userId)}`;

const importChallengeIdentifier = (userId: string, sessionId: string): string =>
	JSON.stringify({ purpose: "identity-import", userId, sessionId });

const importAuthority = (configuredAuthority: string | undefined): string =>
	(configuredAuthority || "trust0.app").trim().toLowerCase();

function normalizeImportBundle(bundle: ImportBundle) {
	return {
		version: bundle.version,
		profile: {
			fingerprint: bundle.profile.fingerprint,
			profileJws: bundle.profile.profileJws,
			identityId: bundle.profile.identityId ?? null,
		},
		chain: bundle.chain.map((link) => ({
			seqno: link.seqno,
			type: link.type,
			linkJws: link.linkJws,
		})),
	};
}

export async function computeImportBundleDigest(
	bundle: ImportBundle,
): Promise<string> {
	const encoded = new TextEncoder().encode(
		JSON.stringify(normalizeImportBundle(bundle)),
	);
	const digest = await crypto.subtle.digest("SHA-256", encoded);
	return `sha256:${base64urlEncode(new Uint8Array(digest))}`;
}

export function assertSupportedImportChainLength(chainLength: number): void {
	if (!Number.isInteger(chainLength) || chainLength < 0) {
		throw new Error("Invalid sigchain length");
	}
	if (chainLength > MAX_IMPORT_CHAIN_LINKS) {
		throw new Error(
			`Sigchain exceeds the ${MAX_IMPORT_CHAIN_LINKS}-link import limit`,
		);
	}
}

export function chunkImportChainRows<T>(rows: T[]): T[][] {
	const chunks: T[][] = [];
	for (let index = 0; index < rows.length; index += IMPORT_CHAIN_INSERT_ROWS) {
		chunks.push(rows.slice(index, index + IMPORT_CHAIN_INSERT_ROWS));
	}
	return chunks;
}

export function createImportProofClaims(
	userId: string,
	sessionId: string,
	configuredAuthority: string | undefined,
	bundleDigest: string,
	nonce: string,
	now = new Date(),
): ImportProofClaims {
	const iat = Math.floor(now.getTime() / 1000);
	return {
		version: 1,
		type: "trust0.identity.import",
		userId,
		sessionId,
		authority: importAuthority(configuredAuthority),
		bundleDigest,
		nonce,
		iat,
		exp: iat + IMPORT_PROOF_TTL_SECONDS,
	};
}

function parseStoredImportProof(value: string): ImportProofClaims {
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch {
		throw new Error("Import challenge is invalid");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("Import challenge is invalid");
	}
	return parsed as ImportProofClaims;
}

function equalImportProofClaims(
	actual: Record<string, unknown>,
	expected: ImportProofClaims,
): boolean {
	const expectedKeys = Object.keys(expected);
	return (
		Object.keys(actual).length === expectedKeys.length &&
		expectedKeys.every(
			(key) => actual[key] === expected[key as keyof ImportProofClaims],
		)
	);
}

export async function verifyImportProof(
	proofJws: string,
	publicJWK: JsonWebKey,
	expectedFingerprint: string,
	expectedClaims: ImportProofClaims,
	now = new Date(),
): Promise<void> {
	const header = decodeProtectedHeader(proofJws);
	if (
		header.typ !== IMPORT_PROOF_TYPE ||
		header.alg !== "EdDSA" ||
		header.kid !== expectedFingerprint
	) {
		throw new Error("Import proof header is invalid");
	}

	const key = await importJWK(publicJWK as JWK, "EdDSA");
	const { payload } = await compactVerify(proofJws, key);
	let actual: unknown;
	try {
		actual = JSON.parse(new TextDecoder().decode(payload));
	} catch {
		throw new Error("Import proof payload is invalid");
	}
	if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
		throw new Error("Import proof payload is invalid");
	}
	if (
		!equalImportProofClaims(actual as Record<string, unknown>, expectedClaims)
	) {
		throw new Error("Import proof is not bound to this challenge and bundle");
	}

	const nowSeconds = Math.floor(now.getTime() / 1000);
	if (
		!Number.isInteger(expectedClaims.iat) ||
		!Number.isInteger(expectedClaims.exp) ||
		expectedClaims.exp - expectedClaims.iat !== IMPORT_PROOF_TTL_SECONDS ||
		expectedClaims.iat > nowSeconds + 30 ||
		expectedClaims.exp <= nowSeconds
	) {
		throw new Error("Import proof has expired or has an invalid lifetime");
	}
}

const isDatabaseConflict = (error: unknown): boolean =>
	error instanceof Error &&
	/(?:unique|primary key|constraint failed)/i.test(error.message);

type GuardedImportPersistence = {
	challengeId: string;
	challengeIdentifier: string;
	challengeValue: string;
	profile: {
		fingerprint: string;
		profileJws: string;
		userId: string;
		identityId: string | null;
	};
	links: NormalizedChainLink[];
	now: Date;
};

export async function persistGuardedImport(
	db: ApiDb,
	input: GuardedImportPersistence,
): Promise<boolean> {
	const unclaimedChallenge = and(
		eq(schema.verification.id, input.challengeId),
		eq(schema.verification.identifier, input.challengeIdentifier),
		eq(schema.verification.value, input.challengeValue),
		gt(schema.verification.expiresAt, input.now),
	);
	const noProfileConflict = sql`not exists (
		select 1 from ${schema.cryptoProfile}
		where ${schema.cryptoProfile.userId} = ${sql.param(input.profile.userId, schema.cryptoProfile.userId)}
			or ${schema.cryptoProfile.fingerprint} = ${sql.param(input.profile.fingerprint, schema.cryptoProfile.fingerprint)}
	)`;
	const noIdentityConflict = input.profile.identityId
		? sql`not exists (
			select 1 from ${schema.sigchainLink}
			where ${schema.sigchainLink.identityId} = ${sql.param(input.profile.identityId, schema.sigchainLink.identityId)}
		)`
		: sql`1 = 1`;
	const claimedChallengeValue = `claimed:${input.challengeValue}`;
	const claimChallenge = db
		.update(schema.verification)
		.set({ value: claimedChallengeValue, updatedAt: input.now })
		.where(and(unclaimedChallenge, noProfileConflict, noIdentityConflict));
	const claimedChallenge = and(
		eq(schema.verification.id, input.challengeId),
		eq(schema.verification.identifier, input.challengeIdentifier),
		eq(schema.verification.value, claimedChallengeValue),
		gt(schema.verification.expiresAt, input.now),
	);
	const profileInsert = db.insert(schema.cryptoProfile).select(sql`
		select
			${sql.param(input.profile.fingerprint, schema.cryptoProfile.fingerprint)},
			${sql.param(input.profile.profileJws, schema.cryptoProfile.profileJws)},
			${sql.param(input.profile.userId, schema.cryptoProfile.userId)},
			${sql.param(input.profile.identityId, schema.cryptoProfile.identityId)},
			${sql.param(input.now, schema.cryptoProfile.createdAt)},
			${sql.param(input.now, schema.cryptoProfile.updatedAt)}
		from ${schema.verification}
		where ${claimedChallenge}
	`);
	const importedProfileExists = sql`exists (
		select 1 from ${schema.cryptoProfile}
		where ${schema.cryptoProfile.fingerprint} = ${sql.param(input.profile.fingerprint, schema.cryptoProfile.fingerprint)}
			and ${schema.cryptoProfile.userId} = ${sql.param(input.profile.userId, schema.cryptoProfile.userId)}
			and ${schema.cryptoProfile.profileJws} = ${sql.param(input.profile.profileJws, schema.cryptoProfile.profileJws)}
			and ${schema.cryptoProfile.identityId} = ${sql.param(input.profile.identityId, schema.cryptoProfile.identityId)}
	)`;

	const chainChunks = chunkImportChainRows(input.links);
	const chainInserts = chainChunks.map((links) => {
		const valueRows = links.map(
			(link) => sql`(
				${sql.param(link.id, schema.sigchainLink.id)},
				${sql.param(input.profile.identityId, schema.sigchainLink.identityId)},
				${sql.param(link.fingerprint, schema.sigchainLink.fingerprint)},
				${sql.param(link.seqno, schema.sigchainLink.seqno)},
				${sql.param(link.type, schema.sigchainLink.linkType)},
				${sql.param(link.linkJws, schema.sigchainLink.linkJws)},
				${sql.param(link.prevHash, schema.sigchainLink.prevHash)},
				${sql.param(input.now, schema.sigchainLink.createdAt)}
			)`,
		);
		return db.insert(schema.sigchainLink).select(sql`
			with import_rows (
				id, identity_id, fingerprint, seqno, link_type, link_jws, prev_hash, created_at
			) as (values ${sql.join(valueRows, sql.raw(", "))})
			select
				id, identity_id, fingerprint, seqno, link_type, link_jws, prev_hash, created_at
			from import_rows
			where exists (
				select 1 from ${schema.verification} where ${claimedChallenge}
			)
				and ${importedProfileExists}
		`);
	});
	const consumeChallenge = db
		.delete(schema.verification)
		.where(claimedChallenge);

	const results = await db.batch([
		claimChallenge,
		profileInsert,
		...chainInserts,
		consumeChallenge,
	] as Parameters<ApiDb["batch"]>[0]);
	const expectedChanges = [
		1,
		1,
		...chainChunks.map((links) => links.length),
		1,
	];
	return (
		results.length === expectedChanges.length &&
		results.every(
			(result, index) => result.meta.changes === expectedChanges[index],
		)
	);
}

export function getImportConflict(
	hasUserProfile: boolean,
	hasFingerprintProfile: boolean,
	hasIdentity: boolean,
): string | null {
	if (hasUserProfile) {
		return "User already has a profile. Delete it first to import.";
	}
	if (hasFingerprintProfile) {
		return "Profile fingerprint already exists on this instance.";
	}
	if (hasIdentity) {
		return "Identity already exists on this instance.";
	}
	return null;
}

export async function validateImportedChain(
	chain: ImportedChainLink[],
	profileFingerprint: string,
	claimedIdentityId?: string,
): Promise<{ identityId: string | null; links: NormalizedChainLink[] }> {
	assertSupportedImportChainLength(chain.length);
	if (chain.length === 0) {
		if (claimedIdentityId) {
			throw new Error(
				"Cannot import identity_id without a verifiable sigchain",
			);
		}
		return { identityId: null, links: [] };
	}

	const parsedLinks = await Promise.all(
		chain.map(async (link) => {
			const parsed = await parseChainLink(link.linkJws);
			if (parsed.seqno !== link.seqno || parsed.type !== link.type) {
				throw new Error("Chain link metadata does not match signed content");
			}
			return {
				parsed,
				linkHash: await computeLinkHash(link.linkJws),
				linkJws: link.linkJws,
			};
		}),
	);

	parsedLinks.sort((a, b) => a.parsed.seqno - b.parsed.seqno);
	for (let index = 1; index < parsedLinks.length; index++) {
		if (
			parsedLinks[index - 1].parsed.seqno === parsedLinks[index].parsed.seqno
		) {
			throw new Error(
				`Duplicate sigchain seqno ${parsedLinks[index].parsed.seqno}`,
			);
		}
	}

	const chainState = await verifyChain(parsedLinks.map((link) => link.linkJws));
	if (claimedIdentityId && claimedIdentityId !== chainState.identityId) {
		throw new Error("Imported identity ID does not match sigchain");
	}
	assertProfileMatchesChainState(chainState, profileFingerprint);

	return {
		identityId: chainState.identityId,
		links: parsedLinks.map(({ parsed, linkHash, linkJws }) => ({
			id: linkHash,
			fingerprint: parsed.fingerprint,
			seqno: parsed.seqno,
			type: parsed.type,
			linkJws,
			prevHash: parsed.prev,
		})),
	};
}

// ── Export: Download your complete identity ────────────────────────────────

exportApi.use("/api/identity/export", sessionMiddleware);

exportApi.get("/api/identity/export", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");

	// Find user's profile
	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.userId, user.id))
		.limit(1);

	if (!profile) {
		return c.json({ error: "No profile found" }, 404);
	}

	// Fetch chain links
	const links = profile.identityId
		? await db
				.select()
				.from(schema.sigchainLink)
				.where(eq(schema.sigchainLink.identityId, profile.identityId))
				.orderBy(asc(schema.sigchainLink.seqno))
		: [];

	// Fetch username
	const [username] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.fingerprint, profile.fingerprint))
		.limit(1);

	// Fetch attestations
	const attestations = await db
		.select()
		.from(schema.attestation)
		.where(eq(schema.attestation.fingerprint, profile.fingerprint));

	return c.json({
		version: 1,
		exportedAt: new Date().toISOString(),
		profile: {
			fingerprint: profile.fingerprint,
			profileJws: profile.profileJws,
			identityId: profile.identityId,
		},
		username: username?.username ?? null,
		chain: links.map((l) => ({
			seqno: l.seqno,
			type: l.linkType,
			linkJws: l.linkJws,
		})),
		attestations: attestations.map((a) => ({
			type: a.type,
			platform: a.platform,
			platformUsername: a.platformUsername,
			value: a.value,
			attestedBy: a.attestedBy,
			attestedAt: a.attestedAt,
		})),
	});
});

// ── Import: Register an exported identity on this instance ─────────────────

exportApi.use("/api/identity/import", sessionMiddleware);
exportApi.use("/api/identity/import/*", sessionMiddleware);

exportApi.post("/api/identity/import/challenge", requireAuth, async (c) => {
	const user = c.get("user");
	const session = c.get("session");
	if (!user || typeof user.id !== "string") {
		return c.json({ error: "Unauthorized" }, 401);
	}
	if (!session || typeof session.id !== "string") {
		return c.json(
			{ error: "Authenticated session has no stable identifier" },
			401,
		);
	}

	let body: { bundle: ImportBundle };
	try {
		body = await c.req.json<{ bundle: ImportBundle }>();
	} catch {
		return c.json({ error: "Invalid import challenge request" }, 400);
	}
	if (
		!body.bundle ||
		body.bundle.version !== 1 ||
		!Array.isArray(body.bundle.chain) ||
		!body.bundle.profile ||
		typeof body.bundle.profile.fingerprint !== "string" ||
		typeof body.bundle.profile.profileJws !== "string"
	) {
		return c.json({ error: "Unsupported or invalid import bundle" }, 400);
	}
	try {
		assertSupportedImportChainLength(body.bundle.chain.length);
	} catch (error) {
		return c.json({ error: (error as Error).message }, 400);
	}

	const now = new Date();
	const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
	const nonce = Array.from(nonceBytes, (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
	const bundleDigest = await computeImportBundleDigest(body.bundle);
	const challenge = createImportProofClaims(
		user.id,
		session.id,
		c.env.ASPE_DOMAIN,
		bundleDigest,
		nonce,
		now,
	);
	const expiresAt = new Date(challenge.exp * 1000);

	await c
		.get("db")
		.insert(schema.verification)
		.values({
			id: importChallengeId(user.id),
			identifier: importChallengeIdentifier(user.id, session.id),
			value: JSON.stringify(challenge),
			expiresAt,
			createdAt: now,
			updatedAt: now,
		})
		.onConflictDoUpdate({
			target: schema.verification.id,
			set: {
				identifier: importChallengeIdentifier(user.id, session.id),
				value: JSON.stringify(challenge),
				expiresAt,
				updatedAt: now,
			},
		});

	return c.json({ challenge, expiresAt: expiresAt.toISOString() }, 201);
});

exportApi.post("/api/identity/import", requireAuth, async (c) => {
	const user = c.get("user");
	const session = c.get("session");
	if (!user || typeof user.id !== "string") {
		return c.json({ error: "Unauthorized" }, 401);
	}
	if (!session || typeof session.id !== "string") {
		return c.json(
			{ error: "Authenticated session has no stable identifier" },
			401,
		);
	}
	const db = c.get("db");

	let body: ImportBundle & { proof: string };
	try {
		body = await c.req.json<ImportBundle & { proof: string }>();
	} catch {
		return c.json({ error: "Invalid import request" }, 400);
	}

	if (body.version !== 1) {
		return c.json({ error: "Unsupported export version" }, 400);
	}
	if (!Array.isArray(body.chain)) {
		return c.json({ error: "Invalid sigchain" }, 400);
	}
	try {
		assertSupportedImportChainLength(body.chain.length);
	} catch (error) {
		return c.json({ error: (error as Error).message }, 400);
	}

	if (
		!body.profile ||
		typeof body.profile.fingerprint !== "string" ||
		typeof body.profile.profileJws !== "string"
	) {
		return c.json({ error: "Invalid profile" }, 400);
	}

	let parsedProfile: Awaited<ReturnType<typeof parseProfile>>;
	try {
		parsedProfile = await parseProfile(body.profile.profileJws);
	} catch (err) {
		return c.json({ error: `Invalid profile: ${(err as Error).message}` }, 400);
	}

	if (parsedProfile.fingerprint !== body.profile.fingerprint) {
		return c.json({ error: "Profile fingerprint mismatch" }, 400);
	}
	if (typeof body.proof !== "string") {
		return c.json({ error: "Import proof is required" }, 400);
	}

	// Check user doesn't already have a profile
	const [existing] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.userId, user.id))
		.limit(1);

	const [existingFingerprint] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, parsedProfile.fingerprint))
		.limit(1);

	const initialConflict = getImportConflict(
		Boolean(existing),
		Boolean(existingFingerprint),
		false,
	);
	if (initialConflict) {
		return c.json({ error: initialConflict }, 409);
	}

	let verifiedIdentityId: string | null;
	let normalizedChain: NormalizedChainLink[];
	try {
		const validated = await validateImportedChain(
			body.chain,
			parsedProfile.fingerprint,
			body.profile.identityId,
		);
		verifiedIdentityId = validated.identityId;
		normalizedChain = validated.links;
	} catch (err) {
		return c.json(
			{ error: `Invalid sigchain: ${(err as Error).message}` },
			400,
		);
	}

	if (verifiedIdentityId) {
		const [existingIdentity] = await db
			.select()
			.from(schema.sigchainLink)
			.where(eq(schema.sigchainLink.identityId, verifiedIdentityId))
			.limit(1);

		const identityConflict = getImportConflict(
			false,
			false,
			Boolean(existingIdentity),
		);
		if (identityConflict) {
			return c.json({ error: identityConflict }, 409);
		}
	}

	let proofHeader: ReturnType<typeof decodeProtectedHeader>;
	try {
		proofHeader = decodeProtectedHeader(body.proof);
	} catch {
		return c.json({ error: "Import proof is invalid" }, 400);
	}
	if (typeof proofHeader.kid !== "string") {
		return c.json({ error: "Import proof is invalid" }, 400);
	}
	let proofPayload: Record<string, unknown>;
	try {
		const key = await importJWK(parsedProfile.publicJWK as JWK, "EdDSA");
		const verified = await compactVerify(body.proof, key);
		const decodedPayload: unknown = JSON.parse(
			new TextDecoder().decode(verified.payload),
		);
		if (
			!decodedPayload ||
			typeof decodedPayload !== "object" ||
			Array.isArray(decodedPayload)
		) {
			throw new Error("Invalid proof payload");
		}
		proofPayload = decodedPayload as Record<string, unknown>;
	} catch {
		return c.json({ error: "Import proof signature is invalid" }, 400);
	}
	const nonce = proofPayload.nonce;
	if (typeof nonce !== "string" || !/^[a-f0-9]{64}$/.test(nonce)) {
		return c.json({ error: "Import proof nonce is invalid" }, 400);
	}

	const challengeId = importChallengeId(user.id);
	const expectedIdentifier = importChallengeIdentifier(user.id, session.id);
	const [storedChallenge] = await db
		.select()
		.from(schema.verification)
		.where(eq(schema.verification.id, challengeId))
		.limit(1);
	if (!storedChallenge || storedChallenge.identifier !== expectedIdentifier) {
		return c.json(
			{ error: "Import challenge is missing or belongs to another session" },
			409,
		);
	}
	if (storedChallenge.expiresAt <= new Date()) {
		return c.json({ error: "Import challenge has expired" }, 409);
	}

	let expectedProof: ImportProofClaims;
	try {
		expectedProof = parseStoredImportProof(storedChallenge.value);
		if (expectedProof.nonce !== nonce) {
			return c.json(
				{ error: "Import challenge was already consumed or replaced" },
				409,
			);
		}
		const expectedDigest = await computeImportBundleDigest(body);
		if (
			expectedProof.userId !== user.id ||
			expectedProof.sessionId !== session.id ||
			expectedProof.authority !== importAuthority(c.env.ASPE_DOMAIN) ||
			expectedProof.bundleDigest !== expectedDigest ||
			expectedProof.exp * 1000 !== storedChallenge.expiresAt.getTime()
		) {
			throw new Error("Import proof is not bound to this session and bundle");
		}
		await verifyImportProof(
			body.proof,
			parsedProfile.publicJWK,
			parsedProfile.fingerprint,
			expectedProof,
		);
	} catch (error) {
		return c.json({ error: (error as Error).message }, 400);
	}

	const now = new Date();
	let imported = false;
	try {
		imported = await persistGuardedImport(db, {
			challengeId,
			challengeIdentifier: expectedIdentifier,
			challengeValue: storedChallenge.value,
			profile: {
				fingerprint: parsedProfile.fingerprint,
				profileJws: body.profile.profileJws,
				userId: user.id,
				identityId: verifiedIdentityId,
			},
			links: normalizedChain,
			now,
		});
	} catch (error) {
		if (isDatabaseConflict(error)) {
			return c.json(
				{ error: "Identity import conflicts with existing data" },
				409,
			);
		}
		throw error;
	}
	if (!imported) {
		return c.json(
			{ error: "Import challenge was already consumed or replaced" },
			409,
		);
	}

	const ignoredAttestations = body.attestations?.length ?? 0;

	return c.json(
		{
			imported: true,
			fingerprint: parsedProfile.fingerprint,
			identityId: verifiedIdentityId,
			ignoredAttestations,
			attestationsPolicy: IMPORT_ATTESTATIONS_POLICY,
		},
		201,
	);
});

export { exportApi as exportRoutes };
