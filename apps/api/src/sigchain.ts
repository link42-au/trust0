import {
	computeIdentityId,
	computeLinkHash,
	type ParsedChainLink,
	parseChainLink,
	verifyChain,
} from "@trust0/identity";
import { and, asc, eq, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import * as schema from "./db/schema";
import {
	findOwnedProfileByIdentityId,
	loadVerifiedChainState,
} from "./identity-state";
import { type AuthEnv, sessionMiddleware } from "./middleware/session";
import {
	assertAppendAuthorized,
	assertAppendPreservesProfileState,
	assertProfileOwnedByUser,
} from "./policy";

const sigchain = new Hono<AuthEnv>();

// ── Auth middleware for mutation routes ──────────────────────────────────────

sigchain.use("/api/identity/chain/init", sessionMiddleware);
sigchain.use("/api/identity/chain/append", sessionMiddleware);

// ── GET /api/identity/chain/:id — fetch chain by identity_id or fingerprint ─

sigchain.get("/api/identity/chain/:id", async (c) => {
	const id = c.req.param("id");
	const db = c.get("db");

	let identityId: string;
	let fingerprint: string | null = null;

	if (id.length === 52) {
		// identity_id (BASE32, 52 chars)
		identityId = id;
	} else if (id.length === 26) {
		// fingerprint (BASE32, 26 chars)
		const [profile] = await db
			.select()
			.from(schema.cryptoProfile)
			.where(eq(schema.cryptoProfile.fingerprint, id))
			.limit(1);

		if (!profile || !profile.identityId) {
			return c.json({ error: "Chain not found" }, 404);
		}

		identityId = profile.identityId;
		fingerprint = profile.fingerprint;
	} else {
		return c.json(
			{
				error: "Invalid id: must be 52-char identity_id or 26-char fingerprint",
			},
			400,
		);
	}

	const links = await db
		.select()
		.from(schema.sigchainLink)
		.where(eq(schema.sigchainLink.identityId, identityId))
		.orderBy(asc(schema.sigchainLink.seqno));

	if (links.length === 0) {
		return c.json({ error: "Chain not found" }, 404);
	}

	// If we didn't already resolve the fingerprint, grab it from the first link
	if (!fingerprint) {
		fingerprint = links[0].fingerprint;
	}

	return c.json({
		identityId,
		fingerprint,
		links: links.map((l) => ({
			seqno: l.seqno,
			type: l.linkType,
			linkJws: l.linkJws,
			prevHash: l.prevHash,
			createdAt: l.createdAt,
		})),
	});
});

// ── POST /api/identity/chain/init — initialize a new sigchain ───────────────

sigchain.post("/api/identity/chain/init", async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");

	const body = await c.req.json<{ genesisLinkJws: string }>();

	if (!body.genesisLinkJws) {
		return c.json({ error: "genesisLinkJws required" }, 400);
	}

	let parsed: ParsedChainLink;
	try {
		parsed = await parseChainLink(body.genesisLinkJws);
	} catch (err) {
		return c.json(
			{ error: `Invalid genesis link: ${(err as Error).message}` },
			400,
		);
	}

	// Validate genesis link structure
	if (parsed.seqno !== 0) {
		return c.json({ error: "Genesis link must have seqno 0" }, 400);
	}
	if (parsed.type !== "key_init") {
		return c.json({ error: "Genesis link must have type key_init" }, 400);
	}
	if (parsed.prev !== null) {
		return c.json({ error: "Genesis link must have null prev" }, 400);
	}

	// Validate fingerprint ownership
	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, parsed.fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Crypto profile not found for this key" }, 404);
	}

	try {
		assertProfileOwnedByUser(profile.userId, user.id);
	} catch {
		return c.json({ error: "Forbidden" }, 403);
	}

	// Check if already initialized
	if (profile.identityId) {
		return c.json({ error: "Chain already initialized for this profile" }, 409);
	}

	let identityId: string;
	let linkHash: string;
	try {
		identityId = await computeIdentityId(body.genesisLinkJws);
		linkHash = await computeLinkHash(body.genesisLinkJws);
	} catch (err) {
		return c.json(
			{ error: `Failed to compute identity: ${(err as Error).message}` },
			400,
		);
	}

	try {
		await verifyChain([body.genesisLinkJws], identityId);
	} catch (err) {
		return c.json(
			{ error: `Invalid genesis chain state: ${(err as Error).message}` },
			400,
		);
	}

	const now = new Date();

	const uninitializedOwnedProfile = and(
		eq(schema.cryptoProfile.fingerprint, parsed.fingerprint),
		eq(schema.cryptoProfile.userId, user.id),
		isNull(schema.cryptoProfile.identityId),
	);
	const [insertResult, updateResult] = await db.batch([
		db.insert(schema.sigchainLink).select(sql`
			select
				${sql.param(linkHash, schema.sigchainLink.id)},
				${sql.param(identityId, schema.sigchainLink.identityId)},
				${sql.param(parsed.fingerprint, schema.sigchainLink.fingerprint)},
				0,
				${sql.param("key_init", schema.sigchainLink.linkType)},
				${sql.param(body.genesisLinkJws, schema.sigchainLink.linkJws)},
				null,
				${sql.param(now, schema.sigchainLink.createdAt)}
			from ${schema.cryptoProfile}
			where ${uninitializedOwnedProfile}
		`),
		db
			.update(schema.cryptoProfile)
			.set({ identityId })
			.where(uninitializedOwnedProfile),
	]);

	if (insertResult.meta.changes !== 1 || updateResult.meta.changes !== 1) {
		return c.json({ error: "Chain already initialized for this profile" }, 409);
	}

	return c.json({ identityId }, 201);
});

// ── POST /api/identity/chain/append — append a link to an existing chain ────

sigchain.post("/api/identity/chain/append", async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");

	const body = await c.req.json<{ linkJws: string }>();

	if (!body.linkJws) {
		return c.json({ error: "linkJws required" }, 400);
	}

	let parsed: ParsedChainLink;
	try {
		parsed = await parseChainLink(body.linkJws);
	} catch (err) {
		return c.json(
			{ error: `Invalid chain link: ${(err as Error).message}` },
			400,
		);
	}

	if (parsed.seqno === 0) {
		return c.json(
			{ error: "Genesis links must be created via /api/identity/chain/init" },
			400,
		);
	}

	const [lastLink] = await db
		.select()
		.from(schema.sigchainLink)
		.where(eq(schema.sigchainLink.id, parsed.prev!))
		.limit(1);

	if (!lastLink) {
		return c.json(
			{ error: "prev hash does not match a known link in the chain" },
			400,
		);
	}

	const identityId = lastLink.identityId;

	const ownerProfile = await findOwnedProfileByIdentityId(
		db,
		user.id,
		identityId,
	);
	if (!ownerProfile) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const { links, state } = await loadVerifiedChainState(db, identityId);
	const currentLastLink = links[links.length - 1];

	// Validate seqno continuity
	if (parsed.seqno !== currentLastLink.seqno + 1) {
		return c.json(
			{
				error: `Expected seqno ${currentLastLink.seqno + 1}, got ${parsed.seqno}`,
			},
			400,
		);
	}

	// Validate prev hash
	let expectedPrevHash: string;
	try {
		expectedPrevHash = await computeLinkHash(currentLastLink.linkJws);
	} catch (err) {
		return c.json(
			{ error: `Failed to compute prev hash: ${(err as Error).message}` },
			400,
		);
	}

	if (parsed.prev !== expectedPrevHash) {
		return c.json(
			{ error: "prev hash does not match the last link in the chain" },
			400,
		);
	}

	try {
		assertAppendAuthorized(state, parsed.fingerprint);
	} catch (err) {
		return c.json({ error: (err as Error).message }, 403);
	}

	try {
		const nextState = await verifyChain(
			[...links.map((link) => link.linkJws), body.linkJws],
			identityId,
		);
		assertAppendPreservesProfileState(
			state,
			nextState,
			ownerProfile.fingerprint,
			parsed.type,
		);
	} catch (err) {
		return c.json(
			{ error: `Invalid sigchain transition: ${(err as Error).message}` },
			400,
		);
	}

	let linkHash: string;
	try {
		linkHash = await computeLinkHash(body.linkJws);
	} catch (err) {
		return c.json(
			{ error: `Failed to compute link hash: ${(err as Error).message}` },
			400,
		);
	}

	const now = new Date();

	try {
		await db.insert(schema.sigchainLink).values({
			id: linkHash,
			identityId,
			fingerprint: parsed.fingerprint,
			seqno: parsed.seqno,
			linkType: parsed.type,
			linkJws: body.linkJws,
			prevHash: parsed.prev,
			createdAt: now,
		});
	} catch (err) {
		// Unique constraint on (identity_id, seqno) — concurrent append race
		const message = (err as Error).message || "";
		if (message.includes("UNIQUE") || message.includes("unique")) {
			return c.json(
				{
					error:
						"Conflict: another link was appended concurrently. Refetch chain and retry.",
				},
				409,
			);
		}
		throw err;
	}

	return c.json({ seqno: parsed.seqno, identityId });
});

// ── GET /api/identity/id/:identityId — resolve identity to profile ──────────

sigchain.get("/api/identity/id/:identityId", async (c) => {
	const identityId = c.req.param("identityId");
	const db = c.get("db");

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.identityId, identityId))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Identity not found" }, 404);
	}

	const [un] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.fingerprint, profile.fingerprint))
		.limit(1);

	return c.json({
		identityId,
		fingerprint: profile.fingerprint,
		profileJws: profile.profileJws,
		username: un?.username ?? null,
		createdAt: profile.createdAt,
	});
});

export { sigchain as sigchainRoutes };
