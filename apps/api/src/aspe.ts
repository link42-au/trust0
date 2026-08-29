import {
	computeFingerprint,
	parseAspeUri,
	parseProfile,
	parseRequest,
} from "@trust0/identity";
import { and, eq, gt, sql } from "drizzle-orm";
import { Hono } from "hono";
import { cors } from "hono/cors";
import {
	compactVerify,
	decodeProtectedHeader,
	importJWK,
	type JWK,
} from "jose";
import { executeAtomicBatch } from "./atomic";
import * as schema from "./db/schema";
import { type ApiDb, loadVerifiedChainState } from "./identity-state";
import {
	type AuthEnv,
	requireAuth,
	sessionMiddleware,
} from "./middleware/session";
import { classifyProfileUpdate } from "./policy";

const aspe = new Hono<AuthEnv>();

const aspeUriFor = (domain: string | undefined, fingerprint: string): string =>
	`aspe:${domain || "trust0.app"}:${fingerprint}`;

export const parseBoundAspeUriFingerprint = (
	aspeUri: string,
	configuredDomain: string | undefined,
): string | null => {
	const parsed = parseAspeUri(aspeUri);
	if (!parsed) return null;

	const expectedDomain = (configuredDomain || "trust0.app")
		.trim()
		.toLowerCase();
	if (parsed.authority.toLowerCase() !== expectedDomain) return null;

	return parsed.fingerprint;
};

export const emailChallengePublicResponse = (
	email: string,
	expiresAt: Date,
) => ({
	email,
	expiresAt: expiresAt.toISOString(),
});

type EmailChallengeConsumption = {
	verificationId: string;
	signedChallenge: string;
	fingerprint: string;
	email: string;
	now: Date;
};

type ProfileRotationPersistence = {
	oldFingerprint: string;
	newFingerprint: string;
	profileJws: string;
	userId: string;
	identityId: string;
	chainHeadId: string;
	chainHeadSeqno: number;
	chainHeadJws: string;
	createdAt: Date;
	updatedAt: Date;
};

type ProfileCreatePersistence = {
	fingerprint: string;
	profileJws: string;
	userId: string;
	createdAt: Date;
	updatedAt: Date;
};

export async function persistGuardedProfileCreate(
	db: ApiDb,
	input: ProfileCreatePersistence,
): Promise<boolean> {
	const result = await db.insert(schema.cryptoProfile).select(sql`
		select
			${sql.param(input.fingerprint, schema.cryptoProfile.fingerprint)},
			${sql.param(input.profileJws, schema.cryptoProfile.profileJws)},
			${sql.param(input.userId, schema.cryptoProfile.userId)},
			null,
			${sql.param(input.createdAt, schema.cryptoProfile.createdAt)},
			${sql.param(input.updatedAt, schema.cryptoProfile.updatedAt)}
		where not exists (
			select 1 from ${schema.cryptoProfile}
			where ${schema.cryptoProfile.userId} = ${sql.param(input.userId, schema.cryptoProfile.userId)}
		)
		and not exists (
			select 1 from ${schema.cryptoProfile}
			where ${schema.cryptoProfile.fingerprint} = ${sql.param(input.fingerprint, schema.cryptoProfile.fingerprint)}
		)
	`);

	return result.meta.changes === 1;
}

export async function persistGuardedProfileRotation(
	db: ApiDb,
	input: ProfileRotationPersistence,
): Promise<boolean> {
	const oldProfileStillOwned = and(
		eq(schema.cryptoProfile.fingerprint, input.oldFingerprint),
		eq(schema.cryptoProfile.userId, input.userId),
		eq(schema.cryptoProfile.identityId, input.identityId),
	);
	const verifiedChainHeadIsCurrent = sql`exists (
		select 1 from ${schema.sigchainLink}
		where ${schema.sigchainLink.identityId} = ${sql.param(input.identityId, schema.sigchainLink.identityId)}
			and ${schema.sigchainLink.id} = ${sql.param(input.chainHeadId, schema.sigchainLink.id)}
			and ${schema.sigchainLink.seqno} = ${sql.param(input.chainHeadSeqno, schema.sigchainLink.seqno)}
			and ${schema.sigchainLink.linkJws} = ${sql.param(input.chainHeadJws, schema.sigchainLink.linkJws)}
			and not exists (
				select 1 from ${schema.sigchainLink} as later_chain_link
				where later_chain_link.identity_id = ${sql.param(input.identityId, schema.sigchainLink.identityId)}
					and (
						later_chain_link.seqno > ${sql.param(input.chainHeadSeqno, schema.sigchainLink.seqno)}
						or (
							later_chain_link.seqno = ${sql.param(input.chainHeadSeqno, schema.sigchainLink.seqno)}
							and later_chain_link.id <> ${sql.param(input.chainHeadId, schema.sigchainLink.id)}
						)
					)
			)
	)`;
	const oldProfileGuard = sql`exists (
		select 1 from ${schema.cryptoProfile}
		where ${schema.cryptoProfile.fingerprint} = ${sql.param(input.oldFingerprint, schema.cryptoProfile.fingerprint)}
			and ${schema.cryptoProfile.userId} = ${sql.param(input.userId, schema.cryptoProfile.userId)}
			and ${schema.cryptoProfile.identityId} = ${sql.param(input.identityId, schema.cryptoProfile.identityId)}
	)`;
	const newProfileIsThisRotation = sql`exists (
		select 1 from ${schema.cryptoProfile}
		where ${schema.cryptoProfile.fingerprint} = ${sql.param(input.newFingerprint, schema.cryptoProfile.fingerprint)}
			and ${schema.cryptoProfile.userId} = ${sql.param(input.userId, schema.cryptoProfile.userId)}
			and ${schema.cryptoProfile.identityId} = ${sql.param(input.identityId, schema.cryptoProfile.identityId)}
			and ${schema.cryptoProfile.profileJws} = ${sql.param(input.profileJws, schema.cryptoProfile.profileJws)}
	)`;
	const guardedDependency = and(
		oldProfileGuard,
		newProfileIsThisRotation,
		verifiedChainHeadIsCurrent,
	);

	const [insertResult, , , deleteResult] = await db.batch([
		db.insert(schema.cryptoProfile).select(sql`
			select
				${sql.param(input.newFingerprint, schema.cryptoProfile.fingerprint)},
				${sql.param(input.profileJws, schema.cryptoProfile.profileJws)},
				${sql.param(input.userId, schema.cryptoProfile.userId)},
				${sql.param(input.identityId, schema.cryptoProfile.identityId)},
				${sql.param(input.createdAt, schema.cryptoProfile.createdAt)},
				${sql.param(input.updatedAt, schema.cryptoProfile.updatedAt)}
			from ${schema.cryptoProfile}
			where ${oldProfileStillOwned}
				and ${verifiedChainHeadIsCurrent}
				and not exists (
					select 1 from ${schema.cryptoProfile}
					where ${schema.cryptoProfile.fingerprint} = ${sql.param(input.newFingerprint, schema.cryptoProfile.fingerprint)}
				)
		`),
		db
			.update(schema.username)
			.set({ fingerprint: input.newFingerprint })
			.where(
				and(
					eq(schema.username.fingerprint, input.oldFingerprint),
					guardedDependency,
				),
			),
		db
			.update(schema.attestation)
			.set({ fingerprint: input.newFingerprint })
			.where(
				and(
					eq(schema.attestation.fingerprint, input.oldFingerprint),
					guardedDependency,
				),
			),
		db
			.delete(schema.cryptoProfile)
			.where(
				and(
					oldProfileStillOwned,
					newProfileIsThisRotation,
					verifiedChainHeadIsCurrent,
				),
			),
	]);

	return insertResult.meta.changes === 1 && deleteResult.meta.changes === 1;
}

export async function consumeEmailChallenge(
	db: ApiDb,
	input: EmailChallengeConsumption,
): Promise<boolean> {
	const attestationId = `email_${input.fingerprint}`;
	const expiresAt = new Date(input.now.getTime() + 365 * 24 * 60 * 60 * 1000);
	const challengeIsConsumable = and(
		eq(schema.verification.id, input.verificationId),
		eq(schema.verification.value, input.signedChallenge),
		gt(schema.verification.expiresAt, input.now),
	);

	const [attestationResult, consumptionResult] = await db.batch([
		db
			.insert(schema.attestation)
			.select(sql`
				select
					${sql.param(attestationId, schema.attestation.id)},
					${sql.param(input.fingerprint, schema.attestation.fingerprint)},
					${sql.param("email", schema.attestation.type)},
					null,
					null,
					null,
					${sql.param(input.email, schema.attestation.value)},
					${sql.param("trust0.app", schema.attestation.attestedBy)},
					${sql.param(input.now, schema.attestation.attestedAt)},
					${sql.param(expiresAt, schema.attestation.expiresAt)}
				from ${schema.verification}
				where ${challengeIsConsumable}
			`)
			.onConflictDoUpdate({
				target: schema.attestation.id,
				set: {
					value: input.email,
					attestedAt: input.now,
					expiresAt,
				},
			}),
		db.delete(schema.verification).where(challengeIsConsumable),
	]);

	return (
		attestationResult.meta.changes === 1 && consumptionResult.meta.changes === 1
	);
}

// SPEC EXTENSION (APC-005): Ariadne spec does not mention CORS.
// Browser-based ASPE clients need CORS headers for cross-origin fetch.
// See: dev/spec/proposed-changes.md#apc-005
aspe.use("/.well-known/*", async (c, next) => {
	const origins = c.env.ALLOWED_ORIGINS
		? c.env.ALLOWED_ORIGINS.split(",").map((o: string) => o.trim())
		: [];

	return cors({
		origin: origins,
		allowHeaders: ["Content-Type"],
		allowMethods: ["POST", "GET", "OPTIONS"],
		credentials: true,
		maxAge: 600,
	})(c, next);
});

aspe.get("/.well-known/aspe/version", (c) => {
	return c.json({ version: 0 });
});

aspe.get("/.well-known/aspe/id/:fingerprint", async (c) => {
	const fingerprint = c.req.param("fingerprint");
	const db = c.get("db");

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Profile not found" }, 404);
	}

	// SPEC DEVIATION (APC-004): Spec says "application/asp+jwt; charset=UTF-8"
	// We use "application/asp+jwt" without charset (JWS is ASCII-only).
	// See: dev/spec/proposed-changes.md#apc-004
	return c.text(profile.profileJws, 200, {
		"Content-Type": "application/asp+jwt",
	});
});

aspe.use("/.well-known/aspe/post/*", sessionMiddleware);
aspe.use("/api/identity/*", sessionMiddleware);

aspe.post("/.well-known/aspe/post/", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");
	const body = await c.req.text();

	if (!body) {
		return c.json({ error: "Request body required" }, 400);
	}

	let request: Awaited<ReturnType<typeof parseRequest>>;
	try {
		request = await parseRequest(body);
	} catch (err) {
		return c.json({ error: `Invalid request: ${(err as Error).message}` }, 400);
	}

	const { action, fingerprint, profileJws, aspeUri } = request;
	const now = new Date();

	if (action === "create") {
		if (!profileJws) {
			return c.json({ error: "profile_jws required for create" }, 400);
		}

		try {
			const profile = await parseProfile(profileJws);
			if (profile.fingerprint !== fingerprint) {
				return c.json({ error: "Profile fingerprint mismatch" }, 400);
			}
		} catch (err) {
			return c.json(
				{ error: `Invalid profile: ${(err as Error).message}` },
				400,
			);
		}

		// Enforce one profile per user
		const [userProfile] = await db
			.select()
			.from(schema.cryptoProfile)
			.where(eq(schema.cryptoProfile.userId, user.id))
			.limit(1);

		if (userProfile) {
			return c.json(
				{ error: "User already has a profile. Use update action." },
				409,
			);
		}

		const [existing] = await db
			.select()
			.from(schema.cryptoProfile)
			.where(eq(schema.cryptoProfile.fingerprint, fingerprint))
			.limit(1);

		if (existing) {
			return c.json(
				{ error: "Profile already exists. Use update action." },
				409,
			);
		}

		const created = await persistGuardedProfileCreate(db, {
			fingerprint,
			profileJws,
			userId: user.id,
			createdAt: now,
			updatedAt: now,
		});
		if (!created) {
			return c.json(
				{ error: "User or fingerprint already has a profile." },
				409,
			);
		}

		return c.json(
			{ fingerprint, uri: aspeUriFor(c.env.ASPE_DOMAIN, fingerprint) },
			201,
		);
	}

	if (action === "update") {
		if (!profileJws) {
			return c.json({ error: "profile_jws required for update" }, 400);
		}
		if (!aspeUri) {
			return c.json({ error: "aspe_uri required for update" }, 400);
		}

		try {
			const profile = await parseProfile(profileJws);
			if (profile.fingerprint !== fingerprint) {
				return c.json({ error: "Profile fingerprint mismatch" }, 400);
			}
		} catch (err) {
			return c.json(
				{ error: `Invalid profile: ${(err as Error).message}` },
				400,
			);
		}

		const targetFingerprint = parseBoundAspeUriFingerprint(
			aspeUri,
			c.env.ASPE_DOMAIN,
		);
		if (!targetFingerprint) {
			return c.json(
				{
					error: "Invalid aspe_uri or ASPE domain does not match this instance",
				},
				400,
			);
		}

		const [existing] = await db
			.select()
			.from(schema.cryptoProfile)
			.where(eq(schema.cryptoProfile.fingerprint, targetFingerprint))
			.limit(1);

		if (!existing) {
			return c.json({ error: "Profile not found" }, 404);
		}

		if (existing.userId !== user.id) {
			return c.json({ error: "Not authorized to update this profile" }, 403);
		}

		let verifiedChain: Awaited<
			ReturnType<typeof loadVerifiedChainState>
		> | null = null;
		if (existing.identityId) {
			try {
				verifiedChain = await loadVerifiedChainState(db, existing.identityId);
			} catch (err) {
				return c.json(
					{ error: `Cannot verify stored sigchain: ${(err as Error).message}` },
					409,
				);
			}
		}

		if (existing.fingerprint === fingerprint) {
			if (verifiedChain) {
				try {
					classifyProfileUpdate(
						verifiedChain.state,
						existing.fingerprint,
						fingerprint,
					);
				} catch (err) {
					return c.json({ error: (err as Error).message }, 409);
				}
			}

			await db
				.update(schema.cryptoProfile)
				.set({ profileJws, updatedAt: now })
				.where(eq(schema.cryptoProfile.fingerprint, existing.fingerprint));
		} else {
			if (!existing.identityId) {
				return c.json(
					{
						error:
							"Cannot rotate profile keys before the sigchain is initialized",
					},
					400,
				);
			}
			if (!verifiedChain) {
				return c.json({ error: "Cannot verify stored sigchain" }, 409);
			}

			try {
				classifyProfileUpdate(
					verifiedChain.state,
					existing.fingerprint,
					fingerprint,
				);
			} catch (err) {
				return c.json({ error: (err as Error).message }, 403);
			}

			const [conflictingProfile] = await db
				.select()
				.from(schema.cryptoProfile)
				.where(eq(schema.cryptoProfile.fingerprint, fingerprint))
				.limit(1);

			if (conflictingProfile) {
				return c.json(
					{ error: "A profile already exists for the new fingerprint" },
					409,
				);
			}
			const chainHead = verifiedChain.links[verifiedChain.links.length - 1];
			if (!chainHead) {
				return c.json({ error: "Cannot verify stored sigchain" }, 409);
			}

			const rotated = await persistGuardedProfileRotation(db, {
				oldFingerprint: existing.fingerprint,
				newFingerprint: fingerprint,
				profileJws,
				userId: user.id,
				identityId: existing.identityId,
				chainHeadId: chainHead.id,
				chainHeadSeqno: chainHead.seqno,
				chainHeadJws: chainHead.linkJws,
				createdAt: existing.createdAt,
				updatedAt: now,
			});
			if (!rotated) {
				return c.json(
					{ error: "Profile changed concurrently. Refetch it and retry." },
					409,
				);
			}
		}

		return c.json({
			fingerprint,
			uri: aspeUriFor(c.env.ASPE_DOMAIN, fingerprint),
		});
	}

	if (action === "delete") {
		if (!aspeUri) {
			return c.json({ error: "aspe_uri required for delete" }, 400);
		}

		const targetFingerprint = parseBoundAspeUriFingerprint(
			aspeUri,
			c.env.ASPE_DOMAIN,
		);
		if (!targetFingerprint || targetFingerprint !== fingerprint) {
			return c.json(
				{ error: "Invalid aspe_uri, ASPE domain, or target fingerprint" },
				400,
			);
		}

		const [existing] = await db
			.select()
			.from(schema.cryptoProfile)
			.where(eq(schema.cryptoProfile.fingerprint, targetFingerprint))
			.limit(1);

		if (!existing) {
			return c.json({ error: "Profile not found" }, 404);
		}

		if (existing.userId !== user.id) {
			return c.json({ error: "Not authorized to delete this profile" }, 403);
		}

		// D1 batch is transactional: either the complete cascade commits or none does.
		if (existing.identityId) {
			await executeAtomicBatch(db, [
				db
					.delete(schema.sigchainLink)
					.where(eq(schema.sigchainLink.identityId, existing.identityId)),
				db
					.delete(schema.attestation)
					.where(eq(schema.attestation.fingerprint, fingerprint)),
				db
					.delete(schema.username)
					.where(eq(schema.username.fingerprint, fingerprint)),
				db
					.delete(schema.cryptoProfile)
					.where(eq(schema.cryptoProfile.fingerprint, fingerprint)),
			]);
		} else {
			await executeAtomicBatch(db, [
				db
					.delete(schema.attestation)
					.where(eq(schema.attestation.fingerprint, fingerprint)),
				db
					.delete(schema.username)
					.where(eq(schema.username.fingerprint, fingerprint)),
				db
					.delete(schema.cryptoProfile)
					.where(eq(schema.cryptoProfile.fingerprint, fingerprint)),
			]);
		}

		return c.json({ deleted: true });
	}

	return c.json({ error: "Unknown action" }, 400);
});

aspe.get("/api/identity/username/:username", async (c) => {
	const name = c.req.param("username").toLowerCase();
	const db = c.get("db");

	const [record] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.username, name))
		.limit(1);

	if (!record) {
		return c.json({ error: "Username not found" }, 404);
	}

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, record.fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Profile not found" }, 404);
	}

	return c.json({
		username: name,
		fingerprint: record.fingerprint,
		profileJws: profile.profileJws,
	});
});

const USERNAME_REGEX = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

aspe.post("/api/identity/username/claim", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");
	const body = await c.req.json<{ username: string; fingerprint: string }>();

	const name = body.username?.toLowerCase();
	if (!name || !USERNAME_REGEX.test(name)) {
		return c.json(
			{
				error:
					"Username must be 3-32 lowercase alphanumeric characters or hyphens",
			},
			400,
		);
	}

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, body.fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Profile not found" }, 404);
	}

	if (profile.userId !== user.id) {
		return c.json({ error: "Not authorized for this profile" }, 403);
	}

	const [existing] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.username, name))
		.limit(1);

	if (existing) {
		return c.json({ error: "Username already taken" }, 409);
	}

	await db.insert(schema.username).values({
		username: name,
		fingerprint: body.fingerprint,
		claimedAt: new Date(),
	});

	return c.json({ username: name, fingerprint: body.fingerprint }, 201);
});

aspe.post("/api/identity/username/release", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");
	const body = await c.req.json<{ fingerprint: string }>();

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, body.fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Profile not found" }, 404);
	}

	if (profile.userId !== user.id) {
		return c.json({ error: "Not authorized for this profile" }, 403);
	}

	const [existing] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.fingerprint, body.fingerprint))
		.limit(1);

	if (!existing) {
		return c.json({ error: "No username to release" }, 404);
	}

	await db
		.delete(schema.username)
		.where(eq(schema.username.fingerprint, body.fingerprint));

	return c.json({ released: existing.username });
});

aspe.get("/api/identity/my-profile", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	const db = c.get("db");

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.userId, user.id))
		.limit(1);

	if (!profile) {
		return c.json({ error: "No profile found" }, 404);
	}

	const [un] = await db
		.select()
		.from(schema.username)
		.where(eq(schema.username.fingerprint, profile.fingerprint))
		.limit(1);

	return c.json({
		fingerprint: profile.fingerprint,
		profileJws: profile.profileJws,
		username: un?.username ?? null,
		createdAt: profile.createdAt,
		updatedAt: profile.updatedAt,
	});
});

// ── Email Attestation ────────────────────────────────────────────────────────
// SPEC EXTENSION (APC-008): Ariadne spec has no email verification mechanism.
// We implement challenge-response: server emails a challenge, client signs it.
// See: dev/spec/proposed-changes.md#apc-008

// Step 1: Generate challenge and send to user's verified email
aspe.post("/api/identity/email/challenge", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	if (!user.email || !user.emailVerified) {
		return c.json({ error: "No verified email on account" }, 400);
	}
	if (!c.env.RESEND_API_KEY) {
		return c.json({ error: "Email service not configured" }, 500);
	}
	const db = c.get("db");

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.userId, user.id))
		.limit(1);

	if (!profile) {
		return c.json(
			{ error: "No crypto profile found. Create a profile first." },
			404,
		);
	}

	// Generate random challenge
	const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
	const challenge = Array.from(challengeBytes, (b) =>
		b.toString(16).padStart(2, "0"),
	).join("");

	const now = new Date();
	const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 minutes

	// Store challenge in verification table
	const verificationId = `identity-email:${profile.fingerprint}`;
	await db
		.insert(schema.verification)
		.values({
			id: verificationId,
			identifier: verificationId,
			value: challenge,
			expiresAt,
			createdAt: now,
			updatedAt: now,
		})
		.onConflictDoUpdate({
			target: schema.verification.id,
			set: { value: challenge, expiresAt, updatedAt: now },
		});

	// Send email via Resend
	const { Resend } = await import("resend");
	const resend = new Resend(c.env.RESEND_API_KEY);
	const from = c.env.EMAIL_FROM || "trust0 <noreply@trust0.app>";

	await resend.emails.send({
		from,
		to: [user.email],
		subject: "Identity Email Verification Challenge",
		html: `
			<p>You requested to link <strong>${user.email}</strong> to your cryptographic identity.</p>
			<p>Sign this challenge with your identity key to prove ownership:</p>
			<pre style="background: #f4f4f4; padding: 16px; border-radius: 8px; font-family: monospace; word-break: break-all;">${challenge}</pre>
			<p>This challenge expires in 15 minutes.</p>
			<p style="color: #888; font-size: 12px;">If you did not request this, ignore this email.</p>
		`,
	});

	return c.json(emailChallengePublicResponse(user.email, expiresAt));
});

// Step 2: Verify signed challenge and create attestation
aspe.post("/api/identity/email/verify", requireAuth, async (c) => {
	const user = c.get("user");
	if (!user) return c.json({ error: "Unauthorized" }, 401);
	if (typeof user.email !== "string" || !user.email) {
		return c.json({ error: "No email on account" }, 400);
	}
	const db = c.get("db");

	const body = await c.req.json<{ signedChallenge: string }>();
	if (!body.signedChallenge) {
		return c.json({ error: "signedChallenge required" }, 400);
	}

	// Parse the JWS to extract the challenge and signer's key
	let header: ReturnType<typeof decodeProtectedHeader>;
	try {
		header = decodeProtectedHeader(body.signedChallenge);
	} catch {
		return c.json({ error: "Invalid JWS format" }, 400);
	}

	if (
		!header.jwk ||
		typeof header.jwk !== "object" ||
		typeof header.kid !== "string"
	) {
		return c.json({ error: "JWS must include jwk and kid in header" }, 400);
	}

	// Verify the signature
	let payload: Uint8Array;
	try {
		const key = await importJWK(header.jwk as JWK, "EdDSA");
		const result = await compactVerify(body.signedChallenge, key);
		payload = result.payload;
	} catch {
		return c.json({ error: "Signature verification failed" }, 400);
	}

	// Verify fingerprint matches the kid
	const fingerprint = await computeFingerprint(header.jwk as JsonWebKey);
	if (fingerprint !== header.kid) {
		return c.json({ error: "Fingerprint mismatch" }, 400);
	}

	// Verify the signer owns a profile belonging to this user
	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, fingerprint))
		.limit(1);

	if (!profile || profile.userId !== user.id) {
		return c.json(
			{ error: "Profile not found or not owned by this user" },
			403,
		);
	}

	// Extract and verify the challenge
	const signedChallenge = new TextDecoder().decode(payload);
	const verificationId = `identity-email:${fingerprint}`;

	const [verification] = await db
		.select()
		.from(schema.verification)
		.where(eq(schema.verification.id, verificationId))
		.limit(1);

	if (!verification) {
		return c.json(
			{ error: "No pending challenge found. Request a new one." },
			400,
		);
	}

	if (verification.expiresAt < new Date()) {
		return c.json({ error: "Challenge expired. Request a new one." }, 400);
	}

	if (verification.value !== signedChallenge) {
		return c.json({ error: "Challenge does not match" }, 400);
	}

	// Challenge verified — atomically consume it and create the attestation.
	// The guarded INSERT prevents a concurrent verifier from attesting after the
	// first transaction has deleted the one-time challenge.
	const now = new Date();
	const consumed = await consumeEmailChallenge(db, {
		verificationId,
		signedChallenge,
		fingerprint,
		email: user.email,
		now,
	});
	if (!consumed) {
		return c.json(
			{
				error:
					"Challenge already consumed or no longer valid. Request a new one.",
			},
			409,
		);
	}

	return c.json({
		fingerprint,
		email: user.email,
		attestedAt: now.toISOString(),
	});
});

aspe.get("/api/identity/verify-email/:fingerprint", async (c) => {
	const fingerprint = c.req.param("fingerprint");
	const email = c.req.query("email");
	const db = c.get("db");

	if (!email) {
		return c.json({ error: "email query parameter required" }, 400);
	}

	const [att] = await db
		.select()
		.from(schema.attestation)
		.where(
			and(
				eq(schema.attestation.fingerprint, fingerprint),
				eq(schema.attestation.type, "email"),
			),
		)
		.limit(1);

	if (!att) {
		return c.json({ attested: false });
	}

	return c.json({
		attested: att.value === email,
		attestedAt: att.attestedAt,
	});
});

// ── General Attestation Endpoints ─────────────────────────────────────────────
// SPEC EXTENSION (APC-009): Ariadne spec only covers publicly-verifiable proofs.
// These endpoints handle server-attested proofs (Discord bots, Telegram bots, etc.)
// where a trusted intermediary witnesses the proof and signs an attestation.
// See: dev/spec/proposed-changes.md#apc-009

aspe.get("/api/identity/attestations/:fingerprint", async (c) => {
	const fingerprint = c.req.param("fingerprint");
	const db = c.get("db");

	const now = new Date();
	const attestations = await db
		.select()
		.from(schema.attestation)
		.where(eq(schema.attestation.fingerprint, fingerprint));

	// Filter out expired attestations
	const active = attestations.filter((a) => !a.expiresAt || a.expiresAt > now);

	return c.json({
		attestations: active.map((a) => ({
			id: a.id,
			type: a.type,
			platform: a.platform,
			platformUsername: a.platformUsername,
			value: a.value,
			attestedBy: a.attestedBy,
			attestedAt: a.attestedAt,
			expiresAt: a.expiresAt,
		})),
	});
});

aspe.post("/api/identity/attest-bot", async (c) => {
	const db = c.get("db");
	const body = await c.req.json<{
		fingerprint: string;
		platform: string;
		platformUserId: string;
		platformUsername: string;
		apiKey: string;
	}>();

	if (!body.apiKey || body.apiKey !== c.env.BOT_API_KEY) {
		return c.json({ error: "Invalid API key" }, 401);
	}

	if (
		!body.fingerprint ||
		!body.platform ||
		!body.platformUserId ||
		!body.platformUsername
	) {
		return c.json(
			{
				error:
					"Missing required fields: fingerprint, platform, platformUserId, platformUsername",
			},
			400,
		);
	}

	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(eq(schema.cryptoProfile.fingerprint, body.fingerprint))
		.limit(1);

	if (!profile) {
		return c.json({ error: "Crypto profile not found" }, 404);
	}

	const now = new Date();
	const id = `${body.platform}_${body.fingerprint}`;

	await db
		.insert(schema.attestation)
		.values({
			id,
			fingerprint: body.fingerprint,
			type: body.platform,
			platform: body.platform,
			platformUserId: body.platformUserId,
			platformUsername: body.platformUsername,
			value: body.platformUsername,
			attestedBy: "trust0.app",
			attestedAt: now,
		})
		.onConflictDoUpdate({
			target: schema.attestation.id,
			set: {
				platformUserId: body.platformUserId,
				platformUsername: body.platformUsername,
				value: body.platformUsername,
				attestedAt: now,
			},
		});

	return c.json(
		{
			id,
			fingerprint: body.fingerprint,
			platform: body.platform,
			platformUsername: body.platformUsername,
		},
		201,
	);
});

aspe.get(
	"/api/identity/attestation-status/:fingerprint/:platform",
	async (c) => {
		const fingerprint = c.req.param("fingerprint");
		const platform = c.req.param("platform");
		const db = c.get("db");

		const now = new Date();
		const [att] = await db
			.select()
			.from(schema.attestation)
			.where(
				and(
					eq(schema.attestation.fingerprint, fingerprint),
					eq(schema.attestation.type, platform),
				),
			)
			.limit(1);

		if (!att || (att.expiresAt && att.expiresAt <= now)) {
			return c.json({ attested: false });
		}

		return c.json({
			attested: true,
			platformUsername: att.platformUsername,
			attestedAt: att.attestedAt,
		});
	},
);

export { aspe as aspeRoutes };
