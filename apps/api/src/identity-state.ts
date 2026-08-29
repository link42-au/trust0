import { type ChainState, verifyChain } from "@trust0/identity";
import { and, asc, eq } from "drizzle-orm";
import type { DrizzleD1Database } from "drizzle-orm/d1";
import * as schema from "./db/schema";

export type ApiDb = DrizzleD1Database<typeof schema>;

export async function loadVerifiedChainState(
	db: ApiDb,
	identityId: string,
): Promise<{
	links: Array<typeof schema.sigchainLink.$inferSelect>;
	state: ChainState;
}> {
	const links = await db
		.select()
		.from(schema.sigchainLink)
		.where(eq(schema.sigchainLink.identityId, identityId))
		.orderBy(asc(schema.sigchainLink.seqno));

	if (links.length === 0) {
		throw new Error("Chain not found");
	}

	const state = await verifyChain(
		links.map((link) => link.linkJws),
		identityId,
	);

	return { links, state };
}

export async function findOwnedProfileByIdentityId(
	db: ApiDb,
	userId: string,
	identityId: string,
) {
	const [profile] = await db
		.select()
		.from(schema.cryptoProfile)
		.where(
			and(
				eq(schema.cryptoProfile.userId, userId),
				eq(schema.cryptoProfile.identityId, identityId),
			),
		)
		.limit(1);

	return profile ?? null;
}
