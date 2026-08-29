import type { ApiDb } from "./identity-state";

export type AtomicBatch = Parameters<ApiDb["batch"]>[0];

/**
 * Execute related D1 writes as one transaction.
 *
 * Cloudflare D1 guarantees that `batch()` statements are committed in order
 * and rolls the complete batch back when any statement fails.
 */
export async function executeAtomicBatch(
	db: ApiDb,
	statements: AtomicBatch,
): Promise<void> {
	if (statements.length === 0) {
		throw new Error("Atomic batch must contain at least one statement");
	}

	await db.batch(statements);
}
