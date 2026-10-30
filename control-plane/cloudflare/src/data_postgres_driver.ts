/**
 * Driver boundary for the current PostgreSQL deployment.
 *
 * This module is the only place in the Product data layer that knows the
 * node-postgres driver. Higher layers depend on a small connection protocol,
 * not on pg Client or Cloudflare Hyperdrive implementation details.
 *
 * Replacing the database still requires implementing equivalent authorized
 * operations and migrations; it must never silently change ownership or
 * authorization rules.
 */
import { Client } from "pg";

export interface DatabaseQueryResult<Row = Record<string, unknown>> {
  rows: Row[];
}

export interface DatabaseSession {
  connect(): Promise<void>;
  query<Row = Record<string, unknown>>(
    sql: string,
    values?: readonly unknown[],
  ): Promise<DatabaseQueryResult<Row>>;
  end(): Promise<void>;
}

export function openPostgresSession(connectionString: string): DatabaseSession {
  // Connection lifecycle is owned by the caller; no global singleton,
  // implicit fallback, direct SQL in routes or driver-specific return type.
  return new Client({ connectionString }) as DatabaseSession;
}
