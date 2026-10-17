export class InvalidPostgresTextArrayError extends Error {
  constructor() {
    super("invalid_postgres_text_array");
    this.name = "InvalidPostgresTextArrayError";
  }
}

export function encodePostgresTextArrayLiteral(value: unknown): string {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new InvalidPostgresTextArrayError();
  }
  const elements = value.map((item) => `"${item.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`);
  return `{${elements.join(",")}}`;
}
