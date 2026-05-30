// Entity -> display metadata. Colours are applied as inline styles / CSS variables
// (not Tailwind classes) so the JIT compiler can never purge a dynamic colour, and
// so the palette lives in one obvious place.
//
// Hues are grouped by risk family so the screen reads at a glance:
//   network        -> cyans
//   cloud keys     -> purples / magentas
//   tokens         -> ambers / greens
//   crypto + DB    -> reds (the "do not leak" tier)
//   filesystem     -> muted slate

export interface EntityMeta {
  /** Accent colour (used for chip text/border and the legend swatch). */
  color: string;
  /** Short, human label for the legend. */
  label: string;
}

export const ENTITY_META: Record<string, EntityMeta> = {
  // network
  INTERNAL_IP: { color: "#22d3ee", label: "Internal IP" },
  PUBLIC_IP: { color: "#38bdf8", label: "Public IP" },
  MAC_ADDRESS: { color: "#2dd4bf", label: "MAC address" },
  HOSTNAME: { color: "#67e8f9", label: "Hostname" },

  // cloud keys
  AWS_ACCESS_KEY: { color: "#c084fc", label: "AWS access key" },
  AWS_SECRET_KEY: { color: "#a855f7", label: "AWS secret key" },
  AWS_ACCOUNT_ID: { color: "#d8b4fe", label: "AWS account ID" },
  GOOGLE_API_KEY: { color: "#e879f9", label: "Google API key" },
  STRIPE_KEY: { color: "#f0abfc", label: "Stripe key" },

  // tokens
  GITHUB_TOKEN: { color: "#fbbf24", label: "GitHub token" },
  SLACK_TOKEN: { color: "#fcd34d", label: "Slack token" },
  JWT: { color: "#a3e635", label: "JWT" },
  BEARER_TOKEN: { color: "#facc15", label: "Bearer token" },
  GENERIC_API_KEY: { color: "#bef264", label: "Generic key/secret" },
  OPENROUTER_KEY: { color: "#fde047", label: "OpenRouter key" },

  // crypto + DB (highest-risk tier)
  PRIVATE_KEY_BLOCK: { color: "#fb7185", label: "Private key block" },
  DB_CONNECTION_STRING: { color: "#f87171", label: "DB connection string" },

  // filesystem
  UNIX_HOME_PATH: { color: "#94a3b8", label: "Home path (username)" },
};

const FALLBACK: EntityMeta = { color: "#cbd5e1", label: "Unknown" };

export function entityMeta(entity: string): EntityMeta {
  return ENTITY_META[entity] ?? { ...FALLBACK, label: entity };
}

export function entityColor(entity: string): string {
  return entityMeta(entity).color;
}
