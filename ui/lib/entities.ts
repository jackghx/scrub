// Entity -> display metadata. Colours are applied as inline styles / CSS variables
// (not Tailwind classes) so the JIT compiler can never purge a dynamic colour, and
// so the palette lives in one obvious place.
//
// Colour is a *category* hint, not a per-type identity, so each risk family shares one
// hue (with small lightness variation) rather than every type getting its own colour:
//   network            -> cyan / teal
//   cloud + provider    -> violet / purple
//   source-control/pkg  -> amber
//   chat + webhooks     -> green
//   auth / generic      -> blue / indigo
//   crypto + connection -> red / rose (the "do not leak" tier)
//   PII                 -> orange
//   filesystem          -> slate
//
// Every entity the pack can emit is listed here, so the legend and chips always show a
// human label instead of falling back to the raw ENTITY_TOKEN.

export interface EntityMeta {
  /** Accent colour (used for chip text and the legend swatch). */
  color: string;
  /** Short, human label for the legend. */
  label: string;
}

export const ENTITY_META: Record<string, EntityMeta> = {
  // network (cyan / teal)
  INTERNAL_IP: { color: "#22d3ee", label: "Internal IP" },
  PUBLIC_IP: { color: "#38bdf8", label: "Public IP" },
  MAC_ADDRESS: { color: "#2dd4bf", label: "MAC address" },
  HOSTNAME: { color: "#5eead4", label: "Hostname" },

  // cloud + provider keys (violet / purple)
  AWS_ACCESS_KEY: { color: "#c084fc", label: "AWS access key" },
  AWS_SECRET_KEY: { color: "#a855f7", label: "AWS secret key" },
  AWS_ACCOUNT_ID: { color: "#d8b4fe", label: "AWS account ID" },
  GOOGLE_API_KEY: { color: "#a78bfa", label: "Google API key" },
  STRIPE_KEY: { color: "#8b5cf6", label: "Stripe key" },
  OPENAI_KEY: { color: "#c4b5fd", label: "OpenAI key" },
  OPENROUTER_KEY: { color: "#9d7bf0", label: "OpenRouter key" },
  SENDGRID_KEY: { color: "#b794f6", label: "SendGrid key" },
  FCM_SERVER_KEY: { color: "#cd9ff5", label: "FCM server key" },
  TWILIO_SID: { color: "#8e6fe0", label: "Twilio SID" },

  // source-control + package tokens (amber)
  GITHUB_TOKEN: { color: "#fbbf24", label: "GitHub token" },
  GITLAB_TOKEN: { color: "#f59e0b", label: "GitLab token" },
  NPM_TOKEN: { color: "#fcd34d", label: "npm token" },
  SHOPIFY_TOKEN: { color: "#fde68a", label: "Shopify token" },

  // chat tokens + webhooks (green)
  SLACK_TOKEN: { color: "#4ade80", label: "Slack token" },
  SLACK_WEBHOOK: { color: "#86efac", label: "Slack webhook" },
  DISCORD_TOKEN: { color: "#34d399", label: "Discord token" },
  DISCORD_WEBHOOK: { color: "#6ee7b7", label: "Discord webhook" },
  TELEGRAM_BOT_TOKEN: { color: "#22c55e", label: "Telegram bot token" },

  // auth / generic tokens (blue / indigo)
  JWT: { color: "#818cf8", label: "JWT" },
  BEARER_TOKEN: { color: "#60a5fa", label: "Bearer token" },
  GENERIC_API_KEY: { color: "#93c5fd", label: "Generic key/secret" },

  // crypto + connection strings (red / rose, highest-risk tier)
  PRIVATE_KEY_BLOCK: { color: "#fb7185", label: "Private key block" },
  SSH_PUBLIC_KEY: { color: "#f87171", label: "SSH public key" },
  DB_CONNECTION_STRING: { color: "#ef4444", label: "DB connection string" },
  URL_WITH_CREDENTIALS: { color: "#fca5a5", label: "URL with credentials" },

  // PII (orange)
  EMAIL_ADDRESS: { color: "#fb923c", label: "Email address" },
  CREDIT_CARD: { color: "#f97316", label: "Credit card" },

  // filesystem (slate)
  UNIX_HOME_PATH: { color: "#94a3b8", label: "Home path (username)" },
};

const FALLBACK: EntityMeta = { color: "#cbd5e1", label: "Unknown" };

export function entityMeta(entity: string): EntityMeta {
  return ENTITY_META[entity] ?? { ...FALLBACK, label: entity };
}

export function entityColor(entity: string): string {
  return entityMeta(entity).color;
}
