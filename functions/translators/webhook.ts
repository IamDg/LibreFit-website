import { Webhook, WebhookVerificationError } from "standardwebhooks";
import { getDb, translators } from "../_db.js";
import { signString } from '../_supporter-code-sign.js';
import type { Env } from "../types.js";

/**
 * Outbound webhook receiver for Hosted Weblate's Webhook add-on
 * (weblate.webhook.webhook). Weblate signs deliveries following the
 * Standard Webhooks specification:
 *   https://github.com/standard-webhooks/standard-webhooks
 *
 * Signed content: "{webhook-id}.{integer-seconds-timestamp}.{rawBody}"
 *   (Weblate signs the floored integer seconds from its header
 *   "webhook-timestamp: 1788990780.435625" — matching the official
 *   libraries; the raw float header string is NOT part of the signature.)
 * Signature:      "v1," + base64(HMAC-SHA256(base64-decoded secret, content))
 * Headers:        webhook-id, webhook-timestamp, webhook-signature
 *
 * Verification is delegated to the official `standardwebhooks` library,
 * which handles the tolerance window (±5 min), `whsec_` prefix stripping,
 * signature-rotation lists, and timing-safe comparison.
 */

/**
 * Change actions that represent a creditable translation contribution.
 * "Translation added" is the verbose name in current Weblate releases;
 * "New translation" was used by older versions — both accepted for
 * compatibility.
 */
const CREDITABLE_ACTIONS = new Set([
  "New translation",
  "Translation added",
  "Translation changed",
  "Translation approved",
  "Suggestion added",
  "Suggestion accepted",
  "Comment added",
]);

interface WeblateWebhookPayload {
  action?: string;
  author?: string;
  user?: string;
}

/**
 * Only human accounts are creditable: skip "anonymous" and Weblate service
 * accounts ("weblate:commit", "weblate:push", ...) and machine-translation
 * accounts ("mt:libretranslate", ...). Kept in sync with the backfill script
 * (scripts/backfill-translators.mjs).
 */
function isCreditableUsername(username: string | undefined): username is string {
  return Boolean(
    username &&
    username !== "anonymous" &&
    !username.startsWith("weblate:") &&
    !username.startsWith("mt:")
  );
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const { WEBLATE_WEBHOOK_SECRET, PRIVATE_KEY } = env;

  // Signature verification MUST run over the exact bytes received: read the
  // raw body once and reuse the string for both verification and parsing.
  const rawBody = await request.text();

  // The library expects a plain header record, not a Headers object.
  const webhook = new Webhook(WEBLATE_WEBHOOK_SECRET);
  try {
    webhook.verify(
      rawBody,
      {
        "webhook-id": request.headers.get("webhook-id") ?? "",
        "webhook-timestamp": request.headers.get("webhook-timestamp") ?? "",
        "webhook-signature": request.headers.get("webhook-signature") ?? "",
      },
      // Keep JSON parsing separate from verification so that a well-signed
      // but malformed payload is still acknowledged (see below).
      { jsonParse: false }
    );
  } catch (error) {
    if (error instanceof WebhookVerificationError) {
      // Visible in `wrangler pages deployment tail` for future debugging.
      console.warn(`Weblate webhook rejected: ${error.message}`);
      return new Response("Invalid Signature", { status: 401 });
    }
    // Anything else (e.g. misconfigured empty secret) is a server error:
    // let it bubble to the logging middleware.
    throw error;
  }

  let payload: WeblateWebhookPayload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    // Well-signed but malformed: acknowledge so Weblate doesn't retry forever.
    return new Response("OK");
  }

  // Only credit actions that represent an actual contribution; ack the rest.
  if (!payload.action || !CREDITABLE_ACTIONS.has(payload.action)) {
    return new Response("OK");
  }

  // `author` is the credited translator; `user` is who triggered the event.
  const username = payload.author ?? payload.user;
  if (!isCreditableUsername(username)) {
    return new Response("OK");
  }

  const signature = await signString(username, PRIVATE_KEY);
  const code = `${username}.${signature}`;

  const db = getDb(env);

  await db.insert(translators)
    .values({
      weblateUsername: username,
      code: code,
    })
    .onConflictDoUpdate({
      target: translators.weblateUsername,
      set: {
        code: code,
        lastContributionTimestamp: new Date(),
      },
    });

  return new Response("OK");
};