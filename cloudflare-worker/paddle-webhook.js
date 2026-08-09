// Paddle webhook receiver — Cloudflare Worker
// Verifies the Paddle-Signature header, then forwards a purchase/cancellation
// summary to the existing youtube-ai Telegram bot.
//
// Required environment variables (set as Cloudflare "Secrets" in the
// Worker's Settings > Variables, NOT hardcoded here):
//   PADDLE_WEBHOOK_SECRET  — the "endpoint_secret_key" Paddle gives you when
//                            you create the notification destination
//   TELEGRAM_BOT_TOKEN     — same token youtube-ai's backend already uses
//   TELEGRAM_CHAT_ID       — same chat id youtube-ai's backend already uses

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const rawBody = await request.text();
    const sigHeader = request.headers.get("Paddle-Signature") || "";
    const parts = Object.fromEntries(
      sigHeader.split(";").map((kv) => kv.split("="))
    );
    const ts = parts.ts;
    const h1 = parts.h1;

    if (!ts || !h1) {
      return new Response("Missing signature", { status: 400 });
    }

    const signedPayload = `${ts}:${rawBody}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.PADDLE_WEBHOOK_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuffer = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(signedPayload)
    );
    const computedHex = [...new Uint8Array(sigBuffer)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (computedHex !== h1) {
      return new Response("Invalid signature", { status: 401 });
    }

    const event = JSON.parse(rawBody);
    const eventType = event.event_type;
    let message = null;

    if (eventType === "transaction.completed") {
      const tx = event.data;
      const item = tx.items?.[0];
      const plan =
        item?.price?.custom_data?.plan ||
        item?.product?.custom_data?.plan ||
        "(bilinmiyor)";
      const email =
        tx.customer?.email || tx.billing_details?.email || null;
      const amount = tx.details?.totals?.total
        ? `${(Number(tx.details.totals.total) / 100).toFixed(2)} ${tx.currency_code}`
        : "(bilinmiyor)";
      message =
        `💰 Yeni satış!\n\n` +
        `Paket: ${plan}\n` +
        `Müşteri: ${email || "(e-posta yok, Paddle > Customers > " + tx.customer_id + " bak)"}\n` +
        `Tutar: ${amount}\n` +
        `Customer ID: ${tx.customer_id}\n\n` +
        `Lisans anahtarını oluşturup bu müşteriye gönder.`;
    } else if (eventType === "subscription.canceled") {
      const sub = event.data;
      message =
        `⚠️ Abonelik iptal edildi.\n` +
        `Customer ID: ${sub.customer_id}\n` +
        `Subscription: ${sub.id}`;
    } else if (eventType === "transaction.payment_failed") {
      message = `❌ Ödeme başarısız.\nTransaction: ${event.data.id}`;
    }

    if (message) {
      await fetch(
        `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: message }),
        }
      );
    }

    return new Response("OK", { status: 200 });
  },
};
