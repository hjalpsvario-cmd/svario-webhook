// Simple Facebook Messenger webhook + Shopify OAuth for Svario
const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// --------------------
// Fetch compatibility
// Node 18+ has global fetch. If not, fallback to node-fetch.
// --------------------
let fetchFn = global.fetch;
if (!fetchFn) {
  fetchFn = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
}

// --------------------
// In-memory token store (MVP)
// shop -> accessToken
// NOTE: resets on deploy/restart. Replace with DB/Redis later.
// --------------------
const tokenStore = new Map();

// --------------------
// Facebook Webhook
// --------------------
const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || "svario-secret";

app.get("/facebook/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("✅ Webhook verified successfully!");
    return res.status(200).send(challenge);
  }
  console.log("❌ Webhook verification failed");
  return res.sendStatus(403);
});

app.post("/facebook/webhook", (req, res) => {
  console.log("📩 Incoming message:", JSON.stringify(req.body, null, 2));
  return res.sendStatus(200);
});

// --------------------
// Shopify OAuth
// --------------------

// Start install: /auth/shopify/install?shop=xxxx.myshopify.com
app.get("/auth/shopify/install", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();

  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const clientId = process.env.SHOPIFY_API_KEY;
  const appUrl = process.env.APP_URL;

  if (!clientId) return res.status(500).send("Missing SHOPIFY_API_KEY in env");
  if (!appUrl) return res.status(500).send("Missing APP_URL in env");

  // ✅ FULL CHATBOT SCOPES
  const scopes =
    "read_products,read_shop,read_inventory,read_orders,read_customers,read_fulfillments,write_webhooks";

  const redirectUri = `${appUrl}/auth/shopify/callback`;
  const state = crypto.randomBytes(16).toString("hex");

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

// OAuth callback
app.get("/auth/shopify/callback", async (req, res) => {
  const { shop, code, hmac } = req.query;

  if (!shop || !code || !hmac) return res.status(400).send("Missing shop/code/hmac");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const apiKey = process.env.SHOPIFY_API_KEY;
  const apiSecret = process.env.SHOPIFY_API_SECRET;

  if (!apiKey) return res.status(500).send("Missing SHOPIFY_API_KEY in env");
  if (!apiSecret) return res.status(500).send("Missing SHOPIFY_API_SECRET in env");

  // HMAC validation
  const query = { ...req.query };
  delete query.hmac;
  delete query.signature;

  const message = Object.keys(query)
    .sort()
    .map((key) => `${key}=${Array.isArray(query[key]) ? query[key].join(",") : query[key]}`)
    .join("&");

  const generated = crypto.createHmac("sha256", apiSecret).update(message).digest("hex");

  if (
    generated.length !== hmac.length ||
    !crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(hmac))
  ) {
    return res.status(401).send("HMAC validation failed");
  }

  console.log(`✅ HMAC OK for ${shop}. Exchanging code for token...`);

  // Exchange code → access token
  const tokenRes = await fetchFn(`https://${shop}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    }),
  });

  const tokenData = await tokenRes.json();

  if (!tokenRes.ok) {
    console.log("❌ Token exchange failed:", tokenData);
    return res.status(500).send("Token exchange failed");
  }

  const accessToken = tokenData.access_token;

  // Store token securely server-side
  tokenStore.set(shop, accessToken);

  console.log(`✅ Token stored for ${shop}`);

  return res
    .status(200)
    .send(`✅ Svario successfully connected to ${shop}`);
});

// --------------------
// Shopify API routes
// --------------------

// GET /shopify/products?shop=xxxx.myshopify.com
app.get("/shopify/products", async (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");

  const accessToken = tokenStore.get(shop);
  if (!accessToken) {
    return res.status(401).send("Shop not connected. Install app first.");
  }

  try {
    const r = await fetchFn(`https://${shop}/admin/api/2024-10/products.json?limit=5`, {
      headers: {
        "X-Shopify-Access-Token": accessToken,
        "Content-Type": "application/json",
      },
    });

    const data = await r.json();
    return res.status(r.status).json(data);
  } catch (err) {
    console.error(err);
    return res.status(500).send("Failed to fetch products");
  }
});

// Status check
app.get("/shopify/status", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  return res.json({ shop, connected: tokenStore.has(shop) });
});

// Health check
app.get("/", (req, res) => res.send("Svario Webhook is running ✅"));

// Start server
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 Webhook running on port ${port}`));
