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
  const appUrl = process.env.APP_URL; // e.g. https://svario-webhook-1.onrender.com

  if (!clientId) return res.status(500).send("Missing SHOPIFY_API_KEY in env");
  if (!appUrl) return res.status(500).send("Missing APP_URL in env");

  const scopes = "read_products";
  const redirectUri = `${appUrl}/auth/shopify/callback`;
  const state = crypto.randomBytes(16).toString("hex");

  // OPTIONAL: store state to verify later (MVP)
  // tokenStore.set(`state:${shop}`, state);

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

// OAuth callback (Shopify redirects here)
app.get("/auth/shopify/callback", async (req, res) => {
  const { shop, code, hmac } = req.query;

  if (!shop || !code || !hmac) return res.status(400).send("Missing shop/code/hmac");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const apiKey = process.env.SHOPIFY_API_KEY;
  const apiSecret = process.env.SHOPIFY_API_SECRET;

  if (!apiKey) return res.status(500).send("Missing SHOPIFY_API_KEY in env");
  if (!apiSecret) return res.status(500).send("Missing SHOPIFY_API_SECRET in env");

  // 1) HMAC validation
  const query = { ...req.query };
  delete query.hmac;
  delete query.signature;

  const message = Object.keys(query)
    .sort()
    .map((key) => `${key}=${Array.isArray(query[key]) ? query[key].join(",") : query[key]}`)
    .join("&");

  const generated = crypto.createHmac("sha256", apiSecret).update(message).digest("hex");

  const safeCompare = (a, b) => {
    const aBuf = Buffer.from(a, "utf8");
    const bBuf = Buffer.from(b, "utf8");
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  };

  if (!safeCompare(generated, hmac)) return res.status(401).send("HMAC validation failed");

  console.log(`✅ HMAC OK for ${shop}. Exchanging code for token...`);

  // 2) Exchange code -> access token
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

  // ✅ STORE TOKEN SERVER-SIDE (do NOT expose it)
  tokenStore.set(shop, accessToken);

  console.log(`✅ Token stored for ${shop}: ${accessToken.slice(0, 8)}...`);

  // Redirect somewhere safe (or return OK)
  return res
    .status(200)
    .send(`✅ Connected successfully for ${shop}. Token stored securely on server.`);
});

// --------------------
// Shopify API routes (no token in URL)
// --------------------

// GET /shopify/products?shop=xxxx.myshopify.com
app.get("/shopify/products", async (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const accessToken = tokenStore.get(shop);
  if (!accessToken) {
    return res
      .status(401)
      .send("No stored token for this shop. Install the app first: /auth/shopify/install?shop=...");
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

// OPTIONAL: Check if token exists for a shop
// GET /shopify/status?shop=xxxx.myshopify.com
app.get("/shopify/status", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  const hasToken = tokenStore.has(shop);
  return res.status(200).json({ shop, connected: hasToken });
});

// Health check
app.get("/", (req, res) => res.send("Svario Webhook is running ✅"));

// Start server (keep LAST)
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 Webhook running on port ${port}`));
