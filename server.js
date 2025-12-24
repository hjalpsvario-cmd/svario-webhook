// Simple Facebook Messenger webhook for Svario.is
const express = require("express");
const app = express();
const crypto = require("crypto");
app.use(express.json());

// This secret word must match the Verify Token in Facebook settings
const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || "svario-secret";

// Step 1: Verify the webhook when Facebook sends a GET request
app.get("/facebook/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("✅ Webhook verified successfully!");
    res.status(200).send(challenge);
  } else {
    console.log("❌ Webhook verification failed");
    res.sendStatus(403);
  }
});

// Step 2: Receive messages from Facebook (POST)
app.post("/facebook/webhook", (req, res) => {
  console.log("📩 Incoming message:", JSON.stringify(req.body, null, 2));
  res.sendStatus(200);
});
// Shopify OAuth – INSTALL (starts OAuth)
app.get("/auth/shopify/install", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();

  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const clientId = process.env.SHOPIFY_API_KEY; // make sure this exists in Render env
  const scopes = "read_products";
  const redirectUri = "https://svario-webhook-1.onrender.com/auth/shopify/callback";

  const state = crypto.randomBytes(16).toString("hex");

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${clientId}` +
    `&scope=${scopes}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  return res.redirect(installUrl);
});

app.get("/auth/shopify/callback", async (req, res) => {
  const shop = (req.query.shop || "").toString().trim();

  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop domain");

  const clientId = process.env.SHOPIFY_API_KEY;
  const redirectUri = "https://svario-webhook-1.onrender.com/auth/shopify/callback";

  // minimal scope for now (we can add later)
  const scope = "read_products";
  const state = "svario123"; // temporary; later we’ll generate/store per user

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&scope=${encodeURIComponent(scope)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});
// Shopify OAuth callback
app.get("/auth/shopify/callback", async (req, res) => {
  const { shop, code, hmac } = req.query;

  if (!shop || !code || !hmac) {
    return res.status(400).send("Missing shop/code/hmac");
  }

  // Build message from query params (exclude hmac + signature)
  const query = { ...req.query };
  delete query.hmac;
  delete query.signature;

  const message = Object.keys(query)
    .sort()
    .map((key) => `${key}=${Array.isArray(query[key]) ? query[key].join(",") : query[key]}`)
    .join("&");

  const generated = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  const safeCompare = (a, b) => {
    const aBuf = Buffer.from(a, "utf8");
    const bBuf = Buffer.from(b, "utf8");
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  };

  if (!safeCompare(generated, hmac)) {
    return res.status(401).send("HMAC validation failed");
  }

  // If you see this, your callback is secure and correct.
    // Exchange code -> access token
  const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      code,
    }),
  });

  const tokenData = await tokenRes.json();

  if (!tokenRes.ok) {
    console.log("Token exchange failed:", tokenData);
    return res.status(500).send("Token exchange failed");
  }

  const accessToken = tokenData.access_token;

  return res
    .status(200)
    .send(`✅ Token received for ${shop}: ${accessToken.slice(0, 8)}...`);
});

// Default route for quick check
app.get("/", (req, res) => res.send("Svario Webhook is running ✅"));

// Render automatically assigns a port, so we listen on that
const port = process.env.PORT || 4000;
const crypto = require("crypto");

// Shopify install route (start OAuth)
app.get("/auth/shopify/install", (req, res) => {
  const { shop } = req.query;

  if (!shop) {
    return res.status(400).send("Missing ?shop=your-store.myshopify.com");
  }

  const APP_URL = process.env.APP_URL; // e.g. https://svario-webhook-1.onrender.com
  const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;

  const redirectUri = `${APP_URL}/auth/shopify/callback`;
  const scopes = "read_products"; // keep simple for now
  const state = crypto.randomBytes(16).toString("hex");

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  return res.redirect(installUrl);
});

app.listen(port, () => console.log(`🚀 Webhook running on port ${port}`));
