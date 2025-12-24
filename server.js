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

app.get("/auth/shopify", (req, res) => {
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
app.get("/auth/shopify/callback", (req, res) => {
  res.status(200).send("Shopify callback received ✅");
});
// Default route for quick check
app.get("/", (req, res) => res.send("Svario Webhook is running ✅"));

// Render automatically assigns a port, so we listen on that
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 Webhook running on port ${port}`));
