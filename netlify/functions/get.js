//reference: https://medium.com/@brent.gruber77/how-i-built-a-tailscale-auth-key-rotator-814722b839e0
import { getStore } from "@netlify/blobs";

const MAX_AGE_DAYS = 85;

export default async (req) => {
  // --- Basic Auth ---
  if (!checkBasicAuth(req)) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="tailscale-auth"',
      },
    });
  }

  const store = getStore("tailscale");
  const now = new Date();

  let record = await store.get("authkey", { type: "json" });

  const expired =
    !record ||
    (now - new Date(record.createdAt)) / (1000 * 60 * 60 * 24) > MAX_AGE_DAYS;

  if (!expired) {
    return new Response(JSON.stringify({ key: record.key }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  const res = await fetch(
    `https://api.tailscale.com/api/v2/tailnet/-/keys`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${await getAPIKey()}`,
      },
      body: JSON.stringify({
        description: "GitHub Actions rotated key",
        expirySeconds: 86400 * 89,//up to 90 days
        capabilities: {
          devices: {
            create: {
              reusable: true,
              ephemeral: true,
              preauthorized: true,
              tags: ["tag:weak"],//get 'tailnet-owned auth key must have tags set' error if not set
            },
          },
        },
      }),
    }
  );

  if (!res.ok) {
    return new Response("Failed to create key", { status: 500 });
  }

  const data = await res.json();

  const newRecord = {
    key: data.key,
    createdAt: now.toISOString(),
  };

  await store.set("authkey", JSON.stringify(newRecord));

  return new Response(JSON.stringify({ key: data.key }), {
    headers: { "Content-Type": "application/json" },
  });
};

function checkBasicAuth(req) {
  const auth = req.headers.get("authorization");
  if (!auth || !auth.startsWith("Basic ")) {
    return false;
  }

  const decoded = Buffer.from(auth.slice(6), "base64").toString();
  const [user, pass] = decoded.split(":");

  return (
    user === "user" &&
    pass === process.env.BASIC_AUTH_PASS
  );
}

//The OAuth credential must have "auth_keys" scope for subsequent auth key creation,
//but this function will be successful even if no (practically, at least one) permission is granted to the credential.
async function getAPIKey(){
  const auth = await fetch(
    `https://api.tailscale.com/api/v2/oauth/token`,
    {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body: new URLSearchParams({
            grant_type: "client_credentials",
            client_id: process.env.TS_OAUTH_CLIENT_ID,
            client_secret: process.env.TS_OAUTH_CLIENT_SECRET,
        }).toString(),
    }
  )
  const auth1 = await auth.json()
  //we can check scope here
  //console.log(auth1.scope)
  return auth1.access_token
}