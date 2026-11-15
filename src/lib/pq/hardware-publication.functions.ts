import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

const bytes = z.string().regex(/^[A-Za-z0-9_-]+$/).max(8192);
const assertion = z.object({ credentialId: bytes, authenticatorData: bytes, clientDataJSON: bytes, signature: bytes });
const input = z.object({
 prekey: assertion.extend({ bundle: bytes }),
 anchor: assertion.extend({ deviceId: z.string().regex(/^hd_[0-9a-f]{64}$/), keyId: z.string().regex(/^hk_[0-9a-f]{64}$/), treeId: z.string().regex(/^st_[0-9a-f]{64}$/),
 anchorPublicKey: bytes, anchorSignerPublicKey: bytes, rootSignerPublicKey: bytes, anchorSignature: bytes, sealedState: bytes, genesisSignature: bytes }),
});

export const hardwarePublicationStatus = createServerFn({ method: "GET" }).middleware([requireAuth]).handler(async () => {
 const { storageConfigured } = await import("@/lib/storage/s3.server");
 const { readMyHandle } = await import("@/lib/claim.server");
 const { currentDbUserId } = await import("@/lib/neon");
 const { prekeyRp } = await import("./prekey-publish.server");
 const uid = currentDbUserId();
 if (!uid) throw new Error("Authentication required");
 return { storage: storageConfigured("client"), handle: (await readMyHandle(uid)).handle, ...(await prekeyRp()) };
});

/** Uses only existing DB capabilities, a fresh passkey proof and worker-generated public/encrypted material. */
export const publishHardwareIdentity = createServerFn({ method: "POST" }).middleware([requireAuth]).inputValidator((v: unknown) => input.parse(v)).handler(async ({ context, data }) => {
 const { storageConfigured, putObject } = await import("@/lib/storage/s3.server");
 if (!storageConfigured("client")) return { ok: false, reason: "storage_unavailable" };
 const { ensureStepUpProof } = await import("@/lib/auth/step-up.server");
 const { stepUpProofId } = await import("@/lib/vault/step-up-proof-id");
 const proof = await ensureStepUpProof(context.userId, "recovery_vault");
 if (proof.method !== "passkey") return { ok: false, reason: "passkey_required" };
 const { productionPublishDeps, publishPrekey } = await import("./prekey-publish.server");
 const { AnonHostChainStore } = await import("@/lib/anon-booking/host-chain-store.server");
 const { fromB64u, parseCoseKey } = await import("@/lib/anon-booking/zkp-anchor");
 const { runQuery, withDbContext } = await import("@/lib/neon");
 const deps = await productionPublishDeps();
 const store = new AnonHostChainStore(async (uid, q, p) => (await withDbContext({ userId: uid, workspaceId: null }, () => runQuery(q, [...p]))).rows, deps);
 const pk = await store.passkey(context.userId, data.prekey.credentialId);
 const apk = await store.passkey(context.userId, data.anchor.credentialId);
 if (!pk.found || !apk.found || !pk.attested || !apk.attested || !pk.statusSafe || !apk.statusSafe) return { ok: false, reason: "hardware_attestation_required" };
 const prekey = await publishPrekey(deps, context.userId, { ...data.prekey, algorithm: parseCoseKey(pk.publicKey).alg });
 if (!prekey.ok) return { ok: false, reason: prekey.reason };
 const a = data.anchor;
 const registered = await store.registerDevice(context.userId, {
  deviceId: a.deviceId, keyId: a.keyId, treeId: a.treeId, proofId: stepUpProofId(proof.jti), algorithm: parseCoseKey(apk.publicKey).alg,
  credentialId: a.credentialId, anchorPublicKey: fromB64u(a.anchorPublicKey), anchorSignerPublicKey: fromB64u(a.anchorSignerPublicKey), rootSignerPublicKey: fromB64u(a.rootSignerPublicKey),
  anchorSignature: fromB64u(a.anchorSignature), sealedState: fromB64u(a.sealedState), genesisSignature: fromB64u(a.genesisSignature),
  authenticatorData: fromB64u(a.authenticatorData), clientDataJSON: fromB64u(a.clientDataJSON), passkeySignature: fromB64u(a.signature),
 });
 if (!registered.ok) return { ok: false, reason: `anchor_${registered.why}`, prekeyPublished: true };
 const { readZkpAnchorDocument } = await import("@/lib/anon-booking/zkp-anchor.server");
 const doc = await readZkpAnchorDocument(async (q, p) => (await runQuery(q, p)).rows, prekey.handle, deps.rpId);
 if (doc.status !== "ok") return { ok: false, reason: "anchor_readback_failed", prekeyPublished: true };
 try { await putObject("client", `users/${context.userId}/zkp-anchor.json`, new TextEncoder().encode(JSON.stringify(doc.document)), { contentType: "application/json", cacheControl: "no-store" }); }
 catch { return { ok: false, reason: "anchor_storage_failed", prekeyPublished: true }; }
 return { ok: true, handle: prekey.handle };
});