import { enclave, callEnclave } from "@/lib/crypto-enclave/client";
import { anchorChallenge, b64u } from "@/lib/anon-booking/zkp-anchor";

/** All private key generation stays in the enclave. WebAuthn may prompt several times. */
export async function createHardwarePublication(userId: string, rpId: string, handle: string) {
 const id = (prefix: string) => prefix + Array.from(crypto.getRandomValues(new Uint8Array(32)), x => x.toString(16).padStart(2, "0")).join("");
 const assertion = async (challenge: Uint8Array) => {
  const credential = await navigator.credentials.get({ publicKey: { challenge: challenge.slice().buffer as ArrayBuffer, rpId, userVerification: "required", timeout: 120000 } });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("passkey_cancelled");
  return { credentialId: b64u(new Uint8Array(credential.rawId)), authenticatorData: b64u(new Uint8Array(credential.response.authenticatorData)), clientDataJSON: b64u(new Uint8Array(credential.response.clientDataJSON)), signature: b64u(new Uint8Array(credential.response.signature)) };
 };
 const deviceId = id("hd_"), keyId = id("hk_"), treeId = id("st_");
 const host = await enclave.hostKey.init(userId, keyId);
 const genesis = await enclave.smt.genesis(userId, treeId);
 const signed = await callEnclave("host_key.sign_anchor", { userId, keyId, treeId });
 const statement = { deviceId, keyId, treeId, anchorPublicKey: host.anchor.publicKey, anchorSignerPublicKey: signed.signerPublicKey, rootSignerPublicKey: genesis.signedRoot.publicKey };
 let prekey: Awaited<ReturnType<typeof enclave.pqRatchet.createPrekeyBundle>> | undefined;
 try {
  const anchor = { ...(await assertion(anchorChallenge(statement))), deviceId, keyId, treeId, anchorPublicKey: b64u(statement.anchorPublicKey), anchorSignerPublicKey: b64u(statement.anchorSignerPublicKey), rootSignerPublicKey: b64u(statement.rootSignerPublicKey), anchorSignature: b64u(signed.signature), sealedState: b64u(host.sealedState), genesisSignature: b64u(genesis.signedRoot.signature) };
  prekey = await enclave.pqRatchet.createPrekeyBundle(userId, rpId, handle);
  return { sessionId: prekey.sessionId, payload: { anchor, prekey: { ...(await assertion(prekey.challenge)), bundle: b64u(prekey.bundle) } } };
 } catch (error) { if (prekey) await enclave.pqRatchet.close(userId, prekey.sessionId).catch(() => {}); throw error; }
 finally { host.sealedState.fill(0); prekey?.bundle.fill(0); }
}