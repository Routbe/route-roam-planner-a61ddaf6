import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { KeyRound, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { authClient } from "@/lib/auth-client";
import { hardwarePublicationStatus, publishHardwareIdentity } from "@/lib/pq/hardware-publication.functions";
import { useI18n } from "@/lib/i18n";
import { captureEnclaveScope, enclave } from "@/lib/crypto-enclave/client";

export function HardwarePublication() {
 const { user } = useAuth();
 const { locale } = useI18n();
 const status = useServerFn(hardwarePublicationStatus), publish = useServerFn(publishHardwareIdentity);
 const [busy, setBusy] = useState(false), [result, setResult] = useState("");
 const labels = { nl: ["Hardware-identiteit publiceren", "Gepubliceerd", "Publicatie niet voltooid"], en: ["Publish hardware identity", "Published", "Publication incomplete"], fr: ["Publier l’identité matérielle", "Publié", "Publication incomplète"], de: ["Hardware-Identität veröffentlichen", "Veröffentlicht", "Veröffentlichung unvollständig"] };
 const text = labels[locale] ?? labels.en;
 const run = async () => {
  if (!user || busy) return;
  setBusy(true); setResult("");
  try {
   const s = await status();
   if (!s.storage) throw new Error("Scaleway: storage_unavailable");
   if (!s.handle) throw new Error("no_handle");
   const signedIn = await authClient.signIn.passkey();
   if (signedIn.error) throw new Error("passkey_required");
   const scope = captureEnclaveScope();
   const { createHardwarePublication } = await import("@/lib/pq/hardware-publication");
   const created = await createHardwarePublication(user.id, s.rpId, s.handle);
   scope.assertCurrent();
   const r = await publish({ data: created.payload });
   scope.assertCurrent();
   if (!r.ok) {
    if (!("prekeyPublished" in r && r.prekeyPublished)) await enclave.pqRatchet.close(user.id, created.sessionId);
    throw new Error(r.reason);
   }
   setResult(`${text[1]}: /@${r.handle}/prekey-bundle.json · /@${r.handle}/zkp-anchor.json`);
  } catch (e) { setResult(`${text[2]}: ${e instanceof Error ? e.message : "unavailable"}`); }
  finally { setBusy(false); }
 };
 return <section className="border-t border-border pt-6">
  <Button onClick={run} disabled={!user || busy}>{busy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}{text[0]}</Button>
  {result && <p role="status" className="mt-3 break-words text-sm text-muted-foreground">{result}</p>}
 </section>;
}