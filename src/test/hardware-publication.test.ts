import { describe, it, expect, vi, beforeEach } from "vitest";
const mocks = vi.hoisted(() => ({ configured: vi.fn(), proof: vi.fn(), passkey: vi.fn(), put: vi.fn() }));
vi.mock("@tanstack/react-start", () => ({ createServerFn: () => {
 const chain = { middleware: () => chain, inputValidator: () => chain, handler: (h: unknown) => h };
 return chain;
} }));
vi.mock("@/lib/auth/middleware", () => ({ requireAuth: {} }));
vi.mock("@/lib/storage/s3.server", () => ({ storageConfigured: mocks.configured, putObject: mocks.put }));
vi.mock("@/lib/auth/step-up.server", () => ({ ensureStepUpProof: mocks.proof }));
vi.mock("@/lib/pq/prekey-publish.server", () => ({ productionPublishDeps: async () => ({ rpId: "rout.be", origins: ["https://rout.be"] }) }));
vi.mock("@/lib/anon-booking/host-chain-store.server", () => ({ AnonHostChainStore: class { passkey = mocks.passkey; } }));
vi.mock("@/lib/neon", () => ({ runQuery: vi.fn(), withDbContext: vi.fn() }));
import { publishHardwareIdentity } from "@/lib/pq/hardware-publication.functions";
const invoke = publishHardwareIdentity as unknown as (v: { context: { userId: string }; data: unknown }) => Promise<unknown>;
beforeEach(() => { vi.resetAllMocks(); });
describe("hardware publication refuses unsafe setup", () => {
 it("does not publish without Scaleway", async () => {
  mocks.configured.mockReturnValue(false);
  expect(await invoke({ context: { userId: "owner" }, data: {} })).toEqual({ ok: false, reason: "storage_unavailable" });
  expect(mocks.proof).not.toHaveBeenCalled(); expect(mocks.put).not.toHaveBeenCalled();
 });
 it("refuses non-passkey step-up", async () => {
  mocks.configured.mockReturnValue(true); mocks.proof.mockResolvedValue({ method: "totp" });
  expect(await invoke({ context: { userId: "owner" }, data: {} })).toEqual({ ok: false, reason: "passkey_required" });
  expect(mocks.put).not.toHaveBeenCalled();
 });
 it("refuses a passkey without hardware attestation before any storage write", async () => {
  mocks.configured.mockReturnValue(true); mocks.proof.mockResolvedValue({ method: "passkey", jti: "proof" });
  mocks.passkey.mockResolvedValue({ found: true, attested: false, statusSafe: true });
  const data = { prekey: { credentialId: "cred" }, anchor: { credentialId: "cred" } };
  expect(await invoke({ context: { userId: "owner" }, data })).toEqual({ ok: false, reason: "hardware_attestation_required" });
  expect(mocks.put).not.toHaveBeenCalled();
 });
});