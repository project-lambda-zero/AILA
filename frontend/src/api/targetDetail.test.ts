import { describe, expect, it } from "vitest";

import { parseTargetDetail } from "./targetDetail";

const DIGEST = "3f".repeat(32);

describe("parseTargetDetail sha256", () => {
  it("retains the stored sample digest from the merged payload", () => {
    const t = parseTargetDetail({ id: "tgt-1", kind: "elf_sample", sha256: DIGEST });
    expect(t.sha256).toBe(DIGEST);
  });

  it("reads null when the server sent no digest", () => {
    const t = parseTargetDetail({ id: "tgt-1", kind: "elf_sample", sha256: null });
    expect(t.sha256).toBeNull();
  });

  it("reads null when the key is absent", () => {
    const t = parseTargetDetail({ id: "tgt-1", kind: "android_apk" });
    expect(t.sha256).toBeNull();
  });

  it("reads null for a non-string digest rather than coercing it", () => {
    const t = parseTargetDetail({ id: "tgt-1", sha256: 123 });
    expect(t.sha256).toBeNull();
  });
});
