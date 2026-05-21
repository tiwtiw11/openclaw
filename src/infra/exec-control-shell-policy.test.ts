import { describe, expect, it } from "vitest";
import {
  inspectControlShellCommand,
  type ControlShellPolicyDecision,
} from "./exec-control-shell-policy.js";

async function inspect(command: string): Promise<ControlShellPolicyDecision> {
  return await inspectControlShellCommand({ command });
}

describe("exec control shell policy", () => {
  it.each([
    "openclaw channels login --channel whatsapp",
    "openclaw channel login --channel whatsapp",
    "openclaw channels --profile rescue login --channel whatsapp",
    "openclaw channels --dev login --channel whatsapp",
    "npm exec -- openclaw channels login --channel whatsapp",
    "pnpm exec -- openclaw channels login --channel whatsapp",
    "yarn exec -- openclaw channels login --channel whatsapp",
    "sudo -u openclaw bash -lc 'openclaw channels login --channel whatsapp'",
    "env -S 'openclaw channels' login --channel whatsapp",
  ])("denies interactive channel login commands: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining(
        "exec cannot run interactive OpenClaw channel login commands",
      ),
    });
  });

  it.each([
    "/approve req-1 allow-once",
    "bash -lc '/approve req-1 deny'",
    "sudo /approve req-1 deny",
    "env -S '/approve req-1 allow-always'",
  ])("denies approval commands through exec: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining("exec cannot run /approve commands"),
    });
  });

  it.each([
    "openclaw config get security.audit.suppressions",
    "openclaw --profile rescue config get security.audit.suppressions",
    "openclaw config schema security.audit.suppressions",
    "openclaw config validate",
  ])("allows read-only security audit suppression inspection: %s", async (command) => {
    await expect(inspect(command)).resolves.toEqual({ kind: "allow" });
  });

  it.each([
    "openclaw config set security.audit.suppressions '[]'",
    "openclaw config get security.audit.suppressions; openclaw config set security.audit.suppressions '[]'",
    "bash -lc 'openclaw config set security.audit.suppressions []'",
    `openclaw config patch --stdin <<'EOF'
{"security":{"audit":{"suppressions":[]}}}
EOF`,
  ])("requires approval for security audit suppression mutations: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "requires-approval",
      warning: expect.stringContaining(
        "security audit suppression changes require explicit approval",
      ),
    });
  });

  it("returns requires-approval without knowing whether yolo mode is active", async () => {
    await expect(inspect("openclaw config set security.audit.suppressions '[]'")).resolves.toEqual({
      kind: "requires-approval",
      warning:
        "Warning: security audit suppression changes require explicit approval unless exec is running in yolo mode.",
    });
  });
});
