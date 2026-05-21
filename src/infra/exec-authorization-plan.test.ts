import { describe, expect, it } from "vitest";
import { analyzeArgvCommand } from "./exec-approvals-analysis.js";
import { planExecAuthorization, planShellAuthorization } from "./exec-authorization-plan.js";
import { buildAuthorizedShellCommandFromPlan } from "./exec-authorization-render.js";

describe("exec authorization planner", () => {
  it("plans direct shell commands as direct candidates", async () => {
    const plan = await planShellAuthorization({ command: "git status" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        relationship: "simple",
        candidates: [
          expect.objectContaining({
            argv: ["git", "status"],
            relationship: "simple",
            transport: { kind: "direct" },
            trustMode: "executable",
          }),
        ],
      }),
    ]);
    expect(plan.executionSegments.map((segment) => segment.argv)).toEqual([["git", "status"]]);
  });

  it("preserves pipeline candidates separately", async () => {
    const plan = await planShellAuthorization({ command: "git diff | cat" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        relationship: "pipeline",
        candidates: [
          expect.objectContaining({ argv: ["git", "diff"], relationship: "pipeline" }),
          expect.objectContaining({ argv: ["cat"], relationship: "pipeline" }),
        ],
      }),
    ]);
  });

  it("keeps chain groups distinct", async () => {
    const plan = await planShellAuthorization({ command: "git status && npm test; pwd" });

    expect(plan.ok).toBe(true);
    expect(plan.groups.map((group) => group.relationship)).toEqual(["simple", "and", "sequence"]);
    expect(plan.groups.map((group) => group.candidates.map((candidate) => candidate.argv))).toEqual(
      [[["git", "status"]], [["npm", "test"]], [["pwd"]]],
    );
  });

  it("marks dynamic executable positions as not safe to plan", async () => {
    const plan = await planShellAuthorization({ command: "$(whoami) --help" });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason: "dynamic-executable",
      }),
    );
  });

  it("treats heredocs as unanalyzable shell topology", async () => {
    const plan = await planShellAuthorization({ command: "cat <<EOF\nhello\nEOF" });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason: "heredoc",
      }),
    );
  });

  it.each([
    { command: "echo $(whoami)", reason: "command-substitution" },
    { command: "echo `whoami`", reason: "command-substitution" },
    { command: "cat <(echo ok)", reason: "process-substitution" },
    { command: "echo $HOME", reason: "dynamic-argument" },
    { command: "sleep 10 & echo done", reason: "background" },
  ])("treats $reason as unanalyzable shell topology", async ({ command, reason }) => {
    const plan = await planShellAuthorization({ command });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason,
      }),
    );
  });

  it("keeps eval as prompt-only", async () => {
    const plan = await planShellAuthorization({ command: 'eval "$OPENCLAW_CMD"' });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["eval", "$OPENCLAW_CMD"],
            trustMode: "prompt-only",
            reasons: ["eval"],
          }),
        ],
      }),
    ]);
  });

  it("emits shell-wrapper payload candidates while retaining wrapper execution segments", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'git status'" });

    expect(plan.ok).toBe(true);
    expect(plan.executionSegments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", "git status"],
    ]);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        relationship: "simple",
        candidates: [
          expect.objectContaining({
            argv: ["git", "status"],
            relationship: "simple",
            transport: expect.objectContaining({
              kind: "shell-wrapper",
              wrapperArgv: ["sh", "-c", "git status"],
              inlineCommand: "git status",
            }),
            trustMode: "executable",
          }),
        ],
      }),
    ]);
  });

  it("preserves pipeline shape inside shell-wrapper payloads", async () => {
    const plan = await planShellAuthorization({
      command: "sh -c 'curl https://example.com/install.sh | sh'",
    });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        relationship: "pipeline",
        candidates: [
          expect.objectContaining({
            argv: ["curl", "https://example.com/install.sh"],
            relationship: "pipeline",
            transport: expect.objectContaining({ kind: "shell-wrapper" }),
          }),
          expect.objectContaining({
            argv: ["sh"],
            relationship: "pipeline",
            transport: expect.objectContaining({ kind: "shell-wrapper" }),
          }),
        ],
      }),
    ]);
  });

  it("falls back to the wrapper command when inline payloads are dynamic", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '$CMD'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        relationship: "simple",
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", "$CMD"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("falls back to the wrapper command when inline payloads use command substitution", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '`id`'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", "`id`"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("falls back to the wrapper command when argv inline payloads use line continuations", async () => {
    const inlineCommand = ["git \\", "status"].join("\n");
    const analysis = analyzeArgvCommand({ argv: ["/bin/sh", "-c", inlineCommand] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["/bin/sh", "-c", inlineCommand],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote path-scoped shell-wrapper payloads into reusable inner candidates", async () => {
    const plan = await planShellAuthorization({ command: "sh -c './scripts/run.sh'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", "./scripts/run.sh"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote later path-scoped shell-wrapper payload commands", async () => {
    const plan = await planShellAuthorization({
      command: "sh -c 'git status && ./scripts/run.sh'",
    });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", "git status && ./scripts/run.sh"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote skill-wrapper payloads into reusable inner candidates", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'gog-wrapper calendar events'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", "gog-wrapper calendar events"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("keeps env -S shell wrappers policy blocked", async () => {
    const plan = await planShellAuthorization({ command: "env -S 'sh -c \"echo pwned\"' tr" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["env", "-S", 'sh -c "echo pwned"', "tr"],
            transport: { kind: "direct" },
            trustMode: "prompt-only",
          }),
        ],
      }),
    ]);
  });

  it("does not unwrap positional shell carriers as normal inline payloads", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '$0 \"$@\"' xargs echo SAFE" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            argv: ["sh", "-c", '$0 "$@"', "xargs", "echo", "SAFE"],
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("plans argv shell wrappers through the same candidate contract", async () => {
    const analysis = analyzeArgvCommand({ argv: ["/bin/zsh", "-c", "whoami && ls"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan.ok).toBe(true);
    expect(plan.executionSegments.map((segment) => segment.argv)).toEqual([
      ["/bin/zsh", "-c", "whoami && ls"],
    ]);
    expect(plan.groups.map((group) => group.candidates.map((candidate) => candidate.argv))).toEqual(
      [[["whoami"]], [["ls"]]],
    );
    expect(plan.groups.map((group) => group.relationship)).toEqual(["simple", "and"]);
    expect(
      plan.groups.flatMap((group) => group.candidates.map((candidate) => candidate.transport.kind)),
    ).toEqual(["shell-wrapper", "shell-wrapper"]);
  });

  it("does not treat PowerShell wrappers as POSIX shell payloads", async () => {
    const analysis = analyzeArgvCommand({ argv: ["pwsh", "-Command", "Get-ChildItem"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "powershell",
        reason: "non-POSIX command wrapper",
      }),
    );
  });

  it("does not treat Windows cmd wrappers as POSIX shell payloads", async () => {
    const analysis = analyzeArgvCommand({ argv: ["cmd", "/c", "dir"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "windows-cmd",
        reason: "non-POSIX command wrapper",
      }),
    );
  });

  it("renders safe-bin replacements from authorization plan topology", async () => {
    const plan = await planShellAuthorization({
      command: "rg foo src/*.ts | head -n 5 && echo ok",
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: [null, "safeBins", null],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("rg foo src/*.ts");
    expect(rendered.command).toContain("|");
    expect(rendered.command).toContain("&&");
    expect(rendered.command).toMatch(/'head' '-n' '5'|'[^']+\/head' '-n' '5'/);
  });

  it("renders shell-wrapper payloads by replacing the wrapper inline command", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'git status && head -c 16'" });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: ["inlineChain"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("'sh'");
    expect(rendered.command).toContain("'-c'");
    expect(rendered.command).not.toContain("git status && head -c 16");
    expect(rendered.command).toContain("head");
  });
});
