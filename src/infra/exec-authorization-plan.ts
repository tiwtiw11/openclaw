import { explainShellCommand } from "./command-explainer/extract.js";
import type {
  CommandExplanation,
  CommandOperator,
  CommandRisk,
  CommandStep,
} from "./command-explainer/types.js";
import { isDispatchWrapperExecutable } from "./dispatch-wrapper-resolution.js";
import {
  type ExecCommandAnalysis,
  type ExecCommandSegment,
  resolveCommandResolutionFromArgv,
  type ShellChainOperator,
} from "./exec-approvals-analysis.js";
import {
  extractBindableShellWrapperInlineCommand,
  normalizeExecutableToken,
} from "./exec-wrapper-resolution.js";
import {
  hasPosixInteractiveStartupBeforeInlineCommand,
  hasPosixLoginStartupBeforeInlineCommand,
  POSIX_INLINE_COMMAND_FLAGS,
  resolveInlineCommandMatch,
} from "./shell-inline-command.js";
import { POSIX_SHELL_WRAPPERS } from "./shell-wrapper-resolution.js";

const POSIX_SHELL_NAMES: ReadonlySet<string> = new Set(POSIX_SHELL_WRAPPERS);

export type ExecAuthorizationDialect = "argv" | "posix-shell" | "windows-cmd" | "powershell";

export type ExecAuthorizationRelationship =
  | "simple"
  | "pipeline"
  | "sequence"
  | "and"
  | "or"
  | "wrapper-inline";

export type ExecAuthorizationTransport =
  | { kind: "direct" }
  | {
      kind: "shell-wrapper";
      wrapperSegment: ExecCommandSegment;
      wrapperArgv: string[];
      inlineCommand: string;
    };

export type ExecAuthorizationTrustMode = "executable" | "exact-command" | "prompt-only";

export type ExecAuthorizationCandidate = {
  argv: string[];
  sourceSegment: ExecCommandSegment;
  sourceStep: CommandStep;
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
  trustMode: ExecAuthorizationTrustMode;
  allowAlways: boolean;
  reasons: string[];
};

export type ExecAuthorizationGroup = {
  relationship: ExecAuthorizationRelationship;
  opFromPrevious?: ShellChainOperator | null;
  opToNext?: ShellChainOperator | null;
  candidates: ExecAuthorizationCandidate[];
};

export type ExecAuthorizationPlan =
  | {
      ok: true;
      dialect: ExecAuthorizationDialect;
      originalCommand: string;
      groups: ExecAuthorizationGroup[];
      executionSegments: ExecCommandSegment[];
      operators: CommandOperator[];
      risks: CommandRisk[];
    }
  | {
      ok: false;
      dialect: ExecAuthorizationDialect;
      originalCommand: string;
      reason: string;
      groups: [];
      executionSegments: [];
      operators: [];
      risks: CommandRisk[];
    };

type CommandStepWithSegment = {
  step: CommandStep;
  segment: ExecCommandSegment;
};

type PlanningContext = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
};

type WrapperPayloadPlan = {
  groups: ExecAuthorizationGroup[];
  reasons: string[];
};

const PROMPT_ONLY_RISKS = new Set<CommandRisk["kind"]>([
  "inline-eval",
  "eval",
  "source",
  "alias",
  "function-definition",
  "shell-wrapper-through-carrier",
  "command-carrier",
]);

const UNANALYZABLE_RISKS = new Set<CommandRisk["kind"]>([
  "command-substitution",
  "dynamic-executable",
  "line-continuation",
  "heredoc",
  "here-string",
  "process-substitution",
  "redirect",
  "syntax-error",
]);

const POWERSHELL_NAMES = new Set(["powershell", "pwsh"]);
const WINDOWS_CMD_NAMES = new Set(["cmd", "cmd.exe"]);
export const POSITIONAL_CARRIER_BLOCKED_EXECUTABLES = new Set(["find", "xargs"]);

function commandSegmentFromStep(step: CommandStep, context: PlanningContext): ExecCommandSegment {
  return {
    raw: step.text,
    argv: step.argv,
    resolution: resolveCommandResolutionFromArgv(step.argv, context.cwd, context.env),
  };
}

function commandSegmentFromArgv(
  argv: string[],
  context: PlanningContext,
  sourceArgv?: string[],
): ExecCommandSegment {
  return {
    raw: argv.join(" "),
    argv,
    sourceArgv,
    resolution: resolveCommandResolutionFromArgv(argv, context.cwd, context.env),
  };
}

function relationshipForOperator(
  operator: ShellChainOperator | null | undefined,
): ExecAuthorizationRelationship {
  if (operator === "&&") {
    return "and";
  }
  if (operator === "||") {
    return "or";
  }
  if (operator === ";") {
    return "sequence";
  }
  return "simple";
}

type AuthorizationOperator = ShellChainOperator | "pipe";

function authorizationOperatorForTopology(operator: CommandOperator): AuthorizationOperator {
  switch (operator.kind) {
    case "and":
      return "&&";
    case "or":
      return "||";
    case "pipe":
    case "stderr-pipe":
      return "pipe";
    case "sequence":
    case "newline-sequence":
    case "background":
      return ";";
    default: {
      const unreachable: never = operator.kind;
      return unreachable;
    }
  }
}

function riskInsideStep(risk: CommandRisk, step: CommandStep): boolean {
  return risk.span.startIndex >= step.span.startIndex && risk.span.endIndex <= step.span.endIndex;
}

function stepReasons(step: CommandStep, risks: readonly CommandRisk[]): string[] {
  const reasons: string[] = [];
  for (const risk of risks) {
    if (PROMPT_ONLY_RISKS.has(risk.kind) && riskInsideStep(risk, step)) {
      reasons.push(risk.kind);
    }
  }
  return [...new Set(reasons)];
}

function isShellExpansionDynamicArgument(risk: CommandRisk): boolean {
  return (
    risk.kind === "dynamic-argument" &&
    /(?:\$[A-Za-z0-9_@*?#$!-]|\$\{|`|\$\(|[<>]\()/u.test(risk.text)
  );
}

function riskInsidePromptOnlyStep(risk: CommandRisk, explanation: CommandExplanation): boolean {
  return [...explanation.topLevelCommands, ...explanation.nestedCommands].some(
    (step) => riskInsideStep(risk, step) && stepReasons(step, explanation.risks).length > 0,
  );
}

function hasBlockingRisk(explanation: CommandExplanation): string | null {
  const risk = explanation.risks.find((entry) => UNANALYZABLE_RISKS.has(entry.kind));
  if (risk) {
    return risk.kind;
  }
  const dynamicArgument = explanation.risks.find(
    (entry) =>
      isShellExpansionDynamicArgument(entry) && !riskInsidePromptOnlyStep(entry, explanation),
  );
  if (dynamicArgument) {
    return dynamicArgument.kind;
  }
  const operator = explanation.operators?.find((entry) => entry.kind === "background");
  return operator ? operator.kind : null;
}

function isPathScopedExecutableToken(token: string): boolean {
  return token.includes("/") || token.includes("\\");
}

export function canUseReusableWrapperPayloadCandidates(
  segments: readonly ExecCommandSegment[],
): boolean {
  const firstExecutable = segments[0]?.argv[0]?.trim() ?? "";
  if (!firstExecutable) {
    return false;
  }
  if (segments.some((segment) => isPathScopedExecutableToken(segment.argv[0]?.trim() ?? ""))) {
    return false;
  }
  return !normalizeExecutableToken(firstExecutable).endsWith("-wrapper");
}

function isShellExecutable(argv: readonly string[]): boolean {
  const executable = normalizeExecutableToken(argv[0] ?? "");
  return POSIX_SHELL_NAMES.has(executable);
}

function canUseWrapperShellInvocation(argv: string[]): boolean {
  return (
    !hasPosixInteractiveStartupBeforeInlineCommand(argv, POSIX_INLINE_COMMAND_FLAGS) &&
    !hasPosixLoginStartupBeforeInlineCommand(argv, POSIX_INLINE_COMMAND_FLAGS)
  );
}

function isDirectShellPositionalCarrierInvocation(command: string): boolean {
  const trimmed = command.trim();
  if (trimmed.length === 0) {
    return false;
  }

  const shellWhitespace = String.raw`[^\S\r\n]+`;
  const positionalZero = String.raw`(?:\$(?:0|\{0\})|"\$(?:0|\{0\})")`;
  const positionalArg = String.raw`(?:\$(?:[@*]|[1-9]|\{[@*1-9]\})|"\$(?:[@*]|[1-9]|\{[@*1-9]\})")`;
  return new RegExp(
    `^(?:exec${shellWhitespace}(?:--${shellWhitespace})?)?${positionalZero}(?:${shellWhitespace}${positionalArg})*$`,
    "u",
  ).test(trimmed);
}

function positionalCarrierSteps(params: {
  wrapper: CommandStepWithSegment;
  context: PlanningContext;
}): CommandStepWithSegment[] | null {
  const inlineMatch = resolveInlineCommandMatch(
    params.wrapper.segment.argv,
    POSIX_INLINE_COMMAND_FLAGS,
    { allowCombinedC: true },
  );
  if (inlineMatch.valueTokenIndex === null || !inlineMatch.command) {
    return null;
  }
  if (!canUseWrapperShellInvocation(params.wrapper.segment.argv)) {
    return null;
  }
  if (!isDirectShellPositionalCarrierInvocation(inlineMatch.command)) {
    return null;
  }
  const carriedArgv = params.wrapper.segment.argv
    .slice(inlineMatch.valueTokenIndex + 1)
    .filter((token) => token.trim().length > 0);
  if (carriedArgv.length === 0) {
    return null;
  }
  const carriedName = normalizeExecutableToken(carriedArgv[0] ?? "");
  if (
    isDispatchWrapperExecutable(carriedName) ||
    POSITIONAL_CARRIER_BLOCKED_EXECUTABLES.has(carriedName) ||
    POSIX_SHELL_NAMES.has(carriedName) ||
    carriedName.endsWith("-wrapper")
  ) {
    return null;
  }
  const raw = carriedArgv.join(" ");
  const carriedSpan = {
    startIndex: params.wrapper.step.span.endIndex,
    endIndex: params.wrapper.step.span.endIndex,
    startPosition: params.wrapper.step.span.endPosition,
    endPosition: params.wrapper.step.span.endPosition,
  };
  const step: CommandStep = {
    context: "wrapper-payload",
    executable: carriedArgv[0] ?? "",
    argv: carriedArgv,
    text: raw,
    span: carriedSpan,
    executableSpan: carriedSpan,
  };
  return [
    {
      step,
      segment: commandSegmentFromArgv(
        carriedArgv,
        params.context,
        params.wrapper.segment.sourceArgv,
      ),
    },
  ];
}

function shouldPersistCandidate(params: {
  segment: ExecCommandSegment;
  relationship: ExecAuthorizationRelationship;
  trustMode: ExecAuthorizationTrustMode;
}): boolean {
  if (params.trustMode !== "executable") {
    return false;
  }
  if (params.relationship === "pipeline" && isShellExecutable(params.segment.argv)) {
    return false;
  }
  return params.segment.resolution?.policyBlocked !== true;
}

function createCandidate(params: {
  step: CommandStep;
  segment: ExecCommandSegment;
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
  risks: readonly CommandRisk[];
}): ExecAuthorizationCandidate {
  const reasons = stepReasons(params.step, params.risks);
  const isDirectShellWrapper =
    params.transport.kind === "direct" &&
    extractBindableShellWrapperInlineCommand(params.segment.argv);
  const trustMode: ExecAuthorizationTrustMode =
    params.segment.resolution?.policyBlocked === true
      ? "prompt-only"
      : isDirectShellWrapper
        ? "exact-command"
        : reasons.length > 0
          ? "prompt-only"
          : "executable";
  return {
    argv: params.segment.argv,
    sourceSegment: params.segment,
    sourceStep: params.step,
    relationship: params.relationship,
    transport: params.transport,
    trustMode,
    allowAlways: shouldPersistCandidate({
      segment: params.segment,
      relationship: params.relationship,
      trustMode,
    }),
    reasons,
  };
}

function finalizeGroup(params: {
  steps: CommandStepWithSegment[];
  relationship: ExecAuthorizationRelationship;
  opFromPrevious: ShellChainOperator | null;
  opToNext: ShellChainOperator | null;
  transport: ExecAuthorizationTransport;
  risks: readonly CommandRisk[];
}): ExecAuthorizationGroup {
  const relationship = params.steps.length > 1 ? "pipeline" : params.relationship;
  return {
    relationship,
    opFromPrevious: params.opFromPrevious,
    opToNext: params.opToNext,
    candidates: params.steps.map((entry) =>
      createCandidate({
        step: entry.step,
        segment: entry.segment,
        relationship,
        transport: params.transport,
        risks: params.risks,
      }),
    ),
  };
}

function groupsFromSteps(params: {
  steps: CommandStepWithSegment[];
  operators?: readonly CommandOperator[];
  transport: ExecAuthorizationTransport;
  risks: readonly CommandRisk[];
}): ExecAuthorizationGroup[] {
  const sorted = params.steps.toSorted(
    (left, right) => left.step.span.startIndex - right.step.span.startIndex,
  );
  const groups: ExecAuthorizationGroup[] = [];
  let current: CommandStepWithSegment[] = [];
  let opFromPrevious: ShellChainOperator | null = null;
  const operatorByFromCommandId = new Map<string, AuthorizationOperator>();
  for (const operator of params.operators ?? []) {
    operatorByFromCommandId.set(operator.fromCommandId, authorizationOperatorForTopology(operator));
  }

  if (sorted.length > 1 && operatorByFromCommandId.size === 0) {
    return [
      finalizeGroup({
        steps: sorted,
        relationship: "pipeline",
        opFromPrevious: null,
        opToNext: null,
        transport: params.transport,
        risks: params.risks,
      }),
    ];
  }

  for (const entry of sorted) {
    if (current.length === 0) {
      current = [entry];
      continue;
    }
    const previous = current[current.length - 1];
    if (!previous) {
      current = [entry];
      continue;
    }
    const previousCommandId = previous.step.id;
    const operator = previousCommandId ? operatorByFromCommandId.get(previousCommandId) : undefined;
    if (operator === "pipe") {
      current.push(entry);
      continue;
    }
    const opToNext = operator === "&&" || operator === "||" || operator === ";" ? operator : ";";
    groups.push(
      finalizeGroup({
        steps: current,
        relationship: relationshipForOperator(opFromPrevious),
        opFromPrevious,
        opToNext,
        transport: params.transport,
        risks: params.risks,
      }),
    );
    current = [entry];
    opFromPrevious = opToNext;
  }

  if (current.length > 0) {
    groups.push(
      finalizeGroup({
        steps: current,
        relationship: relationshipForOperator(opFromPrevious),
        opFromPrevious,
        opToNext: null,
        transport: params.transport,
        risks: params.risks,
      }),
    );
  }

  return groups;
}

function shellWrapperRiskForStep(
  step: CommandStep,
  risks: readonly CommandRisk[],
): Extract<CommandRisk, { kind: "shell-wrapper" }> | null {
  const risk = risks.find(
    (entry): entry is Extract<CommandRisk, { kind: "shell-wrapper" }> =>
      entry.kind === "shell-wrapper" && riskInsideStep(entry, step),
  );
  return risk ?? null;
}

function shouldUseWrapperPayload(params: {
  wrapperCommandId?: string;
  topLevelSteps: readonly CommandStepWithSegment[];
  nestedSteps: readonly CommandStepWithSegment[];
  risks: readonly CommandRisk[];
}): boolean {
  if (params.topLevelSteps.length !== 1 || params.nestedSteps.length === 0) {
    return false;
  }
  const wrapperStep = params.topLevelSteps[0]?.step;
  if (!wrapperStep || !shellWrapperRiskForStep(wrapperStep, params.risks)) {
    return false;
  }
  const nestedStepsForWrapper = params.wrapperCommandId
    ? params.nestedSteps.filter((entry) => entry.step.parentCommandId === params.wrapperCommandId)
    : params.nestedSteps;
  return canUseReusableWrapperPayloadCandidates(
    nestedStepsForWrapper.map((entry) => entry.segment),
  );
}

function wrapperPayloadPlan(params: {
  context: PlanningContext;
  allowNestedPayload: boolean;
  topLevelSteps: CommandStepWithSegment[];
  nestedSteps: CommandStepWithSegment[];
  operators: readonly CommandOperator[];
  risks: readonly CommandRisk[];
}): WrapperPayloadPlan | null {
  const wrapper = params.topLevelSteps[0];
  if (!wrapper) {
    return null;
  }
  const wrapperRisk = shellWrapperRiskForStep(wrapper.step, params.risks);
  if (!wrapperRisk) {
    return null;
  }
  if (!canUseWrapperShellInvocation(wrapper.segment.argv)) {
    return null;
  }
  const carriedSteps = positionalCarrierSteps({ wrapper, context: params.context });
  if (carriedSteps) {
    const transport: ExecAuthorizationTransport = {
      kind: "shell-wrapper",
      wrapperSegment: wrapper.segment,
      wrapperArgv: wrapper.segment.argv,
      inlineCommand: wrapperRisk.payload,
    };
    const groups = groupsFromSteps({
      steps: carriedSteps,
      transport,
      risks: params.risks,
    });
    return groups.length > 0 ? { groups, reasons: [] } : null;
  }
  if (!params.allowNestedPayload) {
    return null;
  }
  if (
    !shouldUseWrapperPayload({
      wrapperCommandId: wrapper.step.id,
      topLevelSteps: params.topLevelSteps,
      nestedSteps: params.nestedSteps,
      risks: params.risks,
    })
  ) {
    return null;
  }
  const transport: ExecAuthorizationTransport = {
    kind: "shell-wrapper",
    wrapperSegment: wrapper.segment,
    wrapperArgv: wrapper.segment.argv,
    inlineCommand: wrapperRisk.payload,
  };
  const nestedStepsForWrapper = wrapper.step.id
    ? params.nestedSteps.filter((entry) => entry.step.parentCommandId === wrapper.step.id)
    : params.nestedSteps;
  const operatorsForWrapper = wrapper.step.id
    ? params.operators.filter((operator) => operator.parentCommandId === wrapper.step.id)
    : params.operators;
  const groups = groupsFromSteps({
    steps: nestedStepsForWrapper,
    operators: operatorsForWrapper,
    transport,
    risks: params.risks,
  });
  return groups.length > 0 ? { groups, reasons: [] } : null;
}

function dialectForArgv(argv: readonly string[]): ExecAuthorizationDialect {
  const executable = normalizeExecutableToken(argv[0] ?? "");
  if (POWERSHELL_NAMES.has(executable)) {
    return "powershell";
  }
  if (WINDOWS_CMD_NAMES.has(executable)) {
    return "windows-cmd";
  }
  return "argv";
}

function unanalyzablePlan(params: {
  dialect: ExecAuthorizationDialect;
  command: string;
  reason: string;
  risks?: CommandRisk[];
}): ExecAuthorizationPlan {
  return {
    ok: false,
    dialect: params.dialect,
    originalCommand: params.command,
    reason: params.reason,
    groups: [],
    executionSegments: [],
    operators: [],
    risks: params.risks ?? [],
  };
}

function planFromExplanation(params: {
  command: string;
  explanation: CommandExplanation;
  context: PlanningContext;
}): ExecAuthorizationPlan {
  const topLevelSteps = params.explanation.topLevelCommands.map((step) => ({
    step,
    segment: commandSegmentFromStep(step, params.context),
  }));
  const nestedSteps = params.explanation.nestedCommands
    .filter((step) => step.context === "wrapper-payload")
    .map((step) => ({
      step,
      segment: commandSegmentFromStep(step, params.context),
    }));
  const blockingRisk = hasBlockingRisk(params.explanation);
  const canFallBackToExactWrapper =
    topLevelSteps.length === 1 &&
    Boolean(
      topLevelSteps[0]?.step &&
      shellWrapperRiskForStep(topLevelSteps[0].step, params.explanation.risks),
    );
  if (!params.explanation.ok || (blockingRisk && !canFallBackToExactWrapper)) {
    return unanalyzablePlan({
      dialect: "posix-shell",
      command: params.command,
      reason: blockingRisk ?? "unable to parse command",
      risks: params.explanation.risks,
    });
  }

  const payloadPlan = wrapperPayloadPlan({
    context: params.context,
    allowNestedPayload: !blockingRisk,
    topLevelSteps,
    nestedSteps,
    operators: params.explanation.operators ?? [],
    risks: params.explanation.risks,
  });
  const groups =
    payloadPlan?.groups ??
    groupsFromSteps({
      steps: topLevelSteps,
      operators: (params.explanation.operators ?? []).filter(
        (operator) => operator.parentCommandId === undefined,
      ),
      transport: { kind: "direct" },
      risks: params.explanation.risks,
    });
  if (groups.length === 0) {
    return unanalyzablePlan({
      dialect: "posix-shell",
      command: params.command,
      reason: "no commands to authorize",
      risks: params.explanation.risks,
    });
  }
  return {
    ok: true,
    dialect: "posix-shell",
    originalCommand: params.command,
    groups,
    executionSegments: topLevelSteps.map((entry) => entry.segment),
    operators: params.explanation.operators ?? [],
    risks: params.explanation.risks,
  };
}

export async function planShellAuthorization(params: {
  command: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): Promise<ExecAuthorizationPlan> {
  if (params.platform === "win32") {
    return unanalyzablePlan({
      dialect: "windows-cmd",
      command: params.command,
      reason: "non-POSIX shell command",
    });
  }
  try {
    const explanation = await explainShellCommand(params.command);
    return planFromExplanation({
      command: params.command,
      explanation,
      context: { cwd: params.cwd, env: params.env },
    });
  } catch (error) {
    return unanalyzablePlan({
      dialect: "posix-shell",
      command: params.command,
      reason: error instanceof Error ? error.message : "unable to parse command",
    });
  }
}

export async function planExecAuthorization(params: {
  analysis: ExecCommandAnalysis;
  command?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): Promise<ExecAuthorizationPlan> {
  const command =
    params.command ??
    params.analysis.segments
      .map((segment) => segment.raw)
      .join(params.analysis.chains ? " && " : " | ");
  if (!params.analysis.ok) {
    return unanalyzablePlan({
      dialect: "argv",
      command,
      reason: params.analysis.reason ?? "unable to parse command",
    });
  }

  const argv = params.analysis.segments[0]?.argv ?? [];
  const dialect = dialectForArgv(argv);
  if (dialect !== "argv") {
    return unanalyzablePlan({
      dialect,
      command,
      reason: "non-POSIX command wrapper",
    });
  }

  if (params.analysis.segments.length === 1) {
    const inlineCommand = extractBindableShellWrapperInlineCommand(argv);
    if (inlineCommand) {
      const shellPlan = await planShellAuthorization({
        command: inlineCommand,
        cwd: params.cwd,
        env: params.env,
        platform: params.platform,
      });
      if (shellPlan.ok) {
        const wrapperSegment = params.analysis.segments[0];
        const nestedSegments = shellPlan.groups.flatMap((group) =>
          group.candidates.map((candidate) => candidate.sourceSegment),
        );
        if (wrapperSegment && canUseReusableWrapperPayloadCandidates(nestedSegments)) {
          const groups = shellPlan.groups.map((group) => ({
            ...group,
            candidates: group.candidates.map((candidate) => {
              const transport: ExecAuthorizationTransport = {
                kind: "shell-wrapper",
                wrapperSegment,
                wrapperArgv: wrapperSegment.argv,
                inlineCommand,
              };
              return {
                ...candidate,
                transport,
              };
            }),
          }));
          return {
            ok: true,
            dialect: "argv",
            originalCommand: command,
            groups,
            executionSegments: [wrapperSegment],
            operators: shellPlan.operators,
            risks: shellPlan.risks,
          };
        }
      }
    }
  }

  const steps = params.analysis.segments.map((segment, index) => ({
    step: {
      context: "top-level" as const,
      executable: segment.argv[0] ?? "",
      argv: segment.argv,
      text: segment.raw,
      span: {
        startIndex: index,
        endIndex: index + segment.raw.length,
        startPosition: { row: 0, column: index },
        endPosition: { row: 0, column: index + segment.raw.length },
      },
      executableSpan: {
        startIndex: index,
        endIndex: index + (segment.argv[0]?.length ?? 0),
        startPosition: { row: 0, column: index },
        endPosition: { row: 0, column: index + (segment.argv[0]?.length ?? 0) },
      },
    },
    segment:
      segment.resolution === null
        ? commandSegmentFromArgv(
            segment.argv,
            { cwd: params.cwd, env: params.env },
            segment.sourceArgv,
          )
        : segment,
  }));
  const groups = groupsFromSteps({
    steps,
    transport: { kind: "direct" },
    risks: [],
  });
  return {
    ok: true,
    dialect: "argv",
    originalCommand: command,
    groups,
    executionSegments: params.analysis.segments,
    operators: [],
    risks: [],
  };
}
