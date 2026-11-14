#!/usr/bin/env node
/**
 * @module deadbolt-mcp
 * @description DEADBOLT Stdio MCP Server enforcing INV-DB-01, INV-DB-02, and 8090 Software Factory
 * MCP Permission Model (4 read-only Allow tools + 1 human-gated Confirm action tool).
 */

import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  defineMcpTool,
  createMcpServer,
  okMcpResult,
  errorMcpResult
} from '@krusch/toolkit/mcp';

export const DEADBOLT_MCP_TOOLS = Object.freeze([
  defineMcpTool({
    name: 'deadbolt_hydrate_work_order',
    title: 'Hydrate Work Order Organizational Context',
    description:
      'Hydrates bounded (<4,000 token) 6-modality organizational context, INV-12 SHA-256 span locks, and invariant superseding lineage for a Work Order (8090 Permission: Allow for Unattended Automations).',
    inputSchema: {
      type: 'object',
      properties: {
        workOrderId: {
          type: 'string',
          default: 'WO-101',
          description: '8090 Software Factory Work Order ID (default: WO-101).'
        },
        query: {
          type: 'string',
          description: 'Optional semantic/BM25 context focus query.'
        },
        tokenBudget: {
          type: 'integer',
          default: 4000,
          description: 'Maximum context token budget ceiling.'
        }
      }
    },
    annotations: {
      sofaPermission: 'Allow',
      sofaScope: 'Unattended Automations'
    },
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  }),
  defineMcpTool({
    name: 'deadbolt_map_blast_radius',
    title: 'Map 2-Hop AST Blast Radius & Parallel Leases',
    description:
      'Maps 2-hop AST dependency call paths, <25us Cascade tier routing, and parallel WO-* disjoint AST leases (8090 Permission: Allow for Unattended Automations).',
    inputSchema: {
      type: 'object',
      properties: {
        workOrderId: {
          type: 'string',
          default: 'WO-101',
          description: 'Work Order ID to evaluate for blast radius and parallel lease isolation.'
        },
        entryFile: {
          type: 'string',
          default: 'src/fee-engine.js',
          description: 'Entry file path for 2-hop caller and dependent traversal.'
        },
        repoDir: {
          type: 'string',
          description: 'Optional target repository directory override.'
        }
      }
    },
    annotations: {
      sofaPermission: 'Allow',
      sofaScope: 'Unattended Automations'
    },
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  }),
  defineMcpTool({
    name: 'deadbolt_validate_reconciliation',
    title: 'Validate Slop Breaker, Policy Floor & SOX Reconciliation',
    description:
      'Runs deterministic <1ms Slop Breaker, non-overridable policy-floor workaround guard, INV-FIN-03 SOX-style integer cent batch reconciliation, and cross-family review (8090 Permission: Allow for Drift Bot & PR Gate).',
    inputSchema: {
      type: 'object',
      properties: {
        workOrderId: {
          type: 'string',
          default: 'WO-101',
          description: 'Work Order ID associated with candidate edits.'
        },
        mode: {
          type: 'string',
          enum: ['naive', 'workaround', 'remediated'],
          default: 'remediated',
          description: 'Preset candidate mode (naive | workaround | remediated) when custom edits are omitted.'
        },
        edits: {
          type: 'array',
          description: 'Optional custom array of { file_path, content } candidate patches.',
          items: {
            type: 'object',
            required: ['file_path', 'content'],
            properties: {
              file_path: { type: 'string' },
              content: { type: 'string' }
            }
          }
        },
        runCrossModel: {
          type: 'boolean',
          default: true,
          description: 'Run separate-family cross-model review after deterministic gates.'
        }
      }
    },
    annotations: {
      sofaPermission: 'Allow',
      sofaScope: 'Drift Bot & PR Gate'
    },
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true
  }),
  defineMcpTool({
    name: 'deadbolt_verify_audit_chain',
    title: 'Verify SHA-256 Cryptographic Audit Ledger',
    description:
      'Verifies tamper-evident SHA-256 cryptographic audit chain integrity and returns measured cost-per-verified-task receipts (8090 Permission: Allow for Compliance Audit).',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'integer',
          default: 50,
          description: 'Maximum number of recent audit ledger entries to return.'
        }
      }
    },
    annotations: {
      sofaPermission: 'Allow',
      sofaScope: 'Compliance Audit'
    },
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  }),
  defineMcpTool({
    name: 'deadbolt_apply_verified_stage',
    title: 'Apply Verified Staged Task & Dispatch Linked PR',
    description:
      'Atomically applies a VERIFIED staged task from isolated harness workspace and dispatches a [WO-101]-linked PR receipt (8090 Permission: Confirm - Human Approval Required).',
    inputSchema: {
      type: 'object',
      required: ['taskId'],
      properties: {
        taskId: {
          type: 'string',
          description: 'Verified harness task identifier to apply atomically.'
        },
        workOrderId: {
          type: 'string',
          default: 'WO-101',
          description: 'Linked 8090 Software Factory Work Order ID for PR receipt.'
        }
      }
    },
    annotations: {
      sofaPermission: 'Confirm',
      sofaScope: 'Human Approval Required'
    },
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true
  })
]);

export const DEADBOLT_MCP_PERMISSION_TABLE = Object.freeze(
  DEADBOLT_MCP_TOOLS.map((tool) =>
    Object.freeze({
      name: tool.name,
      title: tool.annotations.title,
      sofaPermission:
        tool.annotations.sofaPermission || (tool.annotations.readOnlyHint ? 'Allow' : 'Confirm'),
      sofaScope: tool.annotations.sofaScope,
      readOnlyHint: tool.annotations.readOnlyHint,
      destructiveHint: tool.annotations.destructiveHint,
      idempotentHint: tool.annotations.idempotentHint,
      openWorldHint: tool.annotations.openWorldHint,
      description: tool.description
    })
  )
);

function wrapOrchestratorOutcome(toolName, outcome, fallbackSummary) {
  if (!outcome || typeof outcome !== 'object') {
    return okMcpResult(toolName, fallbackSummary, { result: outcome ?? null });
  }

  if (outcome.ok === false) {
    const errInfo = outcome.error && typeof outcome.error === 'object' ? outcome.error : {};
    return errorMcpResult(
      toolName,
      errInfo.code || 'DEADBOLT_GATE_ERROR',
      errInfo.message || outcome.summary || 'DEADBOLT governance gate rejected request.',
      errInfo.details ?? outcome.data ?? null
    );
  }

  if (outcome.ok === true && Object.hasOwn(outcome, 'data')) {
    return okMcpResult(toolName, outcome.summary || fallbackSummary, outcome.data);
  }

  return okMcpResult(toolName, outcome.summary || fallbackSummary, outcome);
}

/**
 * Create the DEADBOLT MCP server backed by @krusch/toolkit/mcp.
 *
 * @param {object} [options={}]
 * @param {object} [options.orchestrator] Deadbolt orchestrator instance.
 * @param {boolean} [options.connect=false] Connect stdio transport immediately when true.
 */
export async function createDeadboltMcp({ orchestrator, connect = false } = {}) {
  const handleToolCall = async (name, rawArgs = {}) => {
    const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};

    if (!orchestrator) {
      return errorMcpResult(
        name,
        'ORCHESTRATOR_UNAVAILABLE',
        'DEADBOLT orchestrator instance is required to execute MCP tools.'
      );
    }

    try {
      switch (name) {
        case 'deadbolt_hydrate_work_order': {
          const fn = orchestrator.hydrateWorkOrder ?? orchestrator.hydrateWorkOrderContext;
          if (typeof fn !== 'function') {
            return errorMcpResult(name, 'METHOD_NOT_FOUND', 'Orchestrator missing hydrateWorkOrder method.');
          }
          const workOrderId = typeof args.workOrderId === 'string' && args.workOrderId.trim()
            ? args.workOrderId.trim()
            : 'WO-101';
          const res = await fn.call(orchestrator, {
            workOrderId,
            ...(args.query ? { query: String(args.query) } : {}),
            tokenBudget: Number.isFinite(Number(args.tokenBudget)) ? Number(args.tokenBudget) : 4000
          });
          return wrapOrchestratorOutcome(name, res, `Hydrated organizational context for ${workOrderId}`);
        }

        case 'deadbolt_map_blast_radius': {
          const fn = orchestrator.mapBlastRadius ?? orchestrator.analyzeBlastRadius;
          if (typeof fn !== 'function') {
            return errorMcpResult(name, 'METHOD_NOT_FOUND', 'Orchestrator missing mapBlastRadius method.');
          }
          const workOrderId = typeof args.workOrderId === 'string' && args.workOrderId.trim()
            ? args.workOrderId.trim()
            : 'WO-101';
          const entryFile = typeof args.entryFile === 'string' && args.entryFile.trim()
            ? args.entryFile.trim()
            : 'src/fee-engine.js';
          const res = await fn.call(orchestrator, {
            workOrderId,
            entryFile,
            ...(args.repoDir ? { repoDir: String(args.repoDir) } : {})
          });
          return wrapOrchestratorOutcome(name, res, `Mapped 2-hop blast radius from ${entryFile}`);
        }

        case 'deadbolt_validate_reconciliation': {
          const fn = orchestrator.validateModeOrEdits ?? orchestrator.validateCandidate;
          if (typeof fn !== 'function') {
            return errorMcpResult(name, 'METHOD_NOT_FOUND', 'Orchestrator missing validateModeOrEdits method.');
          }
          const workOrderId = typeof args.workOrderId === 'string' && args.workOrderId.trim()
            ? args.workOrderId.trim()
            : 'WO-101';
          const mode = typeof args.mode === 'string' && args.mode.trim()
            ? args.mode.trim().toLowerCase()
            : 'remediated';
          if (!Array.isArray(args.edits) && !['naive', 'workaround', 'remediated'].includes(mode)) {
            return errorMcpResult(
              name,
              'INVALID_ARGUMENTS',
              `Unsupported validation mode "${mode}". Expected one of: naive, workaround, remediated.`
            );
          }
          const res = await fn.call(orchestrator, {
            workOrderId,
            mode,
            ...(Array.isArray(args.edits) ? { edits: args.edits } : {}),
            runCrossModel: args.runCrossModel !== false
          });
          return wrapOrchestratorOutcome(name, res, `Validated ${workOrderId} (${mode})`);
        }

        case 'deadbolt_verify_audit_chain': {
          const fn = orchestrator.getAuditStatus ?? orchestrator.getAuditTrail;
          if (typeof fn !== 'function') {
            return errorMcpResult(name, 'METHOD_NOT_FOUND', 'Orchestrator missing getAuditStatus method.');
          }
          const limit = Number.isFinite(Number(args.limit)) ? Number(args.limit) : 50;
          const res = await fn.call(orchestrator, { limit });
          return wrapOrchestratorOutcome(name, res, 'Verified SHA-256 cryptographic audit chain');
        }

        case 'deadbolt_apply_verified_stage': {
          const fn = orchestrator.applyVerifiedTask ?? orchestrator.applyVerifiedStage;
          if (typeof fn !== 'function') {
            return errorMcpResult(name, 'METHOD_NOT_FOUND', 'Orchestrator missing applyVerifiedTask method.');
          }
          const taskId = typeof args.taskId === 'string' ? args.taskId.trim() : '';
          if (!taskId) {
            return errorMcpResult(name, 'INVALID_ARGUMENTS', 'Required argument "taskId" must be a non-empty string.');
          }
          const workOrderId = typeof args.workOrderId === 'string' && args.workOrderId.trim()
            ? args.workOrderId.trim()
            : 'WO-101';
          const res = await fn.call(orchestrator, { taskId, workOrderId });
          return wrapOrchestratorOutcome(name, res, `Applied verified task ${taskId} for [${workOrderId}]`);
        }

        default:
          return errorMcpResult(name, 'UNKNOWN_TOOL', `Unknown DEADBOLT MCP tool: ${name}`);
      }
    } catch (err) {
      const code = err?.code ? String(err.code) : 'DEADBOLT_MCP_ERROR';
      const msg = err instanceof Error ? err.message : String(err);
      return errorMcpResult(name, code, msg);
    }
  };

  return createMcpServer('deadbolt-mcp', '0.1.0', DEADBOLT_MCP_TOOLS, handleToolCall, {
    connect,
    strictTools: true
  });
}

function isDirectCliEntrypoint(metaUrl, argvEntry) {
  if (!argvEntry) return false;
  try {
    return realpathSync(argvEntry) === realpathSync(fileURLToPath(metaUrl));
  } catch {
    return resolve(argvEntry) === resolve(fileURLToPath(metaUrl));
  }
}

const isMain = isDirectCliEntrypoint(import.meta.url, process.argv[1]);

if (isMain) {
  try {
    const orchestratorModule = await import('../orchestrator.js');
    const createOrchestrator =
      orchestratorModule.createDeadboltOrchestrator ?? orchestratorModule.default;
    if (typeof createOrchestrator !== 'function') {
      throw new Error('createDeadboltOrchestrator export not found in ../orchestrator.js');
    }
    const orchestrator = await createOrchestrator();
    await createDeadboltMcp({ orchestrator, connect: true });
  } catch (err) {
    console.error('[deadbolt-mcp] Failed to start stdio MCP server:', err?.message || err);
    process.exitCode = 1;
  }
}
