/**
 * @module engines/treesitter-ast
 * Portable WebAssembly Tree-sitter CST/AST engine (`INV-DB-TS-01`) covering all 10 DEADBOLT
 * languages and 14 enterprise source extensions with zero native C++ `.node` bindings.
 */

import { createRequire } from 'node:module';
import path from 'node:path';
import Parser from 'web-tree-sitter';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';

const require = createRequire(import.meta.url);

export const TREE_SITTER_GRAMMAR_BY_EXTENSION = Object.freeze({
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'tsx',
  '.py': 'python',
  '.php': 'php',
  '.java': 'java',
  '.cs': 'c_sharp',
  '.go': 'go',
  '.rb': 'ruby',
  '.rs': 'rust',
  '.kt': 'kotlin'
});

const ALL_GRAMMAR_NAMES = Object.freeze([
  ...new Set(Object.values(TREE_SITTER_GRAMMAR_BY_EXTENSION))
]);

let parserInstance = null;
/** @type {Map<string, import('web-tree-sitter').Language>} */
const loadedLanguages = new Map();
let runtimeReady = false;
let runtimeInitPromise = null;

function resolveGrammarWasmDir() {
  const pkgJsonPath = require.resolve('tree-sitter-wasms/package.json');
  return path.join(path.dirname(pkgJsonPath), 'out');
}

/**
 * Initialize `web-tree-sitter` and preload all 11 WebAssembly language grammars once per process.
 */
export async function initTreeSitterRuntime() {
  if (runtimeReady && parserInstance) {
    return okEnvelope(
      'deadbolt.treesitter.init',
      `Tree-sitter WASM runtime ready (${loadedLanguages.size} grammars cached).`,
      {
        ready: true,
        astEngine: 'web-tree-sitter-wasm',
        grammars: [...loadedLanguages.keys()]
      }
    );
  }

  if (!runtimeInitPromise) {
    runtimeInitPromise = (async () => {
      await Parser.init();
      const wasmDir = resolveGrammarWasmDir();
      for (const grammarName of ALL_GRAMMAR_NAMES) {
        if (!loadedLanguages.has(grammarName)) {
          const wasmPath = path.join(wasmDir, `tree-sitter-${grammarName}.wasm`);
          const lang = await Parser.Language.load(wasmPath);
          loadedLanguages.set(grammarName, lang);
        }
      }
      if (!parserInstance) {
        parserInstance = new Parser();
      }
      runtimeReady = true;
    })().catch((err) => {
      runtimeInitPromise = null;
      throw err;
    });
  }

  try {
    await runtimeInitPromise;
    return okEnvelope(
      'deadbolt.treesitter.init',
      `Initialized Tree-sitter WASM runtime across ${loadedLanguages.size} grammars.`,
      {
        ready: true,
        astEngine: 'web-tree-sitter-wasm',
        grammars: [...loadedLanguages.keys()]
      }
    );
  } catch (err) {
    return errorEnvelope(
      'TREESITTER_INIT_FAILED',
      err instanceof Error ? err.message : 'Failed to initialize Tree-sitter WASM runtime.',
      null,
      'deadbolt.treesitter.init'
    );
  }
}

/**
 * Return whether the WASM parser and all 11 language grammars are loaded in memory.
 * @returns {boolean}
 */
export function isTreeSitterReady() {
  return Boolean(runtimeReady && parserInstance && loadedLanguages.size === ALL_GRAMMAR_NAMES.length);
}

function unquoteStringText(rawText = '') {
  const text = String(rawText || '').trim();
  if (!text) return '';
  if (
    (text.startsWith('"') && text.endsWith('"')) ||
    (text.startsWith("'") && text.endsWith("'")) ||
    (text.startsWith('`') && text.endsWith('`'))
  ) {
    return text.slice(1, -1);
  }
  if (text.startsWith('r"') || text.startsWith("r'")) {
    return text.slice(2, -1);
  }
  return text;
}

function extractFirstLineSignature(node) {
  const firstLine = String(node?.text || '')
    .split(/\r?\n/, 1)[0]
    .replace(/\s*\{\s*$/, '')
    .trim();
  return firstLine.length > 180 ? `${firstLine.slice(0, 177)}...` : firstLine;
}

function findFirstNamedChildText(node, candidateTypes) {
  if (!node) return '';
  for (let i = 0; i < node.namedChildCount; i += 1) {
    const child = node.namedChild(i);
    if (child && candidateTypes.has(child.type)) {
      return String(child.text || '').trim();
    }
  }
  return '';
}

function unwrapJsExpression(node) {
  let cur = node;
  while (
    cur &&
    (cur.type === 'parenthesized_expression' ||
      cur.type === 'as_expression' ||
      cur.type === 'type_assertion' ||
      cur.type === 'satisfies_expression' ||
      cur.type === 'non_null_expression')
  ) {
    cur = cur.namedChild(0);
  }
  return cur;
}

function extractJsTargetKeyName(node) {
  const cur = unwrapJsExpression(node);
  if (!cur) return '';
  if (
    cur.type === 'identifier' ||
    cur.type === 'property_identifier' ||
    cur.type === 'shorthand_property_identifier' ||
    cur.type === 'shorthand_property_identifier_pattern'
  ) {
    return cur.text.trim();
  }
  if (cur.type === 'computed_property_name') {
    const inner = unwrapJsExpression(cur.namedChild(0));
    if (inner && (inner.type === 'string' || inner.type === 'template_string')) {
      if (inner.type === 'template_string' && inner.text.includes('${')) return '';
      return unquoteStringText(inner.text);
    }
  }
  if (cur.type === 'member_expression' || cur.type === 'subscript_expression') {
    const prop = cur.childForFieldName('property') || cur.childForFieldName('index');
    if (!prop) return '';
    if (prop.type === 'string' || prop.type === 'template_string') {
      if (prop.type === 'template_string' && prop.text.includes('${')) return '';
      return unquoteStringText(prop.text);
    }
    return prop.text.trim();
  }
  return '';
}

function isJsZeroLiteral(node) {
  const cur = unwrapJsExpression(node);
  if (!cur) return false;
  if (cur.type === 'number') {
    const raw = cur.text.replace(/_/g, '').trim();
    if (/^0n$/i.test(raw)) return true;
    const val = Number(raw);
    return Number.isFinite(val) && val === 0;
  }
  if (cur.type === 'unary_expression') {
    const op = String(cur.childForFieldName('operator')?.text || '').trim();
    const arg = cur.childForFieldName('argument') || cur.namedChild(0);
    if ((op === '+' || op === '-') && isJsZeroLiteral(arg)) {
      return true;
    }
  }
  return false;
}

function isJsTruthyStrictSox(node) {
  const cur = unwrapJsExpression(node);
  if (!cur) return false;
  if (cur.type === 'true') return true;
  if (cur.type === 'unary_expression') {
    const op = String(cur.childForFieldName('operator')?.text || '').trim();
    const arg = unwrapJsExpression(cur.childForFieldName('argument') || cur.namedChild(0));
    if (op === '!' && (arg?.type === 'false' || isJsZeroLiteral(arg))) {
      return true;
    }
  }
  return false;
}

function isJsExplicitFalsyStrictSox(node) {
  const cur = unwrapJsExpression(node);
  if (!cur) return false;
  if (
    cur.type === 'false' ||
    cur.type === 'null' ||
    cur.type === 'undefined' ||
    isJsZeroLiteral(cur)
  ) {
    return true;
  }
  if (cur.type === 'string' && unquoteStringText(cur.text) === '') {
    return true;
  }
  if (cur.type === 'unary_expression') {
    const op = String(cur.childForFieldName('operator')?.text || '').trim();
    const arg = unwrapJsExpression(cur.childForFieldName('argument') || cur.namedChild(0));
    if (op === '!' && (arg?.type === 'true' || (arg?.type === 'number' && Number(arg.text) !== 0))) {
      return true;
    }
  }
  if (cur.type === 'call_expression') {
    const fn = unwrapJsExpression(cur.childForFieldName('function'));
    const args = cur.childForFieldName('arguments');
    if (fn?.text === 'Boolean' && args) {
      if (args.namedChildCount === 0) return true;
      return isJsExplicitFalsyStrictSox(args.namedChild(0));
    }
  }
  return false;
}

function isJsNonZeroConstantExpr(node) {
  const cur = unwrapJsExpression(node);
  if (!cur) return false;
  if (isJsZeroLiteral(cur)) return false;
  if (cur.type === 'number') {
    return true;
  }
  if (cur.type === 'identifier' && (cur.text === 'Infinity' || cur.text === 'NaN')) {
    return true;
  }
  if (cur.type === 'unary_expression') {
    const arg = cur.childForFieldName('argument') || cur.namedChild(0);
    return isJsNonZeroConstantExpr(arg);
  }
  if (cur.type === 'binary_expression') {
    const left = cur.childForFieldName('left') || cur.namedChild(0);
    const right = cur.childForFieldName('right') || cur.namedChild(1);
    return isJsNonZeroConstantExpr(left) || isJsNonZeroConstantExpr(right);
  }
  return false;
}

const IDENT_TYPES = new Set([
  'identifier',
  'type_identifier',
  'simple_identifier',
  'property_identifier',
  'field_identifier',
  'constant',
  'name'
]);

const COMMENT_OR_STRING_TYPES = new Set([
  'comment',
  'line_comment',
  'block_comment',
  'multiline_comment',
  'string',
  'string_literal',
  'interpreted_string_literal',
  'raw_string_literal',
  'encapsed_string',
  'template_string',
  'verbatim_string_literal',
  'interpolated_string_expression',
  'line_string_literal',
  'multi_line_string_literal'
]);

/**
 * Parse `sourceText` using the cached WebAssembly Tree-sitter grammar for `filePath`
 * and extract deterministic CST symbols, imports, calls, identifiers, syntax errors,
 * and SOX policy-floor AST checks.
 *
 * @param {string} sourceText
 * @param {string} filePath
 */
export function analyzeFileWithTreeSitter(sourceText = '', filePath = '') {
  const ext = path.extname(String(filePath || '')).toLowerCase();
  const language = TREE_SITTER_GRAMMAR_BY_EXTENSION[ext] || null;

  if (!language) {
    return okEnvelope(
      'deadbolt.treesitter.analyze',
      `Extension "${ext || '(none)'}" is not mapped to a Tree-sitter grammar.`,
      {
        supported: false,
        astEngine: 'web-tree-sitter-wasm',
        language: null,
        hasSyntaxError: false,
        syntaxErrors: [],
        packageName: '',
        namespaces: [],
        symbols: [],
        imports: [],
        calls: [],
        identifiers: [],
        soxViolations: []
      }
    );
  }

  const langObj = loadedLanguages.get(language);
  if (!runtimeReady || !parserInstance || !langObj) {
    return errorEnvelope(
      'TREESITTER_NOT_INITIALIZED',
      'Tree-sitter WASM runtime has not been initialized yet. Call await initTreeSitterRuntime() first.',
      { language, filePath },
      'deadbolt.treesitter.analyze'
    );
  }

  const src = String(sourceText ?? '');
  parserInstance.setLanguage(langObj);
  const tree = parserInstance.parse(src);

  try {
    const root = tree.rootNode;
    const hasSyntaxError = Boolean(root.hasError);
    const syntaxErrors = [];
    const symbols = [];
    const seenSymbols = new Set();
    const imports = [];
    const seenImports = new Set();
    const callsSet = new Set();
    const identSet = new Set();
    const namespaces = [];
    const soxViolations = [];
    let packageName = '';

    const isJsFamily =
      language === 'javascript' || language === 'typescript' || language === 'tsx';

    const pushSymbol = (rawName, symbolType, node) => {
      const cleanName = String(rawName || '').trim();
      if (!cleanName || seenSymbols.has(`${symbolType}:${cleanName}:${node.startPosition.row}`)) {
        return;
      }
      seenSymbols.add(`${symbolType}:${cleanName}:${node.startPosition.row}`);
      symbols.push({
        symbol_name: cleanName,
        symbol_type: symbolType,
        start_line: node.startPosition.row + 1,
        end_line: node.endPosition.row + 1,
        signature: extractFirstLineSignature(node)
      });
    };

    const pushImport = (specifier, kind, importedNames = []) => {
      const cleanSpec = String(specifier || '').trim();
      if (!cleanSpec && importedNames.length === 0) return;
      const key = `${kind}:${cleanSpec}:${importedNames.join(',')}`;
      if (seenImports.has(key)) return;
      seenImports.add(key);
      imports.push({
        specifier: cleanSpec,
        kind,
        importedNames
      });
    };

    const pushSoxViolation = (reason, node) => {
      const line = node ? node.startPosition.row + 1 : 1;
      if (!soxViolations.some((v) => v.line === line && v.reason === reason)) {
        soxViolations.push({
          ruleId: 'FLOOR-SOX-TOLERANCE-BYPASS',
          line,
          reason
        });
      }
    };

    const checkJsBindingViolation = (keyNode, valNode, contextNode) => {
      const keyName = extractJsTargetKeyName(keyNode);
      if (!keyName || !valNode) return;
      if (keyName === 'strictSox') {
        if (isJsExplicitFalsyStrictSox(valNode) || (!isJsTruthyStrictSox(valNode) && valNode.type === 'number')) {
          pushSoxViolation(
            'Tree-sitter CST detected disabling strictSox enforcement.',
            contextNode
          );
        }
      } else if (
        keyName === 'MAX_TOLERANCE_CENTS' ||
        keyName === 'toleranceCents'
      ) {
        if (isJsNonZeroConstantExpr(valNode)) {
          pushSoxViolation(
            `Tree-sitter CST detected widening ${keyName} above zero.`,
            contextNode
          );
        }
      }
    };

    const walk = (node, insideClass = false, insideHeader = false) => {
      if (!node) return;
      const type = node.type;

      if ((type === 'ERROR' || node.isMissing) && syntaxErrors.length < 8) {
        const snippet = String(node.text || '')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 80);
        syntaxErrors.push({
          line: node.startPosition.row + 1,
          column: node.startPosition.column + 1,
          snippet
        });
      }

      if (COMMENT_OR_STRING_TYPES.has(type)) {
        return;
      }

      if (!insideHeader && IDENT_TYPES.has(type) && identSet.size < 2000) {
        const txt = node.text.trim();
        if (txt) identSet.add(txt);
      }

      let nextInsideClass = insideClass;
      let nextInsideHeader = insideHeader;

      // Language-specific CST declarations & imports
      if (isJsFamily) {
        if (
          type === 'function_declaration' ||
          type === 'generator_function_declaration'
        ) {
          const name = node.childForFieldName('name')?.text;
          pushSymbol(name, 'function', node);
        } else if (type === 'class_declaration') {
          const name = node.childForFieldName('name')?.text;
          pushSymbol(name, 'class', node);
          nextInsideClass = true;
        } else if (type === 'method_definition' || type === 'method_signature') {
          const name = node.childForFieldName('name')?.text;
          if (name && name !== 'constructor') {
            pushSymbol(name, 'method', node);
          }
        } else if (type === 'interface_declaration') {
          pushSymbol(node.childForFieldName('name')?.text, 'interface', node);
        } else if (type === 'type_alias_declaration') {
          pushSymbol(node.childForFieldName('name')?.text, 'type', node);
        } else if (type === 'enum_declaration') {
          pushSymbol(node.childForFieldName('name')?.text, 'enum', node);
        } else if (type === 'variable_declarator') {
          const nameNode = node.childForFieldName('name');
          const valueNode = node.childForFieldName('value');
          if (
            nameNode?.type === 'identifier' &&
            valueNode &&
            (valueNode.type === 'arrow_function' || valueNode.type === 'function_expression')
          ) {
            pushSymbol(nameNode.text, 'function', node);
          }
          checkJsBindingViolation(nameNode, valueNode, node);
        } else if (type === 'assignment_expression' || type === 'augmented_assignment_expression') {
          const leftNode = node.childForFieldName('left');
          const rightNode = node.childForFieldName('right');
          if (type === 'augmented_assignment_expression') {
            const leftKey = extractJsTargetKeyName(leftNode);
            if (
              (leftKey === 'MAX_TOLERANCE_CENTS' || leftKey === 'toleranceCents') &&
              isJsNonZeroConstantExpr(rightNode)
            ) {
              pushSoxViolation(`Tree-sitter CST detected mutating ${leftKey} above zero.`, node);
            }
          } else {
            checkJsBindingViolation(leftNode, rightNode, node);
          }
        } else if (type === 'pair') {
          checkJsBindingViolation(
            node.childForFieldName('key'),
            node.childForFieldName('value'),
            node
          );
        } else if (type === 'binary_expression') {
          const op = String(node.childForFieldName('operator')?.text || '').trim();
          const left = node.childForFieldName('left');
          const right = node.childForFieldName('right');
          const leftKey = extractJsTargetKeyName(left);
          if (
            (leftKey === 'toleranceCents' || leftKey === 'MAX_TOLERANCE_CENTS') &&
            (op === '>' || op === '>=') &&
            isJsNonZeroConstantExpr(right)
          ) {
            pushSoxViolation(
              `Tree-sitter CST detected non-zero tolerance threshold on ${leftKey}.`,
              node
            );
          }
        } else if (type === 'import_statement' || type === 'export_statement') {
          const srcNode = node.childForFieldName('source');
          if (srcNode) {
            pushImport(unquoteStringText(srcNode.text), 'import');
          }
          nextInsideHeader = type === 'import_statement';
        } else if (type === 'call_expression' || type === 'new_expression') {
          const fnNode = node.childForFieldName('function') || node.childForFieldName('constructor');
          const fnText = fnNode?.text?.trim() || '';
          if (fnNode?.type === 'identifier') {
            callsSet.add(fnText);
          } else if (fnNode?.type === 'member_expression') {
            const prop = fnNode.childForFieldName('property')?.text?.trim();
            if (prop) callsSet.add(prop);
          }
          if (type === 'call_expression' && (fnText === 'require' || fnNode?.type === 'import')) {
            const args = node.childForFieldName('arguments');
            const firstArg = args?.namedChild(0);
            if (
              firstArg &&
              (firstArg.type === 'string' ||
                (firstArg.type === 'template_string' && !firstArg.text.includes('${')))
            ) {
              pushImport(
                unquoteStringText(firstArg.text),
                fnText === 'require' ? 'require' : 'dynamic_import'
              );
            }
          }
        }
      } else if (language === 'python') {
        if (type === 'class_definition') {
          pushSymbol(node.childForFieldName('name')?.text, 'class', node);
          nextInsideClass = true;
        } else if (type === 'function_definition') {
          pushSymbol(
            node.childForFieldName('name')?.text,
            insideClass ? 'method' : 'function',
            node
          );
        } else if (type === 'import_statement') {
          nextInsideHeader = true;
          for (let i = 0; i < node.namedChildCount; i += 1) {
            const child = node.namedChild(i);
            if (child?.type === 'dotted_name') {
              pushImport(child.text.trim(), 'import');
            } else if (child?.type === 'aliased_import') {
              const target = child.childForFieldName('name')?.text?.trim();
              if (target) pushImport(target, 'import');
            }
          }
        } else if (type === 'import_from_statement') {
          nextInsideHeader = true;
          const modNode = node.childForFieldName('module_name');
          let modSpec = modNode ? modNode.text.trim() : '';
          if (!modSpec) {
            const relChild = findFirstNamedChildText(node, new Set(['relative_import']));
            if (relChild) modSpec = relChild;
          }
          const importedNames = [];
          for (let i = 0; i < node.namedChildCount; i += 1) {
            const child = node.namedChild(i);
            if (!child || child === modNode || child.type === 'relative_import') continue;
            if (child.type === 'dotted_name' || child.type === 'identifier') {
              importedNames.push(child.text.trim());
            } else if (child.type === 'aliased_import') {
              const orig = child.childForFieldName('name')?.text?.trim();
              if (orig) importedNames.push(orig);
            } else if (child.type === 'wildcard_import') {
              importedNames.push('*');
            }
          }
          pushImport(modSpec, 'from_import', importedNames);
        } else if (type === 'call') {
          const fnNode = node.childForFieldName('function');
          if (fnNode?.type === 'identifier') {
            callsSet.add(fnNode.text.trim());
          } else if (fnNode?.type === 'attribute') {
            const attr = fnNode.childForFieldName('attribute')?.text?.trim();
            if (attr) callsSet.add(attr);
          }
        }
      } else if (language === 'php') {
        if (type === 'namespace_definition') {
          const nsName = node.childForFieldName('name')?.text?.trim() || '';
          if (nsName) {
            packageName = nsName;
            pushSymbol(nsName, 'namespace', node);
          }
        } else if (
          type === 'class_declaration' ||
          type === 'interface_declaration' ||
          type === 'trait_declaration' ||
          type === 'enum_declaration'
        ) {
          const kind = type.replace('_declaration', '');
          pushSymbol(node.childForFieldName('name')?.text, kind, node);
          nextInsideClass = true;
        } else if (type === 'function_definition' || type === 'method_declaration') {
          pushSymbol(
            node.childForFieldName('name')?.text,
            type === 'method_declaration' ? 'method' : 'function',
            node
          );
        } else if (
          type === 'include_expression' ||
          type === 'include_once_expression' ||
          type === 'require_expression' ||
          type === 'require_once_expression'
        ) {
          const rawExpr = node.text || '';
          for (const m of rawExpr.matchAll(/['"]([^'"]+\.php)(?:\?[^'"]*)?['"]/gi)) {
            if (m[1]) pushImport(m[1], 'requires');
          }
        } else if (type === 'namespace_use_declaration') {
          nextInsideHeader = true;
          for (let i = 0; i < node.namedChildCount; i += 1) {
            const clause = node.namedChild(i);
            if (clause) {
              const qn = clause.text.split(/\s+as\s+/i)[0].trim().replace(/^\\+/, '');
              if (qn) pushImport(qn, 'use');
            }
          }
        } else if (type === 'text') {
          const htmlChunk = node.text || '';
          for (const m of htmlChunk.matchAll(/\b(?:href|action)\s*=\s*['"]([^'"]*?\.php)(?:\?[^'"]*)?['"]/gi)) {
            if (m[1]) pushImport(m[1], 'links');
          }
        } else if (
          type === 'function_call_expression' ||
          type === 'scoped_call_expression' ||
          type === 'object_creation_expression'
        ) {
          const target =
            node.childForFieldName('function') ||
            node.childForFieldName('name') ||
            node.namedChild(0);
          if (target) {
            const cleanTarget = target.text.trim().replace(/^\\+/, '');
            if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(cleanTarget)) {
              callsSet.add(cleanTarget);
            }
          }
        }
      } else if (language === 'go') {
        if (type === 'package_clause') {
          packageName = findFirstNamedChildText(node, new Set(['package_identifier']));
          nextInsideHeader = true;
        } else if (type === 'import_spec') {
          nextInsideHeader = true;
          const pathNode =
            node.childForFieldName('path') ||
            node.namedChildren.find((c) => c.type.includes('string_literal'));
          if (pathNode) {
            pushImport(unquoteStringText(pathNode.text), 'import');
          }
        } else if (type === 'type_spec') {
          const name = node.childForFieldName('name')?.text;
          const typeDef = node.childForFieldName('type');
          const kind =
            typeDef?.type === 'struct_type'
              ? 'struct'
              : typeDef?.type === 'interface_type'
                ? 'interface'
                : 'type';
          pushSymbol(name, kind, node);
        } else if (type === 'function_declaration' || type === 'method_declaration') {
          const name = node.childForFieldName('name')?.text;
          pushSymbol(name, type === 'method_declaration' ? 'method' : 'function', node);
        } else if (type === 'call_expression') {
          const fnNode = node.childForFieldName('function');
          if (fnNode?.type === 'identifier') {
            callsSet.add(fnNode.text.trim());
          } else if (fnNode?.type === 'selector_expression') {
            const field = fnNode.childForFieldName('field')?.text?.trim();
            if (field) callsSet.add(field);
          }
        }
      } else if (language === 'rust') {
        if (type === 'mod_item') {
          const modName = node.childForFieldName('name')?.text?.trim();
          const hasInlineBody = Boolean(node.childForFieldName('body'));
          if (modName) {
            pushSymbol(modName, 'module', node);
            if (!hasInlineBody) {
              pushImport(modName, 'mod');
            }
          }
        } else if (type === 'use_declaration') {
          nextInsideHeader = true;
          const argNode = node.childForFieldName('argument') || node.namedChild(0);
          if (argNode) {
            const rawUse = argNode.type === 'visibility_modifier'
              ? node.namedChild(1)?.text
              : argNode.text;
            if (rawUse) pushImport(rawUse.trim(), 'use');
          }
        } else if (
          type === 'struct_item' ||
          type === 'enum_item' ||
          type === 'trait_item'
        ) {
          const kind = type.replace('_item', '');
          pushSymbol(node.childForFieldName('name')?.text, kind, node);
        } else if (type === 'function_item' || type === 'function_signature_item') {
          pushSymbol(node.childForFieldName('name')?.text, 'function', node);
        } else if (type === 'call_expression') {
          const fnNode = node.childForFieldName('function');
          if (fnNode?.type === 'identifier') {
            callsSet.add(fnNode.text.trim());
          } else if (fnNode?.type === 'scoped_identifier') {
            const name = fnNode.childForFieldName('name')?.text?.trim();
            if (name) callsSet.add(name);
          }
        }
      } else if (language === 'java') {
        if (type === 'package_declaration') {
          nextInsideHeader = true;
          const pkgNode = node.namedChildren.find(
            (c) => c.type === 'scoped_identifier' || c.type === 'identifier'
          );
          if (pkgNode) packageName = pkgNode.text.trim();
        } else if (type === 'import_declaration') {
          nextInsideHeader = true;
          const targetNode = node.namedChildren.find(
            (c) => c.type === 'scoped_identifier' || c.type === 'identifier'
          );
          const hasWildcard = node.namedChildren.some((c) => c.type === 'asterisk');
          if (targetNode) {
            pushImport(
              hasWildcard ? `${targetNode.text.trim()}.*` : targetNode.text.trim(),
              'import'
            );
          }
        } else if (
          type === 'class_declaration' ||
          type === 'interface_declaration' ||
          type === 'enum_declaration' ||
          type === 'record_declaration'
        ) {
          const kind = type.replace('_declaration', '');
          pushSymbol(node.childForFieldName('name')?.text, kind, node);
          nextInsideClass = true;
        } else if (type === 'method_declaration') {
          pushSymbol(node.childForFieldName('name')?.text, 'function', node);
        } else if (type === 'method_invocation') {
          const name = node.childForFieldName('name')?.text?.trim();
          if (name) callsSet.add(name);
        }
      } else if (language === 'kotlin') {
        if (type === 'package_header') {
          nextInsideHeader = true;
          const idNode = findFirstNamedChildText(node, new Set(['identifier']));
          if (idNode) packageName = idNode.replace(/\s+/g, '');
        } else if (type === 'import_header') {
          nextInsideHeader = true;
          const idNode = findFirstNamedChildText(node, new Set(['identifier']));
          const hasWildcard =
            node.namedChildren.some((c) => c.type === 'wildcard_import') ||
            /\.\*\s*$/.test(node.text);
          if (idNode) {
            const cleanId = idNode.replace(/\s+/g, '');
            pushImport(hasWildcard ? `${cleanId}.*` : cleanId, 'import');
          }
        } else if (type === 'class_declaration' || type === 'object_declaration') {
          const name = findFirstNamedChildText(
            node,
            new Set(['type_identifier', 'simple_identifier'])
          );
          const isIface = /^\s*(?:public\s+|internal\s+)?(?:fun\s+)?interface\b/.test(node.text);
          pushSymbol(
            name,
            type === 'object_declaration' ? 'object' : isIface ? 'interface' : 'class',
            node
          );
          nextInsideClass = true;
        } else if (type === 'function_declaration') {
          const name = findFirstNamedChildText(node, new Set(['simple_identifier']));
          pushSymbol(name, 'function', node);
        } else if (type === 'call_expression') {
          const callee = node.namedChild(0);
          if (callee?.type === 'simple_identifier') {
            callsSet.add(callee.text.trim());
          } else if (callee?.type === 'navigation_expression') {
            const suffix = callee.namedChildren.find((c) => c.type === 'navigation_suffix');
            const methodId = findFirstNamedChildText(suffix, new Set(['simple_identifier']));
            if (methodId) callsSet.add(methodId);
          }
        }
      } else if (language === 'c_sharp') {
        if (
          type === 'namespace_declaration' ||
          type === 'file_scoped_namespace_declaration'
        ) {
          const ns = node.childForFieldName('name')?.text?.replace(/\s+/g, '') || '';
          if (ns && !namespaces.includes(ns)) {
            namespaces.push(ns);
          }
        } else if (type === 'using_directive') {
          nextInsideHeader = true;
          const rawUsing = node.text
            .replace(/^\s*global\s+/i, '')
            .replace(/^\s*using\s+/i, '')
            .replace(/^\s*static\s+/i, '')
            .replace(/;\s*$/, '')
            .trim();
          const rhs = rawUsing.includes('=')
            ? rawUsing.split('=').slice(1).join('=').trim()
            : rawUsing;
          if (rhs && !/\s/.test(rhs)) {
            pushImport(rhs, 'using');
          }
        } else if (
          type === 'class_declaration' ||
          type === 'interface_declaration' ||
          type === 'struct_declaration' ||
          type === 'record_declaration' ||
          type === 'enum_declaration'
        ) {
          const kind = type.replace('_declaration', '');
          pushSymbol(node.childForFieldName('name')?.text, kind, node);
          nextInsideClass = true;
        } else if (type === 'method_declaration') {
          pushSymbol(node.childForFieldName('name')?.text, 'function', node);
        } else if (type === 'invocation_expression') {
          const fnNode = node.childForFieldName('function');
          if (fnNode?.type === 'identifier') {
            callsSet.add(fnNode.text.trim());
          } else if (fnNode?.type === 'member_access_expression') {
            const name = fnNode.childForFieldName('name')?.text?.trim();
            if (name) callsSet.add(name);
          }
        }
      } else if (language === 'ruby') {
        if (type === 'module' || type === 'class') {
          const nameNode =
            node.childForFieldName('name') ||
            node.namedChildren.find((c) => c.type === 'constant' || c.type === 'scope_resolution');
          pushSymbol(nameNode?.text, type, node);
          if (type === 'class') nextInsideClass = true;
        } else if (type === 'method' || type === 'singleton_method') {
          const nameNode = node.childForFieldName('name');
          pushSymbol(nameNode?.text, 'function', node);
        } else if (type === 'call') {
          const methodNode = node.childForFieldName('method');
          const methodName = methodNode?.text?.trim() || '';
          if (methodName) callsSet.add(methodName);
          if (methodName === 'require' || methodName === 'require_relative') {
            const args = node.childForFieldName('arguments');
            const firstArg = args?.namedChild(0);
            if (firstArg && firstArg.type === 'string') {
              const contentNode = firstArg.namedChildren.find((c) => c.type === 'string_content');
              const spec = contentNode ? contentNode.text : unquoteStringText(firstArg.text);
              if (spec) pushImport(spec, methodName);
            }
          }
        }
      }

      if (hasSyntaxError && syntaxErrors.length < 8) {
        for (let i = 0; i < node.childCount; i += 1) {
          const rawChild = node.child(i);
          if (rawChild && !rawChild.isNamed && (rawChild.type === 'ERROR' || rawChild.isMissing)) {
            if (syntaxErrors.length < 8) {
              syntaxErrors.push({
                line: rawChild.startPosition.row + 1,
                column: rawChild.startPosition.column + 1,
                snippet: String(rawChild.text || rawChild.type || '')
                  .replace(/\s+/g, ' ')
                  .trim()
                  .slice(0, 80)
              });
            }
          }
        }
      }

      for (let i = 0; i < node.namedChildCount; i += 1) {
        walk(node.namedChild(i), nextInsideClass, nextInsideHeader);
      }
    };

    walk(root, false, false);

    return okEnvelope(
      'deadbolt.treesitter.analyze',
      `Parsed ${filePath || language} with Tree-sitter WASM (${symbols.length} symbol(s), ${imports.length} import(s)).`,
      {
        supported: true,
        astEngine: 'web-tree-sitter-wasm',
        language,
        hasSyntaxError,
        syntaxErrors,
        packageName,
        namespaces,
        symbols,
        imports,
        calls: [...callsSet],
        identifiers: [...identSet],
        soxViolations
      }
    );
  } finally {
    tree.delete();
  }
}
