'use strict';
// Pure offline parser and static safety analyzer for Claude Code settings.json files.
// Zero network calls, zero shell execution, zero external dependencies.

const SECRET_KEY_RE = /(secret|token|key|password|passwd|pwd|auth|credential|bearer|private)/i;
const SECRET_VAL_PATTERNS = [
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Anthropic API Key', re: /\bsk-ant-[A-Za-z0-9_-]{12,}\b/ },
  { name: 'OpenAI API Key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'GitHub Token', re: /\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: 'Stripe Live Key', re: /\bsk_live_[0-9A-Za-z]{16,}\b/ },
  { name: 'Slack Token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Bearer Token', re: /\bBearer\s+[A-Za-z0-9._-]{16,}/i },
  { name: 'Database URI with password', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:[^@\s]+@/i },
];

const DANGEROUS_HOOK_PATTERNS = [
  { label: 'rm -rf command', severity: 'error', re: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r/i },
  { label: 'curl piped to shell', severity: 'error', re: /\bcurl\b[^|\n]*\|\s*(?:ba|z|da)?sh\b/i },
  { label: 'wget piped to shell', severity: 'error', re: /\bwget\b[^|\n]*\|\s*(?:ba|z|da)?sh\b/i },
  { label: 'shell eval execution', severity: 'warning', re: /\beval\s+["'$`]/i },
  { label: 'chmod 777 permission', severity: 'warning', re: /\bchmod\s+(?:-R\s+)?0?777\b/i },
  { label: 'reverse shell /dev/tcp or netcat', severity: 'error', re: /\/dev\/tcp\/|\bnc\s+-[a-zA-Z]*e\b/i },
];

function stripJsonComments(text) {
  let out = '';
  let inStr = false;
  let esc = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    const next = text[i + 1];
    if (inStr) {
      out += ch;
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out.replace(/,\s*([}\]])/g, '$1');
}

function maskValue(val) {
  const s = String(val == null ? '' : val);
  if (!s) return '(empty)';
  if (s.length <= 6) return '***';
  return `${s.slice(0, 3)}***${s.slice(-2)} (${s.length} chars)`;
}

function detectSecretInString(str) {
  const s = String(str || '');
  for (const p of SECRET_VAL_PATTERNS) {
    if (p.re.test(s)) return p.name;
  }
  return null;
}

function parseRuleString(raw) {
  const s = String(raw || '').trim();
  const m = s.match(/^([A-Za-z0-9_.*:-]+)\(([\s\S]*)\)$/);
  if (m) return { raw: s, tool: m[1], pattern: m[2].trim() };
  return { raw: s, tool: s || '(empty)', pattern: '*' };
}

function evaluateRuleRisk(decision, tool, pattern) {
  const findings = [];
  if (decision === 'allow') {
    const t = tool.toLowerCase();
    const p = pattern.trim();
    if (t === 'bash' && (p === '*' || p === '' || p === ':*' || p === '**')) {
      findings.push({ severity: 'error', category: 'Permission', finding: 'Unrestricted Bash(*) allow rule permits arbitrary shell execution.' });
    } else if (t === 'bash' && /^(?:sudo|rm|chmod|chown|curl|wget|dd|mkfs)\b/i.test(p)) {
      findings.push({ severity: 'error', category: 'Permission', finding: `Broad Bash allow rule "${tool}(${pattern})" grants destructive or privileged command access.` });
    } else if (t === '*' || t === 'mcp__*' || p === '**') {
      findings.push({ severity: 'warning', category: 'Permission', finding: `Wildcard allow rule "${tool}(${pattern})" grants wide tool access.` });
    }
  }
  return findings;
}

function normalizeHooks(hooksObj) {
  const hooks = [];
  if (!hooksObj || typeof hooksObj !== 'object') return hooks;
  let idx = 0;
  for (const [event, entries] of Object.entries(hooksObj)) {
    const list = Array.isArray(entries) ? entries : [entries];
    for (const entry of list) {
      if (!entry || typeof entry !== 'object') continue;
      const matcher = entry.matcher != null ? String(entry.matcher) : '*';
      const inner = Array.isArray(entry.hooks) ? entry.hooks : (entry.command || entry.prompt ? [entry] : []);
      for (const h of inner) {
        if (!h || typeof h !== 'object') continue;
        idx += 1;
        const type = String(h.type || 'command');
        const command = String(h.command || h.prompt || '');
        const timeout = h.timeout != null ? Number(h.timeout) : null;
        const hFindings = [];
        for (const dp of DANGEROUS_HOOK_PATTERNS) {
          if (dp.re.test(command)) {
            hFindings.push({ severity: dp.severity, category: 'Hook Safety', finding: `${event} hook (${matcher}) contains ${dp.label}.` });
          }
        }
        const secretHit = detectSecretInString(command);
        if (secretHit) {
          hFindings.push({ severity: 'error', category: 'Secret', finding: `${event} hook (${matcher}) embeds a plaintext ${secretHit}.` });
        }
        const status = hFindings.some((f) => f.severity === 'error')
          ? 'error'
          : (hFindings.some((f) => f.severity === 'warning') ? 'warning' : 'ok');
        hooks.push({
          index: idx,
          event,
          matcher,
          type,
          command,
          timeout,
          status,
          findings: hFindings,
        });
      }
    }
  }
  return hooks;
}

function parseClaudeSettings(input, fileName = 'settings.json') {
  const rawText = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  if (!rawText.trim()) throw new Error('File is empty.');
  let data;
  try {
    data = JSON.parse(stripJsonComments(rawText));
  } catch (e) {
    throw new Error(`Invalid JSON in ${fileName}: ${e.message}`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(`Expected a JSON object at the root of ${fileName}.`);
  }

  const perms = (data.permissions && typeof data.permissions === 'object') ? data.permissions : {};
  const rules = [];
  const findings = [];
  const allowSet = new Set();
  const denySet = new Set();

  let ruleIdx = 0;
  for (const decision of ['allow', 'deny', 'ask']) {
    const arr = Array.isArray(perms[decision]) ? perms[decision] : [];
    for (const item of arr) {
      ruleIdx += 1;
      const parsed = parseRuleString(item);
      if (decision === 'allow') allowSet.add(parsed.raw);
      if (decision === 'deny') denySet.add(parsed.raw);
      const rFindings = evaluateRuleRisk(decision, parsed.tool, parsed.pattern);
      for (const f of rFindings) findings.push({ ...f, target: `${decision}:${parsed.raw}` });
      const status = rFindings.some((f) => f.severity === 'error')
        ? 'error'
        : (rFindings.some((f) => f.severity === 'warning') ? 'warning' : 'ok');
      rules.push({
        index: ruleIdx,
        decision,
        tool: parsed.tool,
        pattern: parsed.pattern,
        raw: parsed.raw,
        status,
        errorCount: rFindings.filter((f) => f.severity === 'error').length,
        warningCount: rFindings.filter((f) => f.severity === 'warning').length,
        findings: rFindings,
      });
    }
  }

  for (const r of allowSet) {
    if (denySet.has(r)) {
      findings.push({ severity: 'warning', category: 'Conflict', target: r, finding: `Rule "${r}" appears in both permissions.allow and permissions.deny.` });
    }
  }

  if (perms.defaultMode === 'bypassPermissions') {
    findings.push({ severity: 'error', category: 'Permission', target: 'permissions.defaultMode', finding: 'permissions.defaultMode is set to "bypassPermissions", disabling confirmation prompts.' });
  }

  if (allowSet.size > 0 && denySet.size === 0) {
    findings.push({ severity: 'warning', category: 'Hardening', target: 'permissions.deny', finding: 'No permissions.deny rules configured (consider denying Read(.env*) or destructive commands).' });
  }

  const hooks = normalizeHooks(data.hooks);
  for (const h of hooks) {
    for (const f of h.findings) findings.push({ ...f, target: `${h.event}[${h.matcher}]` });
  }

  const envObj = (data.env && typeof data.env === 'object' && !Array.isArray(data.env)) ? data.env : {};
  const envVars = [];
  for (const [k, v] of Object.entries(envObj)) {
    const val = String(v == null ? '' : v);
    const secretHit = detectSecretInString(val);
    const looksSecret = Boolean(secretHit) || SECRET_KEY_RE.test(k);
    const isPlaintextSecret = Boolean(secretHit) || (looksSecret && val.length >= 12 && !/^\$\{?[A-Z0-9_]+\}?$/.test(val) && !/^<.*>$/.test(val) && !/^changeme|placeholder|example/i.test(val));
    if (isPlaintextSecret) {
      findings.push({
        severity: 'error',
        category: 'Secret',
        target: `env.${k}`,
        finding: `Environment variable "${k}" contains a ${secretHit || 'plaintext secret value'} in settings JSON.`,
      });
    }
    envVars.push({
      key: k,
      masked: looksSecret ? maskValue(val) : val,
      value: val,
      isSecret: looksSecret,
      secretType: secretHit || (isPlaintextSecret ? 'High-risk credential' : ''),
      status: isPlaintextSecret ? 'error' : 'ok',
    });
  }

  const errorCount = findings.filter((f) => f.severity === 'error').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const topKeys = Object.keys(data);

  return {
    fileName,
    model: typeof data.model === 'string' ? data.model : '',
    defaultMode: typeof perms.defaultMode === 'string' ? perms.defaultMode : 'default',
    topKeys,
    rules,
    hooks,
    envVars,
    findings,
    rawJson: JSON.stringify(data, null, 2),
    stats: {
      ruleCount: rules.length,
      allowCount: rules.filter((r) => r.decision === 'allow').length,
      denyCount: rules.filter((r) => r.decision === 'deny').length,
      askCount: rules.filter((r) => r.decision === 'ask').length,
      hookCount: hooks.length,
      envCount: envVars.length,
      secretEnvCount: envVars.filter((e) => e.isSecret).length,
      errorCount,
      warningCount,
    },
  };
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildPolicyAuditMarkdown(entries) {
  const lines = [
    '# Claude Code Settings & Hooks Safety Audit',
    '',
    `Generated offline across **${entries.length}** settings file(s). Secret values are masked.`,
    '',
    '| File | Rules (Allow/Deny) | Hooks | Env Vars | Errors | Warnings |',
    '| --- | --- | ---: | ---: | ---: | ---: |',
  ];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const { fileName, parsed } of entries) {
    totalErrors += parsed.stats.errorCount;
    totalWarnings += parsed.stats.warningCount;
    lines.push(`| ${fileName} | ${parsed.stats.allowCount} / ${parsed.stats.denyCount} | ${parsed.stats.hookCount} | ${parsed.stats.envCount} | ${parsed.stats.errorCount} | ${parsed.stats.warningCount} |`);
  }
  lines.push('', `**Total findings:** ${totalErrors} error(s), ${totalWarnings} warning(s).`, '');
  for (const { fileName, parsed } of entries) {
    lines.push(`## ${fileName}`, '');
    if (!parsed.findings.length) {
      lines.push('No safety or permission issues detected.', '');
      continue;
    }
    lines.push('| Severity | Category | Target | Finding |', '| --- | --- | --- | --- |');
    for (const f of parsed.findings) {
      lines.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.target}\` | ${f.finding} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function buildConfigDiffMarkdown(leftName, left, rightName, right) {
  const lines = [
    '# Claude Settings Comparison',
    '',
    `- **Baseline:** \`${leftName}\` (${left.stats.ruleCount} rules, ${left.stats.hookCount} hooks, ${left.stats.errorCount} errors)`,
    `- **Target:** \`${rightName}\` (${right.stats.ruleCount} rules, ${right.stats.hookCount} hooks, ${right.stats.errorCount} errors)`,
    '',
    '## Permission Rule Deltas',
    '',
    '| Rule | Decision | Change |',
    '| --- | --- | --- |',
  ];
  const leftRules = new Map(left.rules.map((r) => [`${r.decision}:${r.raw}`, r]));
  const rightRules = new Map(right.rules.map((r) => [`${r.decision}:${r.raw}`, r]));
  let ruleChanges = 0;
  for (const [k, r] of rightRules) {
    if (!leftRules.has(k)) { lines.push(`| \`${r.raw}\` | ${r.decision} | Added |`); ruleChanges += 1; }
  }
  for (const [k, r] of leftRules) {
    if (!rightRules.has(k)) { lines.push(`| \`${r.raw}\` | ${r.decision} | Removed |`); ruleChanges += 1; }
  }
  if (!ruleChanges) lines.push('| (none) | - | Identical permission rules |');

  lines.push('', '## Hook Deltas', '', '| Event | Matcher | Change | Command |', '| --- | --- | --- | --- |');
  const hookKey = (h) => `${h.event}|${h.matcher}|${h.command}`;
  const leftHooks = new Map(left.hooks.map((h) => [hookKey(h), h]));
  const rightHooks = new Map(right.hooks.map((h) => [hookKey(h), h]));
  let hookChanges = 0;
  for (const [k, h] of rightHooks) {
    if (!leftHooks.has(k)) { lines.push(`| ${h.event} | \`${h.matcher}\` | Added | \`${h.command.replace(/\|/g, '\\|')}\` |`); hookChanges += 1; }
  }
  for (const [k, h] of leftHooks) {
    if (!rightHooks.has(k)) { lines.push(`| ${h.event} | \`${h.matcher}\` | Removed | \`${h.command.replace(/\|/g, '\\|')}\` |`); hookChanges += 1; }
  }
  if (!hookChanges) lines.push('| (none) | - | Identical hooks | - |');

  lines.push('', '## Environment Key Deltas (Values Masked)', '', '| Key | Baseline | Target | Status |', '| --- | --- | --- | --- |');
  const leftEnv = new Map(left.envVars.map((e) => [e.key, e]));
  const rightEnv = new Map(right.envVars.map((e) => [e.key, e]));
  const allEnv = [...new Set([...leftEnv.keys(), ...rightEnv.keys()])].sort();
  let envChanges = 0;
  for (const k of allEnv) {
    const a = leftEnv.get(k);
    const b = rightEnv.get(k);
    if (!a) { lines.push(`| \`${k}\` | (missing) | \`${b.masked}\` | Added |`); envChanges += 1; }
    else if (!b) { lines.push(`| \`${k}\` | \`${a.masked}\` | (missing) | Removed |`); envChanges += 1; }
    else if (a.value !== b.value) { lines.push(`| \`${k}\` | \`${a.masked}\` | \`${b.masked}\` | Changed |`); envChanges += 1; }
  }
  if (!envChanges) lines.push('| (none) | - | - | Identical env keys |');
  lines.push('');
  return lines.join('\n');
}

function buildPolicyDocMarkdown(parsed, fileName) {
  const lines = [
    `# Claude Code Policy & Hook Reference (${fileName})`,
    '',
    `- **Default Mode:** \`${parsed.defaultMode}\``,
    `- **Permission Rules:** ${parsed.stats.ruleCount} (${parsed.stats.allowCount} allow, ${parsed.stats.denyCount} deny, ${parsed.stats.askCount} ask)`,
    `- **Hooks:** ${parsed.stats.hookCount}`,
    `- **Environment Variables:** ${parsed.stats.envCount} (secrets masked)`,
    '',
    '## Permission Rules',
    '',
    '| # | Decision | Tool | Pattern | Status |',
    '| ---: | --- | --- | --- | --- |',
  ];
  for (const r of parsed.rules) {
    lines.push(`| ${r.index} | ${r.decision.toUpperCase()} | ${r.tool} | \`${r.pattern}\` | ${r.status.toUpperCase()} |`);
  }
  if (!parsed.rules.length) lines.push('| - | - | - | (no rules) | - |');

  lines.push('', '## Hooks', '', '| # | Event | Matcher | Type | Command | Status |', '| ---: | --- | --- | --- | --- | --- |');
  for (const h of parsed.hooks) {
    lines.push(`| ${h.index} | ${h.event} | \`${h.matcher}\` | ${h.type} | \`${h.command.replace(/\|/g, '\\|')}\` | ${h.status.toUpperCase()} |`);
  }
  if (!parsed.hooks.length) lines.push('| - | - | - | - | (no hooks) | - |');

  lines.push('', '## Environment Variables (Masked)', '', '| Key | Masked Value | Secret | Status |', '| --- | --- | --- | --- |');
  for (const e of parsed.envVars) {
    lines.push(`| \`${e.key}\` | \`${e.masked}\` | ${e.isSecret ? 'Yes' : 'No'} | ${e.status.toUpperCase()} |`);
  }
  if (!parsed.envVars.length) lines.push('| - | (no env vars) | - | - |');
  lines.push('');
  return lines.join('\n');
}

function buildPolicyDocCsv(parsed) {
  const rows = [['section', 'category', 'name', 'pattern_or_command', 'status', 'finding_count'].join(',')];
  for (const r of parsed.rules) {
    rows.push([r.decision, 'permission', r.tool, r.pattern, r.status, r.findings.length].map(csvCell).join(','));
  }
  for (const h of parsed.hooks) {
    rows.push([h.event, 'hook', h.matcher, h.command, h.status, h.findings.length].map(csvCell).join(','));
  }
  for (const e of parsed.envVars) {
    rows.push(['env', e.isSecret ? 'secret' : 'config', e.key, e.masked, e.status, e.status === 'error' ? 1 : 0].map(csvCell).join(','));
  }
  return rows.join('\n') + '\n';
}

module.exports = {
  parseClaudeSettings,
  buildPolicyAuditMarkdown,
  buildConfigDiffMarkdown,
  buildPolicyDocMarkdown,
  buildPolicyDocCsv,
  maskValue,
  detectSecretInString,
};
