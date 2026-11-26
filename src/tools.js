'use strict';
// Pro tools for Claude Config & Hooks Viewer:
//   1. auditPolicy: Markdown team safety and permission audit across one file or a folder.
//   2. diffConfigs: Two-file Claude settings comparator in Markdown.
//   3. exportPolicyDoc: Non-destructive redacted Markdown + CSV policy and hook export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseClaudeSettings,
  buildPolicyAuditMarkdown,
  buildConfigDiffMarkdown,
  buildPolicyDocMarkdown,
  buildPolicyDocCsv,
} = require('./claude-config');

const JSON_FILE_RE = /\.json$/i;
const JSON_FILTERS = { 'Claude Settings JSON': ['json'] };

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Claude settings JSON') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && JSON_FILE_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: JSON_FILTERS,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listClaudeSettingsInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && /(?:settings(?:\.local)?\.json|\.claude\.json)$/i.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditPolicy(uri, opts = {}) {
    if (!(await pro.allowed('auditPolicy', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listClaudeSettingsInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No Claude settings JSON files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      entries.push({ fileName: path.basename(f), parsed: parseClaudeSettings(buf, path.basename(f)) });
    }
    const md = buildPolicyAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditPolicy');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffConfigs(uri, opts = {}) {
    if (!(await pro.allowed('diffConfigs', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Claude settings JSON');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: JSON_FILTERS,
        openLabel: 'Select second Claude settings JSON to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildConfigDiffMarkdown(
      leftName,
      parseClaudeSettings(leftBuf, leftName),
      rightName,
      parseClaudeSettings(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffConfigs');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportPolicyDoc(uri, opts = {}) {
    if (!(await pro.allowed('exportPolicyDoc', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseClaudeSettings(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/\.json$/i, '') || 'claude-policy';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.policy.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'CSV Policy Table': ['csv'] },
        saveLabel: 'Save Claude policy & hooks documentation',
      });
    if (!saveUri) return undefined;

    const csvPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(csvPath);
    const stem = path.basename(csvPath, '.csv').replace(/\.policy$/i, '');
    const mdPath = uniquePath(path.join(dir, `${stem}.policy.md`));

    fs.writeFileSync(csvPath, buildPolicyDocCsv(parsed), 'utf8');
    fs.writeFileSync(mdPath, buildPolicyDocMarkdown(parsed, baseName), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportPolicyDoc');
    if (reach) reach.refresh();
    return { files: [csvPath, mdPath], rules: parsed.stats.ruleCount, hooks: parsed.stats.hookCount };
  }

  return { auditPolicy, diffConfigs, exportPolicyDoc };
}

module.exports = { createTools, uniquePath, listClaudeSettingsInDir };
