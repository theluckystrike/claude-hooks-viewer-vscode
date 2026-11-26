'use strict';
// ViewModel for Claude Config & Hooks Viewer.

class ClaudeConfigViewModel {
  constructor(parsed, fileName, fileSize = 0) {
    this.parsed = parsed;
    this.fileName = fileName;
    this.fileSize = fileSize;
    this.filter = { text: '', decision: '', status: '' };
    this.filtered = parsed.rules.slice();
  }

  summary() {
    return {
      fileName: this.fileName,
      fileSize: this.fileSize,
      model: this.parsed.model,
      defaultMode: this.parsed.defaultMode,
      ...this.parsed.stats,
      hooks: this.parsed.hooks,
      envVars: this.parsed.envVars.map((e) => ({
        key: e.key,
        masked: e.masked,
        value: e.value,
        isSecret: e.isSecret,
        secretType: e.secretType,
        status: e.status,
      })),
      findings: this.parsed.findings,
    };
  }

  totalCount() {
    return this.parsed.rules.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = String((f && f.text) || '').trim().toLowerCase();
    const decision = String((f && f.decision) || '').trim().toLowerCase();
    const status = String((f && f.status) || '').trim().toLowerCase();
    this.filter = { text, decision, status };
    this.filtered = this.parsed.rules.filter((r) => {
      if (decision && r.decision !== decision) return false;
      if (status && r.status !== status) return false;
      if (text) {
        const hay = `${r.decision} ${r.tool} ${r.pattern} ${r.raw}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from = 0, n = 100) {
    return this.filtered.slice(from, from + n).map((r) => ({
      index: r.index,
      decision: r.decision,
      tool: r.tool,
      pattern: r.pattern,
      raw: r.raw,
      status: r.status,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
    }));
  }

  detail(index) {
    const r = this.parsed.rules.find((x) => x.index === index);
    if (!r) return null;
    return {
      ...r,
      defaultMode: this.parsed.defaultMode,
      rawJson: this.parsed.rawJson,
    };
  }
}

module.exports = { ClaudeConfigViewModel };
