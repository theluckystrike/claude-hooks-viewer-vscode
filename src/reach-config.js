'use strict';
module.exports = {
  prefix: 'zovoClaudeHooks',
  triesKey: 'zovoClaudeHooks.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditPolicy', title: 'Audit Claude settings safety and permissions', command: 'zovoClaudeHooks.auditPolicy' },
    { id: 'diffConfigs', title: 'Compare two Claude settings files', command: 'zovoClaudeHooks.diffConfigs' },
    { id: 'exportPolicyDoc', title: 'Export permission and hook docs to Markdown and CSV', command: 'zovoClaudeHooks.exportPolicyDoc' },
  ],
};
