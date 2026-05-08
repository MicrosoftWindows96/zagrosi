// SPDX-License-Identifier: AGPL-3.0-or-later

export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [
      'identity',
      'workspaces',
      'tasks',
      'agile',
      'docs',
      'chat',
      'incidents',
      'oncall',
      'postmortems',
      'search',
      'notifications',
      'scheduler',
      'gateway',
      'web',
      'mcp',
      'helm',
      'compose',
      'ci',
      'deps',
    ]],
    'scope-empty':          [2, 'never'],
    'subject-case':         [2, 'never', ['pascal-case', 'upper-case']],
    'subject-full-stop':    [2, 'never', '.'],
    'header-max-length':    [2, 'always', 100],
    'body-max-line-length': [0, 'always', 0],
  },
};
