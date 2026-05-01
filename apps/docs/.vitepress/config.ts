import { defineConfig } from 'vitepress';

export default defineConfig({
  title: 'Vouch',
  description: 'Identity infrastructure for AI agents — drop it next to your existing human auth, never replaces it.',
  cleanUrls: true,
  lastUpdated: true,

  head: [
    ['meta', { name: 'theme-color', content: '#3178c6' }],
    ['meta', { property: 'og:title', content: 'Vouch — identity infrastructure for AI agents' }],
    ['meta', { property: 'og:description', content: 'Drop-in auth rail that lives next to your existing human auth. Open-source today, hosted Cloud on the way.' }],
    ['meta', { property: 'og:type', content: 'website' }],
  ],

  themeConfig: {
    logo: undefined,
    siteTitle: 'Vouch',

    nav: [
      { text: 'Guide', link: '/getting-started', activeMatch: '/(getting-started|concepts|providers|client-sdk|cli)' },
      { text: 'Reference', link: '/reference/lifecycle', activeMatch: '/reference/' },
      { text: 'Examples', link: 'https://github.com/shizhigu/agent-auth/tree/main/examples' },
      {
        text: 'v0.1',
        items: [
          { text: 'Changelog', link: 'https://github.com/shizhigu/agent-auth/blob/main/CHANGELOG.md' },
          { text: 'Roadmap', link: 'https://github.com/shizhigu/agent-auth#roadmap' },
        ],
      },
    ],

    sidebar: {
      '/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is Vouch?', link: '/' },
            { text: 'Getting started', link: '/getting-started' },
            { text: 'Concepts', link: '/concepts' },
            { text: 'FAQ', link: '/faq' },
          ],
        },
        {
          text: 'Guides',
          items: [
            { text: 'Identity providers', link: '/providers' },
            { text: 'Migrations CLI', link: '/cli' },
            { text: 'Agent SDK (@vouch/client)', link: '/client-sdk' },
            { text: 'Hono integration', link: '/guides/hono' },
            { text: 'End-to-end demo', link: '/guides/demo' },
          ],
        },
        {
          text: 'Reference',
          items: [
            { text: 'Lifecycle routes', link: '/reference/lifecycle' },
            { text: 'Error codes', link: '/reference/errors' },
            { text: 'Threat model', link: 'https://github.com/shizhigu/agent-auth/blob/main/SPEC.md#part-vi--threat-model' },
            { text: 'SPEC.md', link: 'https://github.com/shizhigu/agent-auth/blob/main/SPEC.md' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/shizhigu/agent-auth' },
    ],

    search: {
      provider: 'local',
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Agentic Flow LLC',
    },

    editLink: {
      pattern: 'https://github.com/shizhigu/agent-auth/edit/main/apps/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
});
