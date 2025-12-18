import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Manetu PolicyEngine',
  tagline: 'Policy-Based Access Control with Open Policy Agent',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  headTags: [
      {
          tagName: "script",
          attributes: {
              id: "Cookiebot",
              type: 'text/javascript',
              src: "https://consent.cookiebot.com/uc.js",
              'data-cbid': "3d4b1355-2f20-4c2e-a32d-fbc05913fb1d",
              'data-blockingmode': "auto",
          },
      },
  ],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: ({sourceFilePath, url}) => {
        throw new Error(`Broken markdown link in ${sourceFilePath}: ${url}`);
      },
    },
  },
  themes: ['@docusaurus/theme-mermaid'],

  // GitHub Pages deployment configuration
  url: 'https://manetu.github.io',
  baseUrl: '/policyengine/',

  organizationName: 'manetu',
  projectName: 'policyengine',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/manetu/policyengine/tree/main/docs/',
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      '@docusaurus/plugin-google-gtag',
      {
        trackingID: 'G-ML72437DHG',
        anonymizeIP: false,
      },
    ],
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        docsRouteBasePath: '/',
        indexBlog: false,
      },
    ],
    './plugins/iubenda-proxy.js',
  ],

  themeConfig: {
    image: 'img/social-card.png',
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Policy Engine',
      logo: {
        alt: 'Manetu Logo',
        src: 'img/logo-light.svg',
        srcDark: 'img/logo-dark.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/manetu/policyengine',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/getting-started',
            },
            {
              label: 'Quick Start',
              to: '/quick-start',
            },
            {
              label: 'Concepts',
              to: '/concepts',
            },
          ],
        },
        {
          title: 'Resources',
          items: [
            {
              label: 'Open Policy Agent',
              href: 'https://www.openpolicyagent.org/',
            },
            {
              label: 'Rego Language',
              href: 'https://www.openpolicyagent.org/docs/latest/policy-language/',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/manetu/policyengine',
            },
            {
              label: 'Manetu',
              href: 'https://manetu.com',
            },
            {
              label: 'Privacy Policy',
              to: '/privacy-policy',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Manetu Inc. All rights reserved.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'yaml', 'json', 'go', 'rego'],
    },
    mermaid: {
      theme: {light: 'neutral', dark: 'dark'},
      options: {
        themeVariables: {
          primaryColor: '#03a3ed',
          primaryTextColor: '#fff',
          primaryBorderColor: '#0282bd',
          lineColor: '#718096',
          secondaryColor: '#1a145f',
          tertiaryColor: '#0f0a3d',
        },
      },
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
