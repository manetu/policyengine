import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    'how-it-works',
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'getting-started/index',
        'getting-started/prerequisites',
        'getting-started/installation',
      ],
    },
    {
      type: 'category',
      label: 'Quick Start',
      collapsed: false,
      items: [
        'quick-start/index',
        'quick-start/first-policy-domain',
        'quick-start/testing-policies',
      ],
    },
    {
      type: 'category',
      label: 'Concepts',
      collapsed: false,
      items: [
        'concepts/index',
        'concepts/pbac',
        'concepts/policy-conjunction',
        'concepts/mrn',
        'concepts/porc',
        'concepts/policy-domains',
        'concepts/policies',
        'concepts/policy-libraries',
        'concepts/operations',
        'concepts/roles',
        'concepts/groups',
        'concepts/resources',
        'concepts/resource-groups',
        'concepts/scopes',
        'concepts/annotations',
        'concepts/mappers',
        'concepts/audit',
      ],
    },
    {
      type: 'category',
      label: 'Examples',
      collapsed: false,
      items: [
        'examples/index',
        'examples/unix-filesystem',
        'examples/mcp-server',
        'examples/multi-tenant-saas',
        'examples/healthcare-hipaa',
        'examples/api-quotas',
      ],
    },
    {
      type: 'category',
      label: 'Integration',
      collapsed: false,
      items: [
        'integration/index',
        'integration/go-library',
        'integration/http-api',
        'integration/resource-resolution',
        'integration/best-practices',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      collapsed: false,
      items: [
        {
          type: 'category',
          label: 'CLI',
          items: [
            'reference/cli/index',
            'reference/cli/build',
            'reference/cli/lint',
            'reference/cli/test',
            'reference/cli/serve',
            'reference/cli/version',
          ],
        },
        {
          type: 'category',
          label: 'PolicyDomain Schema',
          items: [
            'reference/schema/index',
            'reference/schema/policies',
            'reference/schema/policy-libraries',
            'reference/schema/roles',
            'reference/schema/groups',
            'reference/schema/resource-groups',
            'reference/schema/resources',
            'reference/schema/scopes',
            'reference/schema/operations',
            'reference/schema/mappers',
          ],
        },
        'reference/configuration',
        'reference/access-record',
      ],
    },
    {
      type: 'category',
      label: 'Deployment',
      collapsed: true,
      items: [
        'deployment/index',
        'deployment/architecture',
        'deployment/envoy-integration',
      ],
    },
  ],
};

export default sidebars;
