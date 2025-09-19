// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'Nyra SD-JWT Docs',
			description: 'Learn how to issue, hold, and verify selective disclosure JWTs with PHP.',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/nyra-dev/sd-jwt' },
			],
			sidebar: [
				{
					label: 'Introduction',
					items: [
						{ label: 'Welcome', slug: 'index' },
						{ label: 'Getting Started', slug: 'guides/getting-started' },
					],
				},
				{
					label: 'Core Guides',
					items: [
						{ label: 'Issuing Credentials', slug: 'guides/issuing-credentials' },
						{ label: 'Selective Disclosure for Holders', slug: 'guides/selective-disclosure' },
						{ label: 'Verifying Presentations', slug: 'guides/verifying-presentations' },
						{ label: 'Key Binding & sd_hash', slug: 'guides/key-binding' },
						{ label: 'End-to-End Example', slug: 'guides/example-workflow' },
					],
				},
				{
					label: 'Reference',
					autogenerate: { directory: 'reference' },
				},
			],
		}),
	],
});
