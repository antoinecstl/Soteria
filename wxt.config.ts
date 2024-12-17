import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  extensionApi: 'chrome',
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name : 'Soteria',
    version: '1.0.0',
    description: 'Soteria is a browser extension that helps you stay safe online.',
    permissions: ['storage', 'activeTab', 'scripting'],
  },
});
