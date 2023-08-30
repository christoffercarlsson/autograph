import { defineConfig } from 'astro/config'

export default defineConfig({
  markdown: {
    shikiConfig: {
      // https://github.com/shikijs/shiki/blob/main/docs/themes.md
      theme: 'github-dark',
    },
  },
})
