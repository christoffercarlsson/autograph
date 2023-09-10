import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'node:process'
import { copyFile } from 'node:fs/promises'

const run = async () => {
  const sharedOptions = {
    format: 'esm',
    outbase: '.',
    outdir: 'dist',
    platform: 'node',
    plugins: [sourceMapPlugin],
    sourcemap: true
  }
  await build({
    ...sharedOptions,
    entryPoints: ['src/autograph.ts'],
    bundle: true,
    splitting: true
  })
  await build({
    ...sharedOptions,
    entryPoints: await globby('tests/**/*.test.ts')
  })
  await copyFile('wasm/autograph.wasm', 'dist/src/autograph.wasm')
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
