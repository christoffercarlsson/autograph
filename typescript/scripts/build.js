import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'node:process'
import { copyFile } from 'node:fs/promises'

const run = async () => {
  const sharedOptions = {
    format: 'esm',
    outbase: 'typescript',
    outdir: 'typescript/dist',
    platform: 'node',
    plugins: [sourceMapPlugin],
    sourcemap: true
  }
  await build({
    ...sharedOptions,
    entryPoints: ['typescript/src/autograph.ts'],
    bundle: true,
    splitting: true
  })
  await build({
    ...sharedOptions,
    entryPoints: await globby('typescript/tests/**/*.test.ts')
  })
  await copyFile(
    'typescript/wasm/autograph.wasm',
    'typescript/dist/src/autograph.wasm'
  )
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
