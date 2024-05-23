import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'node:process'

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
    bundle: true
  })
  await build({
    ...sharedOptions,
    entryPoints: ['typescript/src/autograph.ts'],
    bundle: true,
    format: 'cjs',
    outExtension: { '.js': '.cjs' }
  })
  await build({
    ...sharedOptions,
    entryPoints: await globby('typescript/tests/**/*.test.ts')
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
