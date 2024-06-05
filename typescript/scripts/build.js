import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'node:process'

const run = async () => {
  const sharedOptions = {
    format: 'esm',
    minify: false,
    outbase: 'typescript',
    outdir: 'typescript/dist',
    platform: 'browser',
    plugins: [sourceMapPlugin],
    sourcemap: true
  }
  await build({
    ...sharedOptions,
    bundle: true,
    entryPoints: ['typescript/src/autograph.ts']
  })
  await build({
    ...sharedOptions,
    bundle: true,
    entryPoints: ['typescript/src/autograph.ts'],
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
