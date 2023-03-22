import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'process'

const run = async () => {
  const sharedOptions = {
    chunkNames: 'src/[hash]',
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
    external: ['stedy'],
    splitting: true
  })
  await build({
    ...sharedOptions,
    entryPoints: await globby('tests/**/*.test.ts')
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
