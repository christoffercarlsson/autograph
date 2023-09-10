import { execa } from 'execa'
import { exit } from 'node:process'
import { copyFile } from 'node:fs/promises'

const run = async () => {
  await execa('/bin/bash', ['../cplusplus/scripts/build.sh', '-w'])
  await copyFile('../cplusplus/build/autograph.js', 'wasm/autograph.js')
  await copyFile('../cplusplus/build/autograph.wasm', 'wasm/autograph.wasm')
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
