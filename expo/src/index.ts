import {
  NativeModulesProxy,
  EventEmitter,
  Subscription
} from 'expo-modules-core'

// Import the native module. On web, it will be resolved to ExpoAutograph.web.ts
// and on native platforms to ExpoAutograph.ts
import { ChangeEventPayload } from './ExpoAutograph.types'
import ExpoAutographModule from './ExpoAutographModule'

// Get the native constant value.
export const PI = ExpoAutographModule.PI

export function hello(): string {
  return ExpoAutographModule.hello()
}

export async function setValueAsync(value: string) {
  return await ExpoAutographModule.setValueAsync(value)
}

const emitter = new EventEmitter(
  ExpoAutographModule ?? NativeModulesProxy.ExpoAutograph
)

export function addChangeListener(
  listener: (event: ChangeEventPayload) => void
): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener)
}

export { ChangeEventPayload }
