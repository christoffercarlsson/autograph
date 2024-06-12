import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { ExpoAutographViewProps } from './ExpoAutograph.types';

const NativeView: React.ComponentType<ExpoAutographViewProps> =
  requireNativeViewManager('ExpoAutograph');

export default function ExpoAutographView(props: ExpoAutographViewProps) {
  return <NativeView {...props} />;
}
