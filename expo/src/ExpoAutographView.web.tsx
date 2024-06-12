import * as React from 'react';

import { ExpoAutographViewProps } from './ExpoAutograph.types';

export default function ExpoAutographView(props: ExpoAutographViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
