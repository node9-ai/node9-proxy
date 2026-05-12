// src/tui/dashboard/views/report/panels/Spinner.tsx
//
// Tiny braille spinner. Used by the LEAKS / LOOPS / TOP RULES panels
// during the scan walk so the user has visible motion while the walker
// runs. On a fast install the walk is sub-second so the spinner barely
// shows; on a slower install it's clearer feedback than a static label.
//
// Implementation: each instance owns its own setInterval. Intervals
// only run while the panel is in the 'loading' state — they unmount
// when scanCache transitions to 'ready' / 'error' / 'idle' so there's
// no idle CPU cost.

import React, { useEffect, useState } from 'react';
import { Text } from 'ink';

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export function Spinner({ frameMs = 80 }: { frameMs?: number }): React.ReactElement {
  const [i, setI] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setI((x) => (x + 1) % FRAMES.length), frameMs);
    return () => clearInterval(id);
  }, [frameMs]);
  return <Text dimColor>{FRAMES[i]}</Text>;
}
