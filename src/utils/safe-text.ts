// Thin re-export of the text sanitizers living in @node9/policy-engine, so
// proxy call sites get a short import path. Same shape as ../utils/regex.
export {
  stripTerminalEscapes,
  stripAnsiSequences,
  stripControlChars,
  safeMessage,
} from '@node9/policy-engine';
