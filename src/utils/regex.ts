// Thin re-export of the regex utilities now living in @node9/policy-engine.
// Existing import paths (`from '../utils/regex'`) keep working.
export { validateRegex, getCompiledRegex } from '@node9/policy-engine';
