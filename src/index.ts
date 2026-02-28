//src/index.ts
import { authorizeAction } from './core';

/**
 * The "Sudo" wrapper for AI tools.
 */
export function protect<T extends (...args: any[]) => any>(
  toolName: string,
  fn: T
): (...args: Parameters<T>) => Promise<ReturnType<T>> {
  return async (...args: Parameters<T>) => {
    const isAuthorized = await authorizeAction(toolName, args);
    
    if (!isAuthorized) {
      throw new Error(`Node9: Execution of ${toolName} was denied by the user.`);
    }

    return await fn(...args);
  };
}
