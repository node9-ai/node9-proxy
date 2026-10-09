/** Serialize scheduled pulls and coalesce invalidations arriving mid-fetch. */
export function createSyncTrigger(sync: () => Promise<void>) {
  let running: Promise<void> | undefined;
  let pending = false;
  return (invalidate = true): Promise<void> => {
    if (running) {
      if (invalidate) pending = true;
      return running;
    }
    running = (async () => {
      do {
        pending = false;
        await sync();
      } while (pending);
    })().finally(() => {
      running = undefined;
    });
    return running;
  };
}
