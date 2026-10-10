/** Hash of the extension source this script was built from (see wxt.config.ts). Two scripts
 * from the same install with different values mean the browser still runs an older copy. */
export const BUILD: string = import.meta.env.BOLTWARDEN_BUILD ?? 'development';
/** What a background from before build checks answers to an action it does not know. */
export const UNKNOWN_ACTION = 'Unknown browser action.';
export const STALE_MESSAGE = 'Boltwarden was updated, but the browser is still running the previous version. Reload the extension to finish the update.';
