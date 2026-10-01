import { defineContentScript } from 'wxt/utils/define-content-script';
import { installPageBridge } from '../lib/passkey-page';

export default defineContentScript({ matches: ['https://*/*'], allFrames: false, runAt: 'document_start', world: 'MAIN', main: installPageBridge });
