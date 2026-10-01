// Reuse the authenticated synthetic host and inject a sync event during one delayed fill.
// This launcher is used only by the disposable inline browser harness.
import './native-host.mjs';

let input = Buffer.alloc(0);
process.stdin.on('data', chunk => {
  input = Buffer.concat([input, chunk]);
  while (input.length >= 4) {
    const length = input.readUInt32LE(0);
    if (length > 256 * 1024) process.exit(2);
    if (input.length < length + 4) return;
    const message = JSON.parse(input.subarray(4, length + 4).toString('utf8'));
    input = input.subarray(length + 4);
    if (message.type === 'FillLogin' && message.frame_url.includes('/slow-sync')) {
      setTimeout(() => {
        const data = Buffer.from(JSON.stringify({ version: 1, type: 'MatchesChanged', epoch: 1 }));
        const header = Buffer.alloc(4); header.writeUInt32LE(data.length);
        process.stdout.write(Buffer.concat([header, data]));
      }, 30);
    }
  }
});
