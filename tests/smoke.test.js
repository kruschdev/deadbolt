import test from 'node:test';
import assert from 'node:assert/strict';
import { buildServer } from '../src/server.js';

test('deadbolt metrics + SSE stream smoke flow', async (t) => {
    const { server, close } = buildServer({ dbPath: ':memory:' });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
        await new Promise((resolve) => server.close(resolve));
        close();
    });

    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    const streamRes = await fetch(`${baseUrl}/api/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: 'hello-sse' })
    });
    assert.equal(streamRes.status, 200);
    assert.match(streamRes.headers.get('content-type') || '', /text\/event-stream/);
    const rawSse = await streamRes.text();
    assert.ok(rawSse.includes('hello-sse'));

    const metricsRes = await fetch(`${baseUrl}/api/metrics`);
    assert.equal(metricsRes.status, 200);
    const metricsBody = await metricsRes.json();
    assert.equal(metricsBody.ok, true);
    assert.equal(metricsBody.data.eventCount, 1);
});
