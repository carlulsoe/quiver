import type { WebSocketRoute } from "playwright-core";
import type { AttackSurfaceWebSocket } from "../attack-surface.ts";

/** Proxies an admitted socket while collecting bounded frame counts and byte totals. */
export function observeWebSocketTraffic(
  route: WebSocketRoute,
  evidence: AttackSurfaceWebSocket,
): void {
  const server = route.connectToServer();
  route.onMessage((message) => {
    evidence.sentFrames += 1;
    evidence.sentBytes += frameByteLength(message);
    server.send(message);
  });
  server.onMessage((message) => {
    evidence.receivedFrames += 1;
    evidence.receivedBytes += frameByteLength(message);
    route.send(message);
  });
}

function frameByteLength(payload: string | Buffer): number {
  return Buffer.isBuffer(payload) ? payload.byteLength : Buffer.byteLength(payload);
}
