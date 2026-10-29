import { describe, it, expect, afterEach } from "bun:test";
import { createTracker } from "../src/tracker";
import { WebSocket } from "ws";

describe("WebTorrent Tracker", () => {
  let server: any;
  const TEST_PORT = 8002; // Use different port for testing

  afterEach(() => {
    if (server) {
      server.close();
      server = null;
    }
  });

  it("creates tracker server successfully", async () => {
    server = await createTracker({ port: TEST_PORT });
    expect(server).toBeDefined();
    expect(server.listening).toBe(true);
  });

  it("tracker server has HTTP and WebSocket servers", async () => {
    server = await createTracker({ port: TEST_PORT });
    expect(server.http).toBeDefined();
    expect(server.ws).toBeDefined();
  });

  it("uses the official WebTorrent WebSocket announce protocol", async () => {
    server = await createTracker({ port: TEST_PORT });
    const socket = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    const response = new Promise<any>((resolve, reject) => {
      socket.once("error", reject);
      socket.once("message", (message) => resolve(JSON.parse(message.toString())));
      setTimeout(() => reject(new Error("tracker response timeout")), 2000);
    });
    await new Promise<void>((resolve) => socket.once("open", resolve));
    socket.send(JSON.stringify({
      action: "announce",
      info_hash: "01234567890123456789",
      peer_id: "abcdefghijklmnopqrst",
      event: "started",
      left: 1,
      offers: [{ offer: {}, offer_id: "01234567890123456789012345678901" }],
    }));
    const message = await response;
    expect(message.interval).toBeGreaterThan(0);
    expect(message.info_hash).toBe("01234567890123456789");
    socket.close();
  });
});
