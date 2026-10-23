import { describe, it, expect, afterEach } from "bun:test";
import { createTracker } from "../src/tracker";

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
});
