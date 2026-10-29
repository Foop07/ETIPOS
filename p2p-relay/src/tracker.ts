// Import the server subpath directly: the package root also imports its Node
// WebRTC client and native node-datachannel, which this tracker-only service
// does not need.
import Server from "bittorrent-tracker/server";

interface TrackerOptions {
  port: number;
  host?: string;
}

export async function createTracker(options: TrackerOptions): Promise<any> {
  const tracker = new Server({
    udp: false,
    trustProxy: false,
    ws: true,
    stats: true,
    interval: 60_000,
  });
  await new Promise<void>((resolve, reject) => {
    tracker.listen(options.port, options.host || "0.0.0.0", (error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });
  return tracker;
}
