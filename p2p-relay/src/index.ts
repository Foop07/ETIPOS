import { createTracker } from "./tracker";

// Get configuration from environment variables
const TRACKER_PORT = parseInt(process.env.TRACKER_PORT || "8001");
const HOST = process.env.HOST || "0.0.0.0";

async function main() {
  console.log("🚀 Starting ETIPOS P2P Relay Server...\n");

  try {
    // Start WebTorrent tracker (includes WebSocket for WebRTC signaling)
    const tracker = await createTracker({
      port: TRACKER_PORT,
      host: HOST,
    });

    console.log("\n✅ P2P Relay Server is ready!");
    console.log(`   Tracker Port: ${TRACKER_PORT}`);
    console.log(`   Host: ${HOST}`);
    console.log("\nPress Ctrl+C to stop the server.\n");

    // Handle graceful shutdown
    process.on("SIGINT", () => {
      console.log("\n🛑 Shutting down P2P Relay Server...");
      tracker.close();
      process.exit(0);
    });

    process.on("SIGTERM", () => {
      console.log("\n🛑 Shutting down P2P Relay Server...");
      tracker.close();
      process.exit(0);
    });
  } catch (err) {
    console.error("❌ Failed to start P2P Relay Server:", err);
    process.exit(1);
  }
}

main();
