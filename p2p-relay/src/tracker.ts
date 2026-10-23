interface TrackerOptions {
  port: number;
  host?: string;
}

interface TrackerServer {
  http: any;
  ws: any;
  listening: boolean;
  close: () => void;
}

interface Peer {
  id: string;
  ws: any;
  infoHash: string;
}

// Simple in-memory storage of peers by info_hash
const swarms = new Map<string, Set<Peer>>();

export async function createTracker(options: TrackerOptions): Promise<TrackerServer> {
  const { port, host = "0.0.0.0" } = options;

  return new Promise((resolve, reject) => {
    // Create unified server for both HTTP and WebSocket
    const server = Bun.serve({
      port,
      hostname: host,
      websocket: {
        open(ws: any) {
          console.log("WebSocket connection opened");
        },
        message(ws: any, message: string | Buffer) {
          try {
            const data = JSON.parse(message.toString());
            
            // Handle peer registration
            if (data.action === "announce" && data.info_hash && data.peer_id) {
              const { info_hash, peer_id } = data;
              
              if (!swarms.has(info_hash)) {
                swarms.set(info_hash, new Set());
              }
              
              const swarm = swarms.get(info_hash)!;
              const peer: Peer = { id: peer_id, ws, infoHash: info_hash };
              swarm.add(peer);
              
              // Send current peers to new peer
              const peers = Array.from(swarm)
                .filter(p => p.id !== peer_id)
                .map(p => ({ id: p.id }));
              
              ws.send(JSON.stringify({
                action: "announce",
                interval: 60,
                info_hash,
                peers,
              }));
              
              console.log(`Peer ${peer_id} joined swarm ${info_hash}`);
            }
            
            // Handle WebRTC signaling (offer/answer/ice-candidate)
            if (data.action === "signal" && data.to && data.info_hash) {
              const swarm = swarms.get(data.info_hash);
              if (swarm) {
                // Forward signal to target peer
                for (const peer of swarm) {
                  if (peer.id === data.to) {
                    peer.ws.send(JSON.stringify({
                      action: "signal",
                      from: data.from,
                      signal: data.signal,
                    }));
                    break;
                  }
                }
              }
            }
          } catch (err) {
            console.error("Error handling WebSocket message:", err);
          }
        },
        close(ws: any) {
          // Remove peer from all swarms
          for (const [infoHash, swarm] of swarms.entries()) {
            for (const peer of swarm) {
              if (peer.ws === ws) {
                swarm.delete(peer);
                console.log(`Peer ${peer.id} left swarm ${infoHash}`);
                if (swarm.size === 0) {
                  swarms.delete(infoHash);
                }
                break;
              }
            }
          }
        },
      },
      fetch(req, server) {
        const url = new URL(req.url);
        
        // Try to upgrade to WebSocket
        if (req.headers.get("upgrade") === "websocket") {
          if (server.upgrade(req)) {
            return; // Connection upgraded
          }
          return new Response("WebSocket upgrade failed", { status: 500 });
        }
        
        // Handle HTTP endpoints
        
        // Handle /announce endpoint (HTTP tracker)
        if (url.pathname === "/announce") {
          const infoHash = url.searchParams.get("info_hash");
          const peerId = url.searchParams.get("peer_id");
          const event = url.searchParams.get("event");
          
          if (!infoHash) {
            return new Response("Missing info_hash", { status: 400 });
          }
          
          // Get or create swarm
          if (!swarms.has(infoHash)) {
            swarms.set(infoHash, new Set());
          }
          
          const swarm = swarms.get(infoHash)!;
          
          // Handle events
          if (event === "stopped" && peerId) {
            // Remove peer from swarm
            for (const peer of swarm) {
              if (peer.id === peerId) {
                swarm.delete(peer);
                break;
              }
            }
          }
          
          // Return peer list (compact format for WebTorrent)
          const peers = Array.from(swarm).map(p => ({
            id: p.id,
          }));
          
          return new Response(JSON.stringify({
            interval: 60,
            complete: peers.length,
            incomplete: 0,
            peers,
          }), {
            headers: { "Content-Type": "application/json" },
          });
        }
        
        // Stats endpoint
        if (url.pathname === "/stats") {
          return new Response(JSON.stringify({
            torrents: swarms.size,
            activePeers: Array.from(swarms.values()).reduce((sum, swarm) => sum + swarm.size, 0),
          }), {
            headers: { "Content-Type": "application/json" },
          });
        }
        
        return new Response("ETIPOS P2P Tracker", { status: 200 });
      },
    });

    console.log(`🌐 WebTorrent Tracker listening on ${host}:${port}`);
    console.log(`   HTTP Tracker: http://${host}:${port}/announce`);
    console.log(`   WebSocket Tracker: ws://${host}:${port}`);

    resolve({
      http: server,
      ws: server,
      listening: true,
      close: () => {
        server.stop();
        swarms.clear();
        console.log("Tracker server closed");
      },
    });
  });
}
