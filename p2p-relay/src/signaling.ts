import { WebSocketServer, WebSocket } from "ws";

interface SignalingOptions {
  port: number;
  host?: string;
}

interface SignalingMessage {
  type: "offer" | "answer" | "ice-candidate";
  from: string;
  to: string;
  data: any;
}

export function createSignalingServer(options: SignalingOptions) {
  const { port, host = "0.0.0.0" } = options;
  
  const wss = new WebSocketServer({ port, host });
  
  // Map of peer IDs to WebSocket connections
  const peers = new Map<string, WebSocket>();
  
  wss.on("connection", (ws: WebSocket) => {
    let peerId: string | null = null;
    
    console.log("New WebSocket connection");
    
    ws.on("message", (data: Buffer) => {
      try {
        const message = JSON.parse(data.toString()) as SignalingMessage;
        
        // Handle peer registration
        if (message.type === "register" && (message as any).peerId) {
          peerId = (message as any).peerId;
          peers.set(peerId, ws);
          console.log(`Peer registered: ${peerId}`);
          return;
        }
        
        // Relay signaling messages between peers
        if (message.to && peers.has(message.to)) {
          const targetWs = peers.get(message.to);
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify(message));
            console.log(`Relayed ${message.type} from ${message.from} to ${message.to}`);
          }
        }
      } catch (err) {
        console.error("Error handling message:", err);
      }
    });
    
    ws.on("close", () => {
      if (peerId) {
        peers.delete(peerId);
        console.log(`Peer disconnected: ${peerId}`);
      }
    });
    
    ws.on("error", (err: Error) => {
      console.error("WebSocket error:", err);
    });
  });
  
  console.log(`🔌 WebRTC Signaling Server listening on ws://${host}:${port}`);
  
  return wss;
}
