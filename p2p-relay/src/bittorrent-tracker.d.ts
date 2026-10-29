declare module "bittorrent-tracker/server" {
  class Server {
    constructor(options: Record<string, unknown>);
    listen(port: number, host: string, callback: (error?: Error) => void): void;
    close(callback?: () => void): void;
  }
  export default Server;
}
