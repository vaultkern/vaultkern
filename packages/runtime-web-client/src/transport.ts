export interface RuntimeTransport {
  send(message: unknown): Promise<unknown>;
}
