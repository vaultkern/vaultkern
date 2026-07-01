export const SMOKE_HOST = "127.0.0.1";

export function smokeUrl(port, page) {
  return `http://${SMOKE_HOST}:${port}/${page}`;
}
