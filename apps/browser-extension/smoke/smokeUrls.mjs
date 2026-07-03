export const SMOKE_HOST = "localhost";

export function smokeUrl(port, page) {
  return `http://${SMOKE_HOST}:${port}/${page}`;
}
