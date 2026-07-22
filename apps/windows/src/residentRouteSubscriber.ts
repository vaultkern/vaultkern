import type { ResidentAppRoute } from "@vaultkern/runtime-web-client";
import type { ResidentAppRouteSubscriber } from "@vaultkern/shared-web-ui";

export function createResidentAppRouteSubscriber(
  takePending: () => Promise<ResidentAppRoute | null>,
  listenAvailable: (listener: () => void) => Promise<() => void>
): ResidentAppRouteSubscriber {
  return async (listener) => {
    let active = true;
    let delivery = Promise.resolve();
    const drain = () => {
      delivery = delivery
        .then(async () => {
          const route = await takePending();
          if (active && route) {
            listener(route);
          }
        })
        .catch(() => undefined);
      return delivery;
    };

    const unlisten = await listenAvailable(() => {
      void drain();
    });
    await drain();

    return () => {
      active = false;
      unlisten();
    };
  };
}
