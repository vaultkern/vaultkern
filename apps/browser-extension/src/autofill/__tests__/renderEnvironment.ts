import { afterEach, beforeEach } from "vitest";

import {
  registerRenderEnvironment,
  type RenderEnvironment
} from "../renderFacts";

function syntheticRect(element: HTMLElement): DOMRect {
  if (Object.prototype.hasOwnProperty.call(element, "getBoundingClientRect")) {
    return element.getBoundingClientRect();
  }
  const left = 20;
  const top = 20;
  return {
    x: left,
    y: top,
    left,
    top,
    right: left + 240,
    bottom: top + 32,
    width: 240,
    height: 32,
    toJSON: () => ({})
  } as DOMRect;
}

export function installDomRenderEnvironment(
  documentRef: Document = document,
  overrides: Partial<RenderEnvironment> = {}
) {
  const environment: RenderEnvironment = {
    gbr: syntheticRect,
    gcr: (element) => {
      const rect = syntheticRect(element);
      return rect.width > 0 && rect.height > 0 ? [rect] : [];
    },
    gvs: () => ({ width: 100_000, height: 100_000 }),
    hit: (_root, _x, _y) => ({ av: false }),
    fht: () => "visible",
    vvp: () => true,
    ...overrides
  };
  return registerRenderEnvironment(documentRef, environment);
}

export function useDomRenderEnvironment() {
  let unregister: (() => void) | undefined;
  beforeEach(() => {
    unregister = installDomRenderEnvironment();
  });
  afterEach(() => {
    unregister?.();
    unregister = undefined;
  });
}
