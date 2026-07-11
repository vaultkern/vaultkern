import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createBasicRenderFactsGetter,
  getBasicRenderFacts,
  proveVisualVisibility,
  registerRenderEnvironment,
  type RenderEnvironment,
  validateSecretTarget
} from "../renderFacts";

function rect(left: number, top: number, width: number, height: number): DOMRect {
  return {
    x: left,
    y: top,
    left,
    top,
    width,
    height,
    right: left + width,
    bottom: top + height,
    toJSON: () => ({})
  } as DOMRect;
}

const unregister: Array<() => void> = [];

afterEach(() => {
  unregister.splice(0).forEach((cleanup) => cleanup());
  document.body.innerHTML = "";
  vi.restoreAllMocks();
});

function useEnvironment(
  element: HTMLElement,
  renderedRect: DOMRect,
  hitTarget: Element | null | "unavailable" = element
) {
  const environment: RenderEnvironment = {
    gcr: () =>
      renderedRect.width > 0 && renderedRect.height > 0 ? [renderedRect] : [],
    gbr: () => renderedRect,
    gvs: () => ({ width: 1024, height: 768 }),
    hit: (_root, _x, _y) =>
      hitTarget === "unavailable"
        ? { av: false }
        : { av: true, t: hitTarget }
  };
  unregister.push(registerRenderEnvironment(document, environment));
}

describe("browser render facts", () => {
  it(
    "iteratively shares a sixty-thousand-level ancestor aggregate across fields",
    { timeout: 30_000 },
    () => {
      const depth = 60_000;
      const fieldCount = 2_048;
      const renderedRect = rect(20, 20, 240, 32);
      const style = {
        contentVisibility: "visible",
        display: "block",
        filter: "none",
        getPropertyValue: () => "",
        maskImage: "none",
        opacity: "1",
        pointerEvents: "auto",
        visibility: "visible"
      } as unknown as CSSStyleDeclaration;
      let styleReads = 0;
      vi.spyOn(window, "getComputedStyle").mockImplementation(() => {
        styleReads += 1;
        return style;
      });
      let parentReads = 0;
      const fakeElement = (
        parentElement: HTMLElement | null,
        tagName = "DIV"
      ) =>
        ({
          assignedSlot: null,
          disabled: false,
          getBoundingClientRect: () => renderedRect,
          getClientRects: () => [renderedRect],
          get parentElement() {
            parentReads += 1;
            return parentElement;
          },
          getRootNode: () => document,
          hasAttribute: () => false,
          hidden: false,
          isConnected: true,
          matches: () => false,
          ownerDocument: document,
          readOnly: false,
          tagName,
          type: "text"
        }) as unknown as HTMLElement;
      let parent: HTMLElement | null = null;
      for (let index = 0; index < depth; index += 1) {
        parent = fakeElement(parent);
      }
      const fields = Array.from({ length: fieldCount }, () =>
        fakeElement(parent, "INPUT")
      );
      const getRenderFacts = createBasicRenderFactsGetter();

      expect(() => fields.forEach(getRenderFacts)).not.toThrow();
      expect(styleReads).toBe(depth + fieldCount);
      expect(parentReads).toBe(depth + fieldCount);
    }
  );

  it("treats a rendered 0x0 field as non-viewable even when CSS size is auto", () => {
    document.body.innerHTML = '<input id="target" style="width: auto; height: auto">';
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 0, 0));

    expect(getBasicRenderFacts(target)).toMatchObject({
      vw: false,
      why: expect.arrayContaining(["not-viewable:zero-size"])
    });
  });

  it("uses viewport intersection and cumulative opacity as basic browser facts", () => {
    document.body.innerHTML = `
      <div style="opacity: 0">
        <input id="transparent">
      </div>
      <input id="offscreen">
    `;
    const transparent = document.querySelector("#transparent") as HTMLInputElement;
    useEnvironment(transparent, rect(20, 20, 240, 32));
    expect(getBasicRenderFacts(transparent)).toMatchObject({
      vw: false,
      why: expect.arrayContaining(["not-viewable:transparent"])
    });

    unregister.pop()?.();
    const offscreen = document.querySelector("#offscreen") as HTMLInputElement;
    useEnvironment(offscreen, rect(20, 900, 240, 32));
    expect(getBasicRenderFacts(offscreen)).toMatchObject({
      vw: false,
      why: expect.arrayContaining(["not-viewable:offscreen"])
    });
  });

  it.each([
    ["filter", "filter: opacity(0)"],
    [
      "mask",
      "-webkit-mask-image: linear-gradient(transparent, transparent); mask-image: linear-gradient(transparent, transparent)"
    ]
  ])("rejects a composed-ancestor %s paint effect", (_case, style) => {
    document.body.innerHTML = `
      <div style="${style}">
        <input id="target" type="password">
      </div>
    `;
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 240, 32));

    expect(getBasicRenderFacts(target)).toMatchObject({
      vw: false,
      why: expect.arrayContaining(["not-viewable:paint-effect"])
    });
  });

  it("does not treat a missing maskImage style property as a paint effect", () => {
    document.body.innerHTML = '<input id="target" type="password">';
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 240, 32));
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    const getComputedStyle = vi
      .spyOn(window, "getComputedStyle")
      .mockImplementation((element, pseudoElement) => {
        const style = originalGetComputedStyle(element, pseudoElement);
        return new Proxy(style, {
          get(styleTarget, property) {
            if (property === "maskImage") {
              return undefined;
            }
            const value = Reflect.get(styleTarget, property, styleTarget);
            return typeof value === "function" ? value.bind(styleTarget) : value;
          }
        });
      });

    try {
      expect(getBasicRenderFacts(target)).toMatchObject({
        vw: true,
        why: []
      });
    } finally {
      getComputedStyle.mockRestore();
    }
  });

  it("reports inert disabled and readonly browser state as non-fillable", () => {
    document.body.innerHTML = `
      <div inert>
        <input id="target" disabled readonly>
      </div>
    `;
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 240, 32));

    expect(getBasicRenderFacts(target)).toMatchObject({
      fl: false,
      fr: expect.arrayContaining([
        "not-fillable:disabled",
        "not-fillable:readonly",
        "not-fillable:inert"
      ])
    });
  });

  it("rejects a tiny totp target with the same strict geometry as other secret roles", () => {
    document.body.innerHTML =
      '<input id="target" autocomplete="one-time-code" inputmode="numeric">';
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 1, 1));

    expect(validateSecretTarget(target, "totp", "fill")).toMatchObject({
      ok: false,
      why: expect.arrayContaining(["invalid-secret-target:tiny"])
    });
  });

  it.each(["username", "password", "newPassword", "totp"] as const)(
    "applies strict minimum geometry to the %s role",
    (role) => {
      document.body.innerHTML = '<input id="target">';
      const target = document.querySelector("#target") as HTMLInputElement;
      useEnvironment(target, rect(20, 20, 7, 32));

      expect(validateSecretTarget(target, role, "fill").ok).toBe(false);
    }
  );

  it("uses the owning open shadow root for hit testing", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = '<input id="target" type="password">';
    const target = root.querySelector("#target") as HTMLInputElement;
    const roots: Array<Document | ShadowRoot> = [];
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: (hitRoot) => {
          roots.push(hitRoot);
          return { av: true, t: target };
        }
      })
    );

    expect(validateSecretTarget(target, "password", "fill").ok).toBe(true);
    expect(roots.length).toBeGreaterThan(1);
    expect(roots.every((hitRoot) => hitRoot === root)).toBe(true);
  });

  it("treats a real occluded hit-test result as final", () => {
    document.body.innerHTML = '<input id="target"><div id="overlay"></div>';
    const target = document.querySelector("#target") as HTMLInputElement;
    const overlay = document.querySelector("#overlay") as HTMLDivElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: () => ({ av: true, t: overlay }),
        fht: () => "visible"
      })
    );

    expect(validateSecretTarget(target, "username", "fill")).toMatchObject({
      ok: false,
      why: expect.arrayContaining(["invalid-secret-target:occluded"])
    });
  });

  it("rejects a target when only one point in its layout box is actually hittable", () => {
    document.body.innerHTML = '<input id="target"><div id="overlay"></div>';
    const target = document.querySelector("#target") as HTMLInputElement;
    const overlay = document.querySelector("#overlay") as HTMLDivElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: (_root, x, y) => ({
          av: true,
          t: x === 140 && y === 36 ? target : overlay
        })
      })
    );

    expect(validateSecretTarget(target, "password", "fill")).toMatchObject({
      ok: false,
      why: expect.arrayContaining(["invalid-secret-target:insufficient-hit-area"])
    });
  });

  it("accepts a partially covered target with one coherent 8x8 hittable footprint", () => {
    document.body.innerHTML = '<input id="target"><div id="overlay"></div>';
    const target = document.querySelector("#target") as HTMLInputElement;
    const overlay = document.querySelector("#overlay") as HTMLDivElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: (_root, x, y) => ({
          av: true,
          t: x >= 20 && x < 28 && y >= 20 && y < 28 ? target : overlay
        })
      })
    );

    expect(validateSecretTarget(target, "password", "fill").ok).toBe(true);
  });

  it("accepts a target whose half-open hittable box is exactly 8x8", () => {
    document.body.innerHTML = '<input id="target"><div id="outside"></div>';
    const target = document.querySelector("#target") as HTMLInputElement;
    const outside = document.querySelector("#outside") as HTMLDivElement;
    const renderedRect = rect(20, 20, 8, 8);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: (_root, x, y) => ({
          av: true,
          t: x >= 20 && x < 28 && y >= 20 && y < 28 ? target : outside
        })
      })
    );

    expect(validateSecretTarget(target, "password", "fill").ok).toBe(true);
  });

  it("does not accept an associated label as a hit on the secret target", () => {
    document.body.innerHTML = `
      <input id="target">
      <label id="cover" for="target">Covered password</label>
    `;
    const target = document.querySelector("#target") as HTMLInputElement;
    const label = document.querySelector("#cover") as HTMLLabelElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: () => ({ av: true, t: label })
      })
    );

    expect(validateSecretTarget(target, "password", "fill")).toMatchObject({
      ok: false,
      why: expect.arrayContaining(["invalid-secret-target:occluded"])
    });
  });

  it("allows a bounded deterministic fallback only when hit testing is unavailable", () => {
    document.body.innerHTML = '<input id="target">';
    const target = document.querySelector("#target") as HTMLInputElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: () => ({ av: false }),
        fht: () => "occluded"
      })
    );

    expect(validateSecretTarget(target, "password", "fill").ok).toBe(false);
  });

  it("fails closed when hit testing is unavailable without an injected fallback", () => {
    document.body.innerHTML = '<input id="target">';
    const target = document.querySelector("#target") as HTMLInputElement;
    const renderedRect = rect(20, 20, 240, 32);
    unregister.push(
      registerRenderEnvironment(document, {
        gcr: () => [renderedRect],
        gbr: () => renderedRect,
        gvs: () => ({ width: 1024, height: 768 }),
        hit: () => ({ av: false })
      })
    );

    expect(validateSecretTarget(target, "password", "fill")).toMatchObject({
      ok: false,
      why: expect.arrayContaining(["invalid-secret-target:hit-test-unavailable"])
    });
  });

  it("fails closed when strong visual proof is unavailable", async () => {
    document.body.innerHTML = '<input id="target" type="password">';
    const target = document.querySelector("#target") as HTMLInputElement;
    useEnvironment(target, rect(20, 20, 240, 32));

    await expect(
      Promise.resolve(proveVisualVisibility([target]))
    ).resolves.toBe(false);
  });
});
