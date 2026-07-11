export type SecretTargetRole = "username" | "password" | "newPassword" | "totp";
export type SecretTargetValidationMode = "collect" | "fill";

export interface RenderHitTestResult {
  av: boolean;
  t?: Element | null;
}

export type FallbackHitTestResult = "visible" | "occluded" | "unknown";

export interface RenderEnvironment {
  gcr(element: HTMLElement): readonly DOMRect[];
  gbr(element: HTMLElement): DOMRect;
  gvs(documentRef: Document): { width: number; height: number };
  hit(
    root: Document | ShadowRoot,
    x: number,
    y: number
  ): RenderHitTestResult;
  fht?(
    element: HTMLElement,
    points: readonly RenderPoint[]
  ): FallbackHitTestResult;
  vvp?(
    elements: readonly HTMLElement[]
  ): boolean | Promise<boolean>;
}

export interface BasicRenderFacts {
  vw: boolean;
  fl: boolean;
  why: string[];
  fr: string[];
  rdr: DOMRect | null;
  vpr: DOMRect | null;
}

export type BasicRenderFactsGetter = (
  element: HTMLElement
) => BasicRenderFacts;

export interface SecretTargetValidation {
  ok: boolean;
  r: SecretTargetRole;
  m: SecretTargetValidationMode;
  why: string[];
  fx: BasicRenderFacts;
}

export interface RenderPoint {
  x: number;
  y: number;
}

const MIN_SECRET_TARGET_SIZE_PX = 8;
const MIN_VISIBLE_OPACITY = 0.01;
const VISIBILITY_PROOF_TIMEOUT_MS = 2_000;
const environmentRegistryKey = Symbol.for("vaultkern.autofill.renderEnvironments");

function environmentRegistry() {
  const globalWithRegistry = globalThis as typeof globalThis &
    Record<symbol, WeakMap<Document, RenderEnvironment> | undefined>;
  if (!globalWithRegistry[environmentRegistryKey]) {
    Object.defineProperty(globalWithRegistry, environmentRegistryKey, {
      configurable: true,
      value: new WeakMap<Document, RenderEnvironment>()
    });
  }
  return globalWithRegistry[environmentRegistryKey]!;
}

function addReason(reasons: string[], reason: string) {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

function realBrowserEnvironment(): RenderEnvironment {
  return {
    gcr: (element) => Array.from(element.getClientRects()),
    gbr: (element) => element.getBoundingClientRect(),
    gvs: (documentRef) => ({
      width:
        documentRef.defaultView?.innerWidth ?? documentRef.documentElement.clientWidth,
      height:
        documentRef.defaultView?.innerHeight ?? documentRef.documentElement.clientHeight
    }),
    hit: (root, x, y) => {
      const hitTester = (root as Document & {
        elementFromPoint?: (x: number, y: number) => Element | null;
      }).elementFromPoint;
      if (typeof hitTester !== "function") {
        return { av: false };
      }
      return { av: true, t: hitTester.call(root, x, y) };
    }
  };
}

function environmentFor(element: HTMLElement) {
  return environmentRegistry().get(element.ownerDocument) ?? realBrowserEnvironment();
}

export function proveVisualVisibility(
  elements: readonly HTMLElement[]
): boolean | Promise<boolean> {
  const targetSet = new Set(elements);
  const targets = [...targetSet];
  if (!targets.length) {
    return true;
  }
  const documentRef = targets[0].ownerDocument;
  if (targets.some((target) => target.ownerDocument !== documentRef)) {
    return false;
  }
  const injectedProof = environmentFor(targets[0]).vvp;
  if (injectedProof) {
    return injectedProof(targets);
  }

  const ownerWindow = documentRef.defaultView;
  if (
    ownerWindow === null ||
    typeof ownerWindow.IntersectionObserver !== "function"
  ) {
    return false;
  }
  const Observer = ownerWindow.IntersectionObserver;

  return new Promise<boolean>((resolve) => {
    let observer: IntersectionObserver | null = null;
    const visible = new Set<Element>();
    const timer = ownerWindow.setTimeout(
      () => finish(false),
      VISIBILITY_PROOF_TIMEOUT_MS
    );
    function finish(result: boolean) {
      clearTimeout(timer);
      observer?.disconnect();
      resolve(result);
    }

    try {
      observer = new Observer(
        (entries) => {
          for (const entry of entries) {
            if (!targetSet.has(entry.target as HTMLElement)) {
              continue;
            }
            const isVisible = (entry as IntersectionObserverEntry & {
              isVisible?: boolean;
            }).isVisible;
            if (typeof isVisible !== "boolean" || !entry.isIntersecting || !isVisible) {
              finish(false);
              return;
            }
            visible.add(entry.target);
          }
          if (visible.size === targets.length) {
            finish(true);
          }
        },
        {
          trackVisibility: true,
          delay: 100
        } as IntersectionObserverInit
      );
      targets.forEach((target) => observer?.observe(target));
    } catch {
      finish(false);
    }
  });
}

export function registerRenderEnvironment(
  documentRef: Document,
  environment: RenderEnvironment
) {
  const environments = environmentRegistry();
  const previous = environments.get(documentRef);
  environments.set(documentRef, environment);
  return () => {
    if (previous) {
      environments.set(documentRef, previous);
    } else {
      environments.delete(documentRef);
    }
  };
}

export function withRenderEnvironment<T>(
  documentRef: Document,
  environment: RenderEnvironment | undefined,
  operation: () => T
) {
  if (!environment) {
    return operation();
  }
  const unregister = registerRenderEnvironment(documentRef, environment);
  try {
    return operation();
  } finally {
    unregister();
  }
}

function parentElementOrShadowHost(element: HTMLElement) {
  if (element.assignedSlot) {
    return element.assignedSlot;
  }
  const parent = element.parentElement;
  if (parent) {
    return parent;
  }
  const root = element.getRootNode();
  const shadowHost = (root as Node & { host?: Element }).host;
  return root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && shadowHost?.nodeType === Node.ELEMENT_NODE
    ? (shadowHost as HTMLElement)
    : null;
}

function finiteOpacity(value: string) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 1;
}

function hasPaintChangingEffect(style: CSSStyleDeclaration | undefined) {
  if (!style) {
    return false;
  }
  const values = [
    style.filter,
    style.maskImage,
    style.getPropertyValue("mask-image"),
    style.getPropertyValue("-webkit-mask-image")
  ];
  return values.some(
    (value) =>
      typeof value === "string" &&
      !/^(none)?$/.test(value.trim())
  );
}

function rectHasArea(rect: DOMRect) {
  return (
    Number.isFinite(rect.left) &&
    Number.isFinite(rect.top) &&
    Number.isFinite(rect.width) &&
    Number.isFinite(rect.height) &&
    rect.width > 0 &&
    rect.height > 0
  );
}

function rectFromEdges(left: number, top: number, right: number, bottom: number) {
  return {
    x: left,
    y: top,
    left,
    top,
    right,
    bottom,
    width: right - left,
    height: bottom - top,
    toJSON: () => ({})
  } as DOMRect;
}

function intersectRect(
  rect: DOMRect,
  viewport: { width: number; height: number }
): DOMRect | null {
  const left = Math.max(0, rect.left);
  const top = Math.max(0, rect.top);
  const right = Math.min(viewport.width, rect.right);
  const bottom = Math.min(viewport.height, rect.bottom);
  if (right <= left || bottom <= top) {
    return null;
  }
  return rectFromEdges(left, top, right, bottom);
}

function unionRects(rects: readonly DOMRect[]) {
  if (!rects.length) {
    return null;
  }
  const left = Math.min(...rects.map((rect) => rect.left));
  const top = Math.min(...rects.map((rect) => rect.top));
  const right = Math.max(...rects.map((rect) => rect.right));
  const bottom = Math.max(...rects.map((rect) => rect.bottom));
  return rectFromEdges(left, top, right, bottom);
}

type AncestorRenderFacts = [
  style: CSSStyleDeclaration | undefined,
  flags: number,
  opacity: number
];

export function createBasicRenderFactsGetter(): BasicRenderFactsGetter {
  const ancestors = new WeakMap<HTMLElement, AncestorRenderFacts>();
  return (element) => {
    const path: HTMLElement[] = [];
    let current: HTMLElement | null = element;
    while (current && !ancestors.has(current)) {
      path.push(current);
      current = parentElementOrShadowHost(current);
    }
    let aggregate: AncestorRenderFacts = current
      ? ancestors.get(current)!
      : [undefined, 0, 1];
    while (path.length) {
      const node = path.pop()!;
      const style = node.ownerDocument.defaultView?.getComputedStyle(node);
      aggregate = [
        style,
        aggregate[1] |
          (Boolean(node.hidden) ? 1 : 0) |
          (style?.display === "none" || style?.contentVisibility === "hidden"
            ? 2
            : 0) |
          (hasPaintChangingEffect(style) ? 4 : 0) |
          (node.hasAttribute("inert") ? 8 : 0),
        aggregate[2] * finiteOpacity(style?.opacity ?? "1")
      ];
      ancestors.set(node, aggregate);
    }

    const environment = environmentFor(element);
    const reasons: string[] = [];
    const renderedRects = environment.gcr(element).filter(rectHasArea);
    const boundingRect = environment.gbr(element);
    const renderedRect = unionRects(renderedRects);
    const viewportRect = renderedRect
      ? intersectRect(renderedRect, environment.gvs(element.ownerDocument))
      : null;
    const ancestorFacts = ancestors.get(element)!;
    const elementStyle = ancestorFacts[0];

    if (!element.isConnected) {
      addReason(reasons, "not-viewable:disconnected");
    }
    if (
      element.localName === "input" &&
      (element as HTMLInputElement).type === "hidden"
    ) {
      addReason(reasons, "not-viewable:hidden");
    }
    if (ancestorFacts[1] & 1) {
      addReason(reasons, "not-viewable:hidden");
    }
    if (
      ancestorFacts[1] & 2 ||
      elementStyle?.visibility === "hidden" ||
      elementStyle?.visibility === "collapse"
    ) {
      addReason(reasons, "not-viewable:css");
    }
    if (ancestorFacts[1] & 4) {
      addReason(reasons, "not-viewable:paint-effect");
    }
    if (ancestorFacts[2] <= MIN_VISIBLE_OPACITY) {
      addReason(reasons, "not-viewable:transparent");
    }
    if (!rectHasArea(boundingRect) || renderedRect === null) {
      addReason(reasons, "not-viewable:zero-size");
    }
    if (renderedRect !== null && viewportRect === null) {
      addReason(reasons, "not-viewable:offscreen");
    }

    const fillableReasons: string[] = [];
    const field = element as
      | HTMLInputElement
      | HTMLSelectElement
      | HTMLTextAreaElement;
    if (field.disabled || element.matches(":disabled")) {
      addReason(fillableReasons, "not-fillable:disabled");
    }
    if ("readOnly" in field && field.readOnly) {
      addReason(fillableReasons, "not-fillable:readonly");
    }
    if (ancestorFacts[1] & 8) {
      addReason(fillableReasons, "not-fillable:inert");
    }
    if (elementStyle?.pointerEvents === "none") {
      addReason(fillableReasons, "not-fillable:pointer-events");
    }
    return {
      vw: !reasons.length,
      fl: !fillableReasons.length,
      why: reasons,
      fr: fillableReasons,
      rdr: renderedRect,
      vpr: viewportRect
    };
  };
}

export function getBasicRenderFacts(element: HTMLElement): BasicRenderFacts {
  return createBasicRenderFactsGetter()(element);
}

function samplePoints(rect: DOMRect): RenderPoint[] {
  const insetX = Math.min(4, rect.width / 4);
  const insetY = Math.min(4, rect.height / 4);
  return [
    { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 },
    { x: rect.left + insetX, y: rect.top + insetY },
    { x: rect.right - insetX, y: rect.top + insetY },
    { x: rect.left + insetX, y: rect.bottom - insetY },
    { x: rect.right - insetX, y: rect.bottom - insetY }
  ];
}

function targetOwnsHit(element: HTMLElement, target: Element) {
  if (target === element) {
    return true;
  }
  return (
    element.contains(target) &&
    target.matches(
      "input,select,textarea,button,a[href],[contenteditable]:not([contenteditable='false']),[tabindex]:not([tabindex='-1'])"
    )
  );
}

function hitTestFootprints(rect: DOMRect) {
  const size = MIN_SECRET_TARGET_SIZE_PX;
  const halfSize = size / 2;
  // Chromium quantizes fractional hit-test coordinates. Left/top are inclusive;
  // sample right/bottom at the final CSS pixel inside their half-open edges.
  const farEdgeInset = 1;
  const boxes = [
    {
      left: rect.left + rect.width / 2 - halfSize,
      top: rect.top + rect.height / 2 - halfSize
    },
    { left: rect.left, top: rect.top },
    { left: rect.right - size, top: rect.top },
    { left: rect.left, top: rect.bottom - size },
    { left: rect.right - size, top: rect.bottom - size }
  ];
  return boxes.map((box) => {
    const right = box.left + size;
    const bottom = box.top + size;
    return [
      { x: box.left + halfSize, y: box.top + halfSize },
      { x: box.left, y: box.top },
      { x: right - farEdgeInset, y: box.top },
      { x: box.left, y: bottom - farEdgeInset },
      { x: right - farEdgeInset, y: bottom - farEdgeInset }
    ];
  });
}

function owningHitTestRoot(element: HTMLElement) {
  const root = element.getRootNode();
  return root.nodeType === Node.DOCUMENT_FRAGMENT_NODE || root.nodeType === Node.DOCUMENT_NODE
    ? (root as Document | ShadowRoot)
    : element.ownerDocument;
}

export function validateSecretTarget(
  element: HTMLElement,
  role: SecretTargetRole,
  mode: SecretTargetValidationMode
): SecretTargetValidation {
  const facts = getBasicRenderFacts(element);
  const reasons = [...facts.why, ...facts.fr];
  const targetRect = facts.vpr;

  if (
    targetRect !== null &&
    (targetRect.width < MIN_SECRET_TARGET_SIZE_PX ||
      targetRect.height < MIN_SECRET_TARGET_SIZE_PX)
  ) {
    addReason(reasons, "invalid-secret-target:tiny");
  }

  if (!reasons.length && targetRect !== null) {
    const environment = environmentFor(element);
    const points = samplePoints(targetRect);
    const root = owningHitTestRoot(element);
    let hitTestingAvailable = false;
    let hitTargetVisible = false;
    let anyTargetHit = false;
    for (const footprint of hitTestFootprints(targetRect)) {
      let completeFootprint = true;
      for (const point of footprint) {
        const hit = environment.hit(root, point.x, point.y);
        if (!hit.av) {
          completeFootprint = false;
          continue;
        }
        hitTestingAvailable = true;
        if (hit.t && targetOwnsHit(element, hit.t)) {
          anyTargetHit = true;
        } else {
          completeFootprint = false;
        }
      }
      if (completeFootprint) {
        hitTargetVisible = true;
        break;
      }
    }

    if (hitTestingAvailable) {
      if (!hitTargetVisible) {
        addReason(
          reasons,
          anyTargetHit
            ? "invalid-secret-target:insufficient-hit-area"
            : "invalid-secret-target:occluded"
        );
      }
    } else {
      const fallback = environment.fht?.(element, points) ?? "unknown";
      if (fallback === "occluded") {
        addReason(reasons, "invalid-secret-target:occluded");
      } else if (fallback === "unknown") {
        addReason(reasons, "invalid-secret-target:hit-test-unavailable");
      }
    }
  }

  return {
    ok: !reasons.length,
    r: role,
    m: mode,
    why: reasons,
    fx: facts
  };
}
