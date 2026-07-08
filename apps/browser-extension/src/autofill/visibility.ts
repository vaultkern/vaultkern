export interface FieldVisibilityResult {
  viewable: boolean;
  reasons: string[];
}

export interface FieldFillabilityResult {
  fillable: boolean;
  reasons: string[];
}

const OFFSCREEN_OFFSET_PX = 1000;
const MIN_CREDENTIAL_FIELD_SIZE_PX = 8;
const CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX = MIN_CREDENTIAL_FIELD_SIZE_PX;
const MIN_CLIPPED_VISIBLE_FRACTION = 0.05;
const MIN_VISIBLE_OPACITY = 0.01;
const TRANSFORM_COLLAPSE_EPSILON = 0.001;

interface CssNumericUnits {
  emPx?: number;
  remPx?: number;
  viewportWidth?: number;
  viewportHeight?: number;
}

function addReason(reasons: string[], reason: string) {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

function numericCssValue(
  value: string | undefined,
  units: CssNumericUnits = {}
) {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed || trimmed === "auto") {
    return null;
  }
  const match = trimmed.match(/^(-?\d+(?:\.\d+)?)([a-z%]*)$/);
  if (!match) {
    return null;
  }

  const parsed = Number.parseFloat(match[1]);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  const unit = match[2];
  if (unit === "" || unit === "px") {
    return parsed;
  }
  if (unit === "em") {
    return parsed * (units.emPx ?? 16);
  }
  if (unit === "rem") {
    return parsed * (units.remPx ?? units.emPx ?? 16);
  }
  if (unit === "vw" || unit === "svw" || unit === "lvw" || unit === "dvw") {
    return units.viewportWidth === undefined ? parsed : (parsed * units.viewportWidth) / 100;
  }
  if (unit === "vh" || unit === "svh" || unit === "lvh" || unit === "dvh") {
    return units.viewportHeight === undefined ? parsed : (parsed * units.viewportHeight) / 100;
  }
  if (unit === "vmin") {
    return units.viewportWidth === undefined || units.viewportHeight === undefined
      ? parsed
      : (parsed * Math.min(units.viewportWidth, units.viewportHeight)) / 100;
  }
  if (unit === "vmax") {
    return units.viewportWidth === undefined || units.viewportHeight === undefined
      ? parsed
      : (parsed * Math.max(units.viewportWidth, units.viewportHeight)) / 100;
  }

  return parsed;
}

function computedCssValue(
  computed: string | undefined,
  inline: string | undefined,
  units: { emPx?: number; remPx?: number } = {}
) {
  return numericCssValue(computed, units) ?? numericCssValue(inline, units);
}

function cssOpacityValue(value: string | undefined) {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed) {
    return null;
  }
  if (trimmed.endsWith("%")) {
    const parsed = Number.parseFloat(trimmed.slice(0, -1));
    return Number.isFinite(parsed) ? parsed / 100 : null;
  }
  const parsed = Number.parseFloat(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function cssPropertyValue(
  style: CSSStyleDeclaration | undefined,
  element: HTMLElement,
  property: string
) {
  const inlineStyleText = element.getAttribute("style") ?? "";
  const inlineMatch = inlineStyleText.match(
    new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`, "i")
  );
  return (
    style?.getPropertyValue(property).trim() ||
    element.style.getPropertyValue(property).trim() ||
    inlineMatch?.[1]?.trim() ||
    ""
  );
}

function parentElementOrShadowHost(element: HTMLElement) {
  if (element.assignedSlot) {
    return element.assignedSlot;
  }

  if (element.parentElement) {
    return element.parentElement;
  }

  const root = element.getRootNode() as Node & { host?: unknown };
  if (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && "host" in root) {
    const host = root.host as Node | undefined;
    if (host?.nodeType === Node.ELEMENT_NODE) {
      return host as HTMLElement;
    }
  }

  return null;
}

function isClosedDetailsContent(element: HTMLElement, current: HTMLElement) {
  if (current.tagName.toLowerCase() !== "details" || current.hasAttribute("open")) {
    return false;
  }

  const summary = Array.from(current.children).find(
    (child) => child.tagName.toLowerCase() === "summary"
  );
  return summary === undefined || !summary.contains(element);
}

function isUnslottedShadowHostChild(element: HTMLElement) {
  return Boolean(element.parentElement?.shadowRoot && !element.assignedSlot);
}

function hasExplicitVisibleDescendantOverride(element: HTMLElement, ancestor: HTMLElement) {
  let current: HTMLElement | null = element;
  while (current && current !== ancestor) {
    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    if (current.style.visibility === "visible" || style?.visibility === "visible") {
      return true;
    }
    current = parentElementOrShadowHost(current);
  }
  return false;
}

function isClippedZeroSizeAncestor(
  current: HTMLElement,
  width: number | null,
  height: number | null,
  style: CSSStyleDeclaration | undefined
) {
  if (width !== 0 || height !== 0) {
    return false;
  }
  return clipsDescendantPaint(current, style);
}

function isLargeOffscreenOffset(value: number | null) {
  return value !== null && Math.abs(value) >= OFFSCREEN_OFFSET_PX;
}

function isNegativeOffset(value: number | null) {
  return value !== null && value < 0;
}

function isPositiveOffset(value: number | null) {
  return value !== null && value > 0;
}

function isMeaningfulCssValue(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized !== "" && normalized !== "auto" && normalized !== "none";
}

function hasClippingOverflow(current: HTMLElement, style: CSSStyleDeclaration | undefined) {
  const overflow = [
    cssPropertyValue(style, current, "overflow"),
    cssPropertyValue(style, current, "overflow-x"),
    cssPropertyValue(style, current, "overflow-y")
  ].join(" ");
  return /\b(hidden|clip)\b/.test(overflow);
}

function hasPaintContainment(current: HTMLElement, style: CSSStyleDeclaration | undefined) {
  const contain = cssPropertyValue(style, current, "contain").toLowerCase();
  return /\b(paint|content|strict)\b/.test(contain);
}

function clipsDescendantPaint(current: HTMLElement, style: CSSStyleDeclaration | undefined) {
  return hasClippingOverflow(current, style) || hasPaintContainment(current, style);
}

function isClippedTinyAncestor(
  current: HTMLElement,
  width: number | null,
  height: number | null,
  style: CSSStyleDeclaration | undefined
) {
  if (!clipsDescendantPaint(current, style)) {
    return false;
  }
  return (
    (width !== null && width <= CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX) ||
    (height !== null && height <= CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX)
  );
}

function transformTranslateOffset(
  value: string | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  let x = 0;
  let y = 0;
  let found = false;
  const transforms = normalized.matchAll(
    /(matrix3d|matrix|translate3d|translatex|translatey|translate)\(([^)]*)\)/g
  );
  const rect = current.getBoundingClientRect();
  for (const transform of transforms) {
    const name = transform[1];
    const args = splitCssFunctionArgs(transform[2]);
    found = true;

    if (name === "matrix") {
      const values = args.map((arg) => numericCssValue(arg, units));
      x += values[4] ?? 0;
      y += values[5] ?? 0;
    } else if (name === "matrix3d") {
      const values = args.map((arg) => numericCssValue(arg, units));
      x += values[12] ?? 0;
      y += values[13] ?? 0;
    } else if (name === "translatex") {
      x += cssLengthToPx(args[0] ?? "0", rect.width, units) ?? 0;
    } else if (name === "translatey") {
      y += cssLengthToPx(args[0] ?? "0", rect.height, units) ?? 0;
    } else {
      x += cssLengthToPx(args[0] ?? "0", rect.width, units) ?? 0;
      y += cssLengthToPx(args[1] ?? "0", rect.height, units) ?? 0;
    }
  }

  return found ? { x, y } : null;
}

function translateLonghandOffset(
  value: string | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  const rect = current.getBoundingClientRect();
  const values = splitCssFunctionArgs(normalized);
  const x = values[0] === undefined ? null : cssLengthToPx(values[0], rect.width, units);
  const y = values[1] === undefined ? 0 : cssLengthToPx(values[1], rect.height, units);
  if (x === null && y === null) {
    return null;
  }
  return { x: x ?? 0, y: y ?? 0 };
}

function combinedTranslateOffset(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const transform = transformTranslateOffset(
    cssPropertyValue(style, current, "transform"),
    current,
    units
  );
  const translate = translateLonghandOffset(
    cssPropertyValue(style, current, "translate"),
    current,
    units
  );
  if (!transform && !translate) {
    return null;
  }
  return {
    x: (transform?.x ?? 0) + (translate?.x ?? 0),
    y: (transform?.y ?? 0) + (translate?.y ?? 0)
  };
}

function isCollapsedScale(value: number | null) {
  return value !== null && Math.abs(value) <= TRANSFORM_COLLAPSE_EPSILON;
}

function transformFullyCollapses(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  const transforms = normalized.matchAll(
    /(matrix3d|matrix|scale3d|scalex|scaley|scale)\(([^)]*)\)/g
  );
  for (const transform of transforms) {
    const name = transform[1];
    const values = transform[2]
      .split(/[,\s]+/)
      .filter(Boolean)
      .map((arg) => numericCssValue(arg, units));

    if (name === "matrix") {
      const [a, b, c, d] = values;
      if (a !== null && b !== null && c !== null && d !== null) {
        const determinant = a * d - b * c;
        if (Math.abs(determinant) <= TRANSFORM_COLLAPSE_EPSILON) {
          return true;
        }
      }
    } else if (name === "matrix3d") {
      const [m11, m12, , , m21, m22] = values;
      if (m11 !== null && m12 !== null && m21 !== null && m22 !== null) {
        const determinant = m11 * m22 - m12 * m21;
        if (Math.abs(determinant) <= TRANSFORM_COLLAPSE_EPSILON) {
          return true;
        }
      }
    } else if (name === "scale") {
      const scaleX = values[0] ?? null;
      const scaleY = values[1] ?? scaleX;
      if (isCollapsedScale(scaleX) || isCollapsedScale(scaleY)) {
        return true;
      }
    } else if (name === "scale3d") {
      if (isCollapsedScale(values[0] ?? null) || isCollapsedScale(values[1] ?? null)) {
        return true;
      }
    } else if (name === "scalex") {
      if (isCollapsedScale(values[0] ?? null)) {
        return true;
      }
    } else if (name === "scaley") {
      if (isCollapsedScale(values[0] ?? null)) {
        return true;
      }
    }
  }

  return false;
}

function scaleLonghandFullyCollapses(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  const values = normalized
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => numericCssValue(part, units));
  const scaleX = values[0] ?? null;
  const scaleY = values[1] ?? scaleX;
  return isCollapsedScale(scaleX) || isCollapsedScale(scaleY);
}

function transformStyleFullyCollapses(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  return (
    transformFullyCollapses(cssPropertyValue(style, current, "transform"), units) ||
    scaleLonghandFullyCollapses(cssPropertyValue(style, current, "scale"), units)
  );
}

function zoomStyleFullyCollapses(style: CSSStyleDeclaration | undefined, current: HTMLElement) {
  const zoom = cssOpacityValue(cssPropertyValue(style, current, "zoom"));
  return zoom !== null && zoom <= TRANSFORM_COLLAPSE_EPSILON;
}

function cssAngleDegrees(value: string | undefined) {
  const match = value?.trim().toLowerCase().match(/^(-?\d+(?:\.\d+)?)(deg|turn|rad|grad)?$/);
  if (!match) {
    return null;
  }
  const parsed = Number.parseFloat(match[1]);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  const unit = match[2] ?? "deg";
  if (unit === "turn") {
    return parsed * 360;
  }
  if (unit === "rad") {
    return (parsed * 180) / Math.PI;
  }
  if (unit === "grad") {
    return parsed * 0.9;
  }
  return parsed;
}

function normalizedDegrees(degrees: number) {
  return ((degrees % 360) + 360) % 360;
}

function angleIsQuarterTurn(value: string | undefined) {
  const degrees = cssAngleDegrees(value);
  if (degrees === null) {
    return false;
  }
  const normalized = normalizedDegrees(degrees);
  return (
    Math.abs(normalized - 90) <= TRANSFORM_COLLAPSE_EPSILON ||
    Math.abs(normalized - 270) <= TRANSFORM_COLLAPSE_EPSILON
  );
}

function angleIsHalfTurn(value: string | undefined) {
  const degrees = cssAngleDegrees(value);
  if (degrees === null) {
    return false;
  }
  return Math.abs(normalizedDegrees(degrees) - 180) <= TRANSFORM_COLLAPSE_EPSILON;
}

function rotateTransformFullyCollapses(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  for (const transform of normalized.matchAll(/(rotate3d|rotatex|rotatey)\(([^)]*)\)/g)) {
    const name = transform[1];
    const args = splitCssFunctionArgs(transform[2]);
    if ((name === "rotatex" || name === "rotatey") && angleIsQuarterTurn(args[0])) {
      return true;
    }
    if (name === "rotate3d" && args.length >= 4) {
      const [x, y, z, angle] = args;
      const rotatesIntoEdge =
        (numericCssValue(x) ?? 0) !== 0 || (numericCssValue(y) ?? 0) !== 0;
      const hasZRotation = (numericCssValue(z) ?? 0) !== 0;
      if (rotatesIntoEdge && !hasZRotation && angleIsQuarterTurn(angle)) {
        return true;
      }
    }
  }

  return false;
}

function rotateLonghandFullyCollapses(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }
  const args = splitCssFunctionArgs(normalized);
  if (args.length === 2 && (args[0] === "x" || args[0] === "y")) {
    return angleIsQuarterTurn(args[1]);
  }
  if (args.length >= 4) {
    const [x, y, z, angle] = args;
    const rotatesIntoEdge =
      (numericCssValue(x) ?? 0) !== 0 || (numericCssValue(y) ?? 0) !== 0;
    const hasZRotation = (numericCssValue(z) ?? 0) !== 0;
    return rotatesIntoEdge && !hasZRotation && angleIsQuarterTurn(angle);
  }
  return false;
}

function rotationTurnsBackfaceAway(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  for (const matrix of normalized.matchAll(/matrix3d\(([^)]*)\)/g)) {
    const values = splitCssFunctionArgs(matrix[1]).map((arg) => numericCssValue(arg));
    if ((values[10] ?? 1) < 0) {
      return true;
    }
  }

  for (const transform of normalized.matchAll(/(rotate3d|rotatex|rotatey)\(([^)]*)\)/g)) {
    const name = transform[1];
    const args = splitCssFunctionArgs(transform[2]);
    if ((name === "rotatex" || name === "rotatey") && angleIsHalfTurn(args[0])) {
      return true;
    }
    if (name === "rotate3d" && args.length >= 4) {
      const [x, y, z, angle] = args;
      const flipsPlane =
        (numericCssValue(x) ?? 0) !== 0 || (numericCssValue(y) ?? 0) !== 0;
      const hasZRotation = (numericCssValue(z) ?? 0) !== 0;
      if (flipsPlane && !hasZRotation && angleIsHalfTurn(angle)) {
        return true;
      }
    }
  }

  const args = splitCssFunctionArgs(normalized);
  if (args.length === 2 && (args[0] === "x" || args[0] === "y")) {
    return angleIsHalfTurn(args[1]);
  }
  if (args.length >= 4) {
    const [x, y, z, angle] = args;
    const flipsPlane = (numericCssValue(x) ?? 0) !== 0 || (numericCssValue(y) ?? 0) !== 0;
    const hasZRotation = (numericCssValue(z) ?? 0) !== 0;
    return flipsPlane && !hasZRotation && angleIsHalfTurn(angle);
  }
  return false;
}

function rotateStyleFullyCollapses(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  return (
    rotateTransformFullyCollapses(cssPropertyValue(style, current, "transform")) ||
    rotateLonghandFullyCollapses(cssPropertyValue(style, current, "rotate"))
  );
}

function backfaceStyleHidesElement(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  const backface = cssPropertyValue(style, current, "backface-visibility")
    .trim()
    .toLowerCase();
  return (
    backface === "hidden" &&
    (rotationTurnsBackfaceAway(cssPropertyValue(style, current, "transform")) ||
      rotationTurnsBackfaceAway(cssPropertyValue(style, current, "rotate")))
  );
}

function filterOpacityValue(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  let opacity = 1;
  let found = false;
  for (const match of normalized.matchAll(/opacity\(([^)]*)\)/g)) {
    const value = cssOpacityValue(match[1]);
    if (value !== null) {
      opacity *= value;
      found = true;
    }
  }

  return found ? opacity : null;
}

function localCssUrlReferenceIds(value: string | undefined) {
  const references: string[] = [];
  const normalized = value?.trim();
  if (!normalized) {
    return references;
  }
  for (const match of normalized.matchAll(/url\(\s*(['"]?)#([^'")]+)\1\s*\)/gi)) {
    references.push(match[2]);
  }
  return references;
}

function svgFilterSuppressesPaint(current: HTMLElement, value: string | undefined) {
  for (const id of localCssUrlReferenceIds(value)) {
    const filter = current.ownerDocument.getElementById(id);
    if (!filter) {
      continue;
    }
    const alphaFunctions = Array.from(filter.querySelectorAll("*")).filter(
      (child) => child.tagName.toLowerCase() === "fefunca"
    );
    if (
      alphaFunctions.some((func) => {
        const type = func.getAttribute("type")?.toLowerCase();
        const tableValues = (func.getAttribute("tableValues") ?? "")
          .trim()
          .split(/\s+/)
          .map(Number);
        const slope = Number(func.getAttribute("slope") ?? "1");
        const intercept = Number(func.getAttribute("intercept") ?? "0");
        const amplitude = Number(func.getAttribute("amplitude") ?? "1");
        const offset = Number(func.getAttribute("offset") ?? "0");
        return (
          (type === "table" &&
            tableValues.length > 0 &&
            tableValues.every((value) => Number.isFinite(value) && value <= 0)) ||
          (type === "discrete" &&
            tableValues.length > 0 &&
            tableValues.every((value) => Number.isFinite(value) && value <= 0)) ||
          (type === "linear" && slope <= 0 && intercept <= 0) ||
          (type === "gamma" && amplitude <= 0 && offset <= 0)
        );
      })
    ) {
      return true;
    }
    const colorMatrices = Array.from(filter.querySelectorAll("*")).filter(
      (child) => child.tagName.toLowerCase() === "fecolormatrix"
    );
    if (
      colorMatrices.some((matrix) => {
        const type = matrix.getAttribute("type")?.toLowerCase() ?? "matrix";
        const values = (matrix.getAttribute("values") ?? "")
          .trim()
          .split(/[\s,]+/)
          .filter(Boolean)
          .map(Number);
        return (
          type === "matrix" &&
          values.length >= 20 &&
          values.slice(15, 20).every((value) => Number.isFinite(value) && value <= 0)
        );
      })
    ) {
      return true;
    }
  }
  return false;
}

function cssColorLooksTransparent(value: string) {
  const normalized = value.trim().toLowerCase();
  return (
    normalized === "transparent" ||
    normalized.startsWith("transparent ") ||
    /^rgba\([^)]*,\s*0(?:\.0+)?\s*\)$/.test(normalized) ||
    /^rgba?\([^)]*\/\s*0(?:%|\.0+)?\s*\)$/.test(normalized) ||
    (/^#[0-9a-f]{4}$/.test(normalized) && normalized.endsWith("0")) ||
    (/^#[0-9a-f]{8}$/.test(normalized) && normalized.endsWith("00"))
  );
}

function cssPaintListLooksEmpty(value: string) {
  const normalized = value.trim().toLowerCase();
  return (
    !normalized ||
    splitCssCommaList(normalized).every((part) => {
      const item = part.trim();
      return item === "" || item === "none";
    })
  );
}

function cssLengthLooksZero(
  value: string,
  units: { emPx?: number; remPx?: number } = {}
) {
  const parsed = numericCssValue(value, units);
  return parsed !== null && parsed <= 0;
}

function cssLinePaints(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  prefix: string,
  units: { emPx?: number; remPx?: number } = {}
) {
  const lineStyle = cssPropertyValue(style, current, `${prefix}-style`).toLowerCase();
  const lineWidth = cssPropertyValue(style, current, `${prefix}-width`);
  const lineColor = cssPropertyValue(style, current, `${prefix}-color`);
  return (
    lineStyle !== "" &&
    lineStyle !== "none" &&
    lineStyle !== "hidden" &&
    !cssLengthLooksZero(lineWidth, units) &&
    !cssColorLooksTransparent(lineColor)
  );
}

function fieldTextPaintIsSuppressed(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const fontSize = numericCssValue(cssPropertyValue(style, current, "font-size"), units);
  if (fontSize !== null && fontSize <= 0) {
    return true;
  }

  const rect = current.getBoundingClientRect();
  const textIndent = cssLengthToPx(
    cssPropertyValue(style, current, "text-indent"),
    rect.width,
    units
  );
  if (
    textIndent !== null &&
    (Math.abs(textIndent) >= OFFSCREEN_OFFSET_PX ||
      (hasMeaningfulClientRect(rect) && Math.abs(textIndent) >= rect.width))
  ) {
    return true;
  }

  const textFillColor = cssPropertyValue(style, current, "-webkit-text-fill-color");
  const textColor =
    isMeaningfulCssValue(textFillColor) && textFillColor.toLowerCase() !== "currentcolor"
      ? textFillColor
      : cssPropertyValue(style, current, "color");
  return cssColorLooksTransparent(textColor);
}

function fieldBackgroundPaintIsTransparent(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  return (
    cssPaintListLooksEmpty(cssPropertyValue(style, current, "background-image")) &&
    cssColorLooksTransparent(cssPropertyValue(style, current, "background-color"))
  );
}

function fieldBorderPaintIsTransparent(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  return ["top", "right", "bottom", "left"].every(
    (side) => !cssLinePaints(style, current, `border-${side}`, units)
  );
}

function fieldOutlinePaintIsTransparent(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  return !cssLinePaints(style, current, "outline", units);
}

function fieldChromePaintIsTransparent(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  return (
    fieldTextPaintIsSuppressed(style, current, units) &&
    fieldBackgroundPaintIsTransparent(style, current) &&
    fieldBorderPaintIsTransparent(style, current, units) &&
    fieldOutlinePaintIsTransparent(style, current, units) &&
    cssPaintListLooksEmpty(cssPropertyValue(style, current, "box-shadow")) &&
    cssPaintListLooksEmpty(cssPropertyValue(style, current, "text-shadow"))
  );
}

function cssColorLooksBlack(value: string | null) {
  const normalized = (value ?? "black").trim().toLowerCase();
  if (normalized === "black" || normalized === "#000" || normalized === "#000000") {
    return true;
  }
  const rgbMatch = normalized.match(/^rgba?\(([^)]*)\)$/);
  if (!rgbMatch) {
    return false;
  }
  const channels = rgbMatch[1]
    .replace(/\//g, " ")
    .split(/[,\s]+/)
    .filter(Boolean)
    .slice(0, 3)
    .map(Number);
  return channels.length === 3 && channels.every((channel) => channel === 0);
}

function maskImageFullyTransparent(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }
  const gradientMatch = normalized.match(/^[a-z-]*gradient\((.*)\)$/);
  if (!gradientMatch) {
    return false;
  }
  const colorStops = splitCssCommaList(gradientMatch[1]).filter(
    (part) => !part.trim().startsWith("to ") && cssAngleDegrees(part.trim()) === null
  );
  return colorStops.length > 0 && colorStops.every(cssColorLooksTransparent);
}

function maskRepeatRepeatsAxis(value: string | undefined, axis: "x" | "y") {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return true;
  }
  if (normalized === "repeat-x") {
    return axis === "x";
  }
  if (normalized === "repeat-y") {
    return axis === "y";
  }

  const tokens = splitCssFunctionArgs(normalized);
  const first = tokens[0] ?? "repeat";
  const second = tokens[1] ?? first;
  const axisValue = axis === "x" ? first : second;
  return axisValue !== "no-repeat";
}

function maskSizeSuppressesPaint(
  value: string | undefined,
  repeatValue: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "auto") {
    return false;
  }
  const repeatLayers = splitCssCommaList(repeatValue?.trim().toLowerCase() ?? "");
  return splitCssCommaList(normalized).some((layer, index) => {
    const repeatLayer = repeatLayers[index] ?? repeatLayers[repeatLayers.length - 1];
    const [width, height = width] = splitCssFunctionArgs(layer);
    const widthPx = width === undefined ? null : cssLengthToPx(width, 0, units);
    const heightPx = height === undefined ? null : cssLengthToPx(height, 0, units);
    return (
      (widthPx !== null && widthPx <= 0) ||
      (heightPx !== null && heightPx <= 0) ||
      (widthPx !== null &&
        widthPx <= MIN_CREDENTIAL_FIELD_SIZE_PX &&
        !maskRepeatRepeatsAxis(repeatLayer, "x")) ||
      (heightPx !== null &&
        heightPx <= MIN_CREDENTIAL_FIELD_SIZE_PX &&
        !maskRepeatRepeatsAxis(repeatLayer, "y"))
    );
  });
}

function maskLayerValue(layers: string[], index: number) {
  return layers[index] ?? layers[layers.length - 1];
}

function maskDimensionToPx(
  value: string | undefined,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (
    !normalized ||
    normalized === "auto" ||
    normalized === "cover" ||
    normalized === "contain"
  ) {
    return axisSize;
  }
  return cssLengthToPx(normalized, axisSize, units) ?? axisSize;
}

function maskLayerSize(
  value: string | undefined,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const [width, height] = splitCssFunctionArgs(value?.trim().toLowerCase() ?? "auto");
  return {
    width: maskDimensionToPx(width, rect.width, units),
    height: maskDimensionToPx(height, rect.height, units)
  };
}

function isPositionKeyword(value: string | undefined) {
  return (
    value === "left" ||
    value === "right" ||
    value === "top" ||
    value === "bottom" ||
    value === "center"
  );
}

function maskPositionAxisComponent(value: string, axis: "x" | "y") {
  const tokens = splitCssFunctionArgs(value.trim().toLowerCase());
  if (tokens.length === 0) {
    return "0%";
  }
  const axisKeywords = axis === "x" ? ["left", "right"] : ["top", "bottom"];
  const oppositeKeywords = axis === "x" ? ["top", "bottom"] : ["left", "right"];
  const keywordIndex = tokens.findIndex((token) => axisKeywords.includes(token));
  if (keywordIndex >= 0) {
    const offset = tokens[keywordIndex + 1];
    return offset !== undefined && !isPositionKeyword(offset)
      ? `${tokens[keywordIndex]} ${offset}`
      : tokens[keywordIndex];
  }
  if (axis === "x") {
    if (oppositeKeywords.includes(tokens[0])) {
      return "50%";
    }
    return tokens[0];
  }
  if (tokens.length === 1) {
    return "50%";
  }
  if (oppositeKeywords.includes(tokens[0]) || tokens[0] === "center") {
    return tokens[1] ?? "50%";
  }
  return tokens[1] ?? "50%";
}

function maskPositionOffsetToPx(
  value: string,
  axisSize: number,
  imageSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const [origin, offsetToken = "0"] = splitCssFunctionArgs(value.trim().toLowerCase());
  const range = axisSize - imageSize;
  if (origin === "left" || origin === "top") {
    return cssLengthToPx(offsetToken, range, units) ?? 0;
  }
  if (origin === "right" || origin === "bottom") {
    return range - (cssLengthToPx(offsetToken, range, units) ?? 0);
  }
  if (origin === "center") {
    return range / 2 + (cssLengthToPx(offsetToken, range, units) ?? 0);
  }
  return cssLengthToPx(value, range, units);
}

function visibleAxisOverlap(axisSize: number, imageSize: number, offset: number) {
  const start = Math.max(0, offset);
  const end = Math.min(axisSize, offset + imageSize);
  return Math.max(0, end - start);
}

function maskAxisPositionSuppressesPaint(
  axisSize: number,
  imageSize: number,
  offset: number | null,
  repeatsAxis: boolean
) {
  if (offset === null || repeatsAxis) {
    return false;
  }
  const overlap = visibleAxisOverlap(axisSize, imageSize, offset);
  return (
    overlap <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    (axisSize > 0 && overlap <= axisSize * MIN_CLIPPED_VISIBLE_FRACTION)
  );
}

function maskPositionSuppressesPaint(
  value: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return false;
  }
  const sizeLayers = splitCssCommaList(sizeValue?.trim().toLowerCase() ?? "");
  const repeatLayers = splitCssCommaList(repeatValue?.trim().toLowerCase() ?? "");
  return splitCssCommaList(normalized).some((layer, index) => {
    const size = maskLayerSize(maskLayerValue(sizeLayers, index), rect, units);
    const repeatLayer = maskLayerValue(repeatLayers, index);
    const x = maskPositionOffsetToPx(
      maskPositionAxisComponent(layer, "x"),
      rect.width,
      size.width,
      units
    );
    const y = maskPositionOffsetToPx(
      maskPositionAxisComponent(layer, "y"),
      rect.height,
      size.height,
      units
    );
    return (
      maskAxisPositionSuppressesPaint(
        rect.width,
        size.width,
        x,
        maskRepeatRepeatsAxis(repeatLayer, "x")
      ) ||
      maskAxisPositionSuppressesPaint(
        rect.height,
        size.height,
        y,
        maskRepeatRepeatsAxis(repeatLayer, "y")
      )
    );
  });
}

function svgElementOpacityValue(shape: Element, attribute: string) {
  const styled = shape as SVGElement;
  return (
    cssOpacityValue(shape.getAttribute(attribute) ?? undefined) ??
    cssOpacityValue(styled.style?.getPropertyValue(attribute)) ??
    1
  );
}

function svgPaintSuppressesMask(shape: Element) {
  const opacity = svgElementOpacityValue(shape, "opacity");
  const fillOpacity = svgElementOpacityValue(shape, "fill-opacity");
  const fill = shape.getAttribute("fill") ?? (shape as SVGElement).style?.fill ?? null;
  return (
    isEffectivelyTransparent(opacity * fillOpacity) ||
    cssColorLooksTransparent(fill ?? "") ||
    cssColorLooksBlack(fill)
  );
}

function svgMaskShapeSuppressesPaint(
  current: HTMLElement,
  shape: Element,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set()
): boolean {
  if (seen.has(shape)) {
    return true;
  }
  seen.add(shape);

  const tagName = shape.tagName.toLowerCase();
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    return target === null || svgMaskShapeSuppressesPaint(current, target, units, seen);
  }
  if (shape.children.length > 0 && (tagName === "g" || tagName === "svg" || tagName === "mask")) {
    return Array.from(shape.children).every((child) =>
      svgMaskShapeSuppressesPaint(current, child, units, seen)
    );
  }
  return svgClipShapeSuppressesField(current, shape, units) || svgPaintSuppressesMask(shape);
}

function svgMaskSuppressesPaint(
  current: HTMLElement,
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  return localCssUrlReferenceIds(value).some((id) => {
    const mask = current.ownerDocument.getElementById(id);
    if (!mask || mask.tagName.toLowerCase() !== "mask") {
      return false;
    }
    const shapes = Array.from(mask.children);
    return (
      shapes.length === 0 ||
      shapes.every((shape) => svgMaskShapeSuppressesPaint(current, shape, units))
    );
  });
}

function maskStyleSuppressesPaint(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const maskImages = [
    cssPropertyValue(style, current, "mask-image"),
    cssPropertyValue(style, current, "-webkit-mask-image"),
    cssPropertyValue(style, current, "mask"),
    cssPropertyValue(style, current, "-webkit-mask")
  ].filter(isMeaningfulCssValue);
  if (!maskImages.length) {
    return false;
  }
  if (maskImages.some(maskImageFullyTransparent)) {
    return true;
  }
  if (maskImages.some((maskImage) => svgMaskSuppressesPaint(current, maskImage, units))) {
    return true;
  }
  return (
    maskSizeSuppressesPaint(
      cssPropertyValue(style, current, "mask-size"),
      cssPropertyValue(style, current, "mask-repeat"),
      units
    ) ||
    maskSizeSuppressesPaint(
      cssPropertyValue(style, current, "-webkit-mask-size"),
      cssPropertyValue(style, current, "-webkit-mask-repeat"),
      units
    ) ||
    maskPositionSuppressesPaint(
      cssPropertyValue(style, current, "mask-position"),
      cssPropertyValue(style, current, "mask-size"),
      cssPropertyValue(style, current, "mask-repeat"),
      current,
      units
    ) ||
    maskPositionSuppressesPaint(
      cssPropertyValue(style, current, "-webkit-mask-position"),
      cssPropertyValue(style, current, "-webkit-mask-size"),
      cssPropertyValue(style, current, "-webkit-mask-repeat"),
      current,
      units
    )
  );
}

function isEffectivelyTransparent(value: number | null) {
  return value !== null && value <= MIN_VISIBLE_OPACITY + 1e-9;
}

function hasMeaningfulClientRect(rect: DOMRect) {
  return rect.width > 0 && rect.height > 0;
}

function viewportSize(element: HTMLElement) {
  const view = element.ownerDocument.defaultView;
  const documentElement = element.ownerDocument.documentElement;
  return {
    width: view?.innerWidth ?? documentElement.clientWidth,
    height: view?.innerHeight ?? documentElement.clientHeight
  };
}

function viewportExitForRect(element: HTMLElement) {
  const rect = element.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const viewport = viewportSize(element);
  return {
    rect,
    viewportWidth: viewport.width,
    viewportHeight: viewport.height,
    beforeX: rect.right <= 0,
    afterX: viewport.width > 0 && rect.left >= viewport.width,
    beforeY: rect.bottom <= 0,
    afterY: viewport.height > 0 && rect.top >= viewport.height
  };
}

function hasMotionPathOffset(style: CSSStyleDeclaration | undefined, current: HTMLElement) {
  return [
    cssPropertyValue(style, current, "offset-path"),
    cssPropertyValue(style, current, "motion-path"),
    cssPropertyValue(style, current, "offset")
  ].some((value) => isMeaningfulCssValue(value) && !value.trim().toLowerCase().startsWith("none"));
}

function hitTargetBelongsToElement(element: HTMLElement, target: Element) {
  if (target === element || element.contains(target)) {
    return true;
  }

  const ownerWindow = element.ownerDocument.defaultView;
  return Boolean(
    ownerWindow &&
      target instanceof ownerWindow.HTMLLabelElement &&
      target.control === element
  );
}

function visibleViewportSamplePoints(element: HTMLElement) {
  const rect = element.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return [];
  }

  const viewport = viewportSize(element);
  const left = Math.max(rect.left, 0);
  const right = Math.min(rect.right, viewport.width);
  const top = Math.max(rect.top, 0);
  const bottom = Math.min(rect.bottom, viewport.height);
  const width = right - left;
  const height = bottom - top;
  if (width <= 0 || height <= 0) {
    return [];
  }

  const insetX = Math.min(4, width / 2);
  const insetY = Math.min(4, height / 2);
  return [
    { x: left + width / 2, y: top + height / 2 },
    { x: left + insetX, y: top + insetY },
    { x: right - insetX, y: top + insetY },
    { x: left + insetX, y: bottom - insetY },
    { x: right - insetX, y: bottom - insetY }
  ];
}

function isFullyOccludedByHitTesting(element: HTMLElement) {
  const elementFromPoint = element.ownerDocument.elementFromPoint;
  if (typeof elementFromPoint !== "function") {
    return false;
  }

  let checkedPoints = 0;
  for (const point of visibleViewportSamplePoints(element)) {
    const target = elementFromPoint.call(element.ownerDocument, point.x, point.y);
    if (!target) {
      continue;
    }
    checkedPoints += 1;
    if (hitTargetBelongsToElement(element, target)) {
      return false;
    }
  }

  return checkedPoints > 0;
}

function pointInsideRect(point: { x: number; y: number }, rect: DOMRect) {
  return (
    hasMeaningfulClientRect(rect) &&
    point.x >= rect.left &&
    point.x <= rect.right &&
    point.y >= rect.top &&
    point.y <= rect.bottom
  );
}

function numericZIndex(value: string | undefined) {
  const trimmed = value?.trim();
  if (!trimmed || trimmed === "auto") {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function documentFollows(element: HTMLElement, candidate: HTMLElement) {
  const followingFlag = element.ownerDocument.defaultView?.Node.DOCUMENT_POSITION_FOLLOWING;
  return Boolean(
    followingFlag !== undefined &&
      (element.compareDocumentPosition(candidate) & followingFlag) !== 0
  );
}

function elementPaintsOverlay(
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined
) {
  const rootStyle = current.ownerDocument.defaultView?.getComputedStyle(
    current.ownerDocument.documentElement
  );
  const emPx = numericCssValue(style?.fontSize || current.style.fontSize) ?? 16;
  const remPx = numericCssValue(rootStyle?.fontSize) ?? emPx;
  const cssUnits = { emPx, remPx };
  const opacity = cssOpacityValue(style?.opacity) ?? cssOpacityValue(current.style.opacity);
  const filter = cssPropertyValue(style, current, "filter");
  return (
    style?.display !== "none" &&
    style?.visibility !== "hidden" &&
    style?.visibility !== "collapse" &&
    !isEffectivelyTransparent(opacity) &&
    !isEffectivelyTransparent(filterOpacityValue(filter)) &&
    !svgFilterSuppressesPaint(current, filter) &&
    !maskStyleSuppressesPaint(style, current, cssUnits) &&
    (!fieldBackgroundPaintIsTransparent(style, current) ||
      !fieldBorderPaintIsTransparent(style, current, cssUnits) ||
      !fieldOutlinePaintIsTransparent(style, current, cssUnits) ||
      !cssPaintListLooksEmpty(cssPropertyValue(style, current, "box-shadow")) ||
      ["canvas", "iframe", "img", "object", "svg", "video"].includes(
        current.tagName.toLowerCase()
      ))
  );
}

function elementCumulativePaintIsVisible(element: HTMLElement) {
  let opacity = 1;
  let filterOpacity = 1;
  for (
    let current: HTMLElement | null = element;
    current;
    current = parentElementOrShadowHost(current)
  ) {
    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    if (
      current.hidden ||
      style?.display === "none" ||
      style?.visibility === "hidden" ||
      style?.visibility === "collapse"
    ) {
      return false;
    }
    opacity *= cssOpacityValue(style?.opacity) ?? cssOpacityValue(current.style.opacity) ?? 1;
    const currentFilterOpacity = filterOpacityValue(cssPropertyValue(style, current, "filter"));
    filterOpacity *= currentFilterOpacity ?? 1;
    if (isEffectivelyTransparent(opacity) || isEffectivelyTransparent(filterOpacity)) {
      return false;
    }
  }
  return true;
}

function elementMayPaintAboveElement(element: HTMLElement, candidate: HTMLElement) {
  const style = candidate.ownerDocument.defaultView?.getComputedStyle(candidate);
  const elementStyle = element.ownerDocument.defaultView?.getComputedStyle(element);
  const candidateZIndex = numericZIndex(style?.zIndex || candidate.style.zIndex);
  const elementZIndex = numericZIndex(elementStyle?.zIndex || element.style.zIndex);
  if (candidateZIndex !== null && candidateZIndex < (elementZIndex ?? 0)) {
    return false;
  }
  if (candidateZIndex !== null && candidateZIndex > (elementZIndex ?? 0)) {
    return true;
  }
  if (candidateZIndex === null && elementZIndex !== null) {
    return elementZIndex <= 0 && documentFollows(element, candidate);
  }

  return documentFollows(element, candidate);
}

function occlusionScanRoots(element: HTMLElement): ParentNode[] {
  const roots: ParentNode[] = [element.ownerDocument];
  const root = element.getRootNode();
  if (root !== element.ownerDocument && "querySelectorAll" in root) {
    roots.push(root as ParentNode);
  }
  return roots;
}

function paintedOverlayCoversPoint(element: HTMLElement, point: { x: number; y: number }) {
  const ownerWindow = element.ownerDocument.defaultView;
  if (!ownerWindow) {
    return false;
  }
  for (const root of occlusionScanRoots(element)) {
    for (const candidate of Array.from(root.querySelectorAll("*"))) {
      if (
        !(candidate instanceof ownerWindow.HTMLElement) ||
        candidate === element ||
        candidate.contains(element) ||
        element.contains(candidate) ||
        !elementMayPaintAboveElement(element, candidate) ||
        !pointInsideRect(point, candidate.getBoundingClientRect())
      ) {
        continue;
      }

      const style = candidate.ownerDocument.defaultView?.getComputedStyle(candidate);
      if (
        elementPaintsOverlay(candidate, style) &&
        elementCumulativePaintIsVisible(candidate)
      ) {
        return true;
      }
    }
  }
  return false;
}

function isFullyOccludedByPaintedOverlay(element: HTMLElement) {
  const points = visibleViewportSamplePoints(element);
  return (
    points.length > 0 &&
    points.every((point) => paintedOverlayCoversPoint(element, point))
  );
}

type ViewportExit = NonNullable<ReturnType<typeof viewportExitForRect>>;

function inverseOffset(value: number | null) {
  return value === null ? null : -value;
}

function horizontalOffsetMatchesViewportExit(
  viewportExit: ViewportExit | null,
  offset: number | null
) {
  if (viewportExit === null || offset === null) {
    return false;
  }
  if (viewportExit.beforeX && isNegativeOffset(offset)) {
    return viewportExit.rect.right - offset > 0;
  }
  if (viewportExit.afterX && isPositiveOffset(offset)) {
    return viewportExit.rect.left - offset < viewportExit.viewportWidth;
  }
  return false;
}

function verticalOffsetMovesBeforeViewport(
  viewportExit: ViewportExit | null,
  offset: number | null
) {
  return (
    viewportExit !== null &&
    viewportExit.beforeY &&
    offset !== null &&
    isNegativeOffset(offset) &&
    viewportExit.rect.bottom - offset > 0
  );
}

function verticalOffsetMovesAfterViewport(
  viewportExit: ViewportExit | null,
  offset: number | null
) {
  return (
    viewportExit !== null &&
    viewportExit.viewportHeight > 0 &&
    viewportExit.rect.top >= viewportExit.viewportHeight &&
    offset !== null &&
    isPositiveOffset(offset) &&
    viewportExit.rect.top - offset < viewportExit.viewportHeight &&
    viewportExit.rect.bottom - offset > 0
  );
}

function rectsIntersect(left: DOMRect, right: DOMRect) {
  return (
    left.left < right.right &&
    left.right > right.left &&
    left.top < right.bottom &&
    left.bottom > right.top
  );
}

function isFullyClippedByAncestor(element: HTMLElement, ancestor: HTMLElement) {
  const elementRect = element.getBoundingClientRect();
  const ancestorRect = ancestor.getBoundingClientRect();
  return (
    hasMeaningfulClientRect(elementRect) &&
    hasMeaningfulClientRect(ancestorRect) &&
    !rectsIntersect(elementRect, ancestorRect)
  );
}

function splitCssTopLevel(value: string, shouldSplit: (char: string) => boolean) {
  const parts: string[] = [];
  let current = "";
  let depth = 0;

  for (const char of value.trim()) {
    if (char === "(") {
      depth += 1;
    } else if (char === ")" && depth > 0) {
      depth -= 1;
    }

    if (depth === 0 && shouldSplit(char)) {
      if (current.trim() !== "") {
        parts.push(current.trim());
        current = "";
      }
      continue;
    }
    current += char;
  }

  if (current.trim() !== "") {
    parts.push(current.trim());
  }
  return parts;
}

function splitCssFunctionArgs(value: string) {
  return splitCssTopLevel(value, (char) => char === "," || /\s/.test(char));
}

function splitCssCommaList(value: string) {
  return splitCssTopLevel(value, (char) => char === ",");
}

function expandBoxValues(values: string[]) {
  const top = values[0] ?? "0";
  const right = values[1] ?? top;
  const bottom = values[2] ?? top;
  const left = values[3] ?? right;
  return { top, right, bottom, left };
}

function cssInsetPercent(value: string) {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed.endsWith("%")) {
    return null;
  }
  const parsed = Number.parseFloat(trimmed.slice(0, -1));
  return Number.isFinite(parsed) ? parsed : null;
}

function cssInsetLength(
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const percent = cssInsetPercent(value);
  return percent === null ? numericCssValue(value, units) : null;
}

function cssLengthOrPercentIsZero(value: string, units: { emPx?: number; remPx?: number }) {
  const percent = cssInsetPercent(value);
  if (percent !== null) {
    return percent <= 0;
  }
  const length = numericCssValue(value, units);
  return length !== null && length <= 0;
}

function cssRadiusVisibleSizeIsTiny(value: string, units: { emPx?: number; remPx?: number }) {
  const percent = cssInsetPercent(value);
  if (percent !== null) {
    return percent * 2 <= MIN_CLIPPED_VISIBLE_FRACTION * 100;
  }
  const length = numericCssValue(value, units);
  return length !== null && length * 2 <= MIN_CREDENTIAL_FIELD_SIZE_PX;
}

function cssLengthToPx(
  value: string,
  axisSize: number,
  units: CssNumericUnits
): number | null {
  const normalized = value.trim().toLowerCase();
  const percent = cssInsetPercent(normalized);
  if (percent !== null) {
    return axisSize > 0 ? (axisSize * percent) / 100 : null;
  }

  const length = numericCssValue(normalized, units);
  if (length !== null) {
    return length;
  }

  const calcMatch = normalized.match(/^calc\((.*)\)$/);
  if (!calcMatch) {
    return null;
  }

  const tokens = calcMatch[1]
    .replace(/([+-])/g, " $1 ")
    .split(/\s+/)
    .filter(Boolean);
  let total = 0;
  let sign = 1;
  for (const token of tokens) {
    if (token === "+") {
      sign = 1;
      continue;
    }
    if (token === "-") {
      sign = -1;
      continue;
    }
    const tokenValue = cssLengthToPx(token, axisSize, units);
    if (tokenValue === null) {
      return null;
    }
    total += sign * tokenValue;
    sign = 1;
  }
  return total;
}

function cssAxisIndependentInsetLength(
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const percent = cssInsetPercent(value);
  if (percent !== null && percent === 0) {
    return 0;
  }
  return numericCssValue(value, units);
}

function cssCalcFullPercentMinusLength(
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value.trim().toLowerCase();
  const calcMatch = normalized.match(/^calc\((.*)\)$/);
  if (!calcMatch) {
    return null;
  }
  const tokens = calcMatch[1]
    .replace(/([+-])/g, " $1 ")
    .split(/\s+/)
    .filter(Boolean);
  if (tokens.length !== 3 || tokens[0] !== "100%" || tokens[1] !== "-") {
    return null;
  }
  const remainingLength = numericCssValue(tokens[2], units);
  return remainingLength !== null && remainingLength >= 0 ? remainingLength : null;
}

function calcInsetPairVisibleLengthWithoutAxis(
  first: string,
  second: string,
  units: { emPx?: number; remPx?: number }
) {
  const firstVisibleLength = cssCalcFullPercentMinusLength(first, units);
  if (firstVisibleLength !== null) {
    const secondLength = cssAxisIndependentInsetLength(second, units);
    return secondLength === null ? null : firstVisibleLength - secondLength;
  }

  const secondVisibleLength = cssCalcFullPercentMinusLength(second, units);
  if (secondVisibleLength !== null) {
    const firstLength = cssAxisIndependentInsetLength(first, units);
    return firstLength === null ? null : secondVisibleLength - firstLength;
  }

  return null;
}

function cssCoordinateNumber(value: string, units: { emPx?: number; remPx?: number }) {
  return cssInsetPercent(value) ?? numericCssValue(value, units);
}

function cssCoordinateToPx(
  value: string,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  return cssLengthToPx(value, axisSize, units) ?? cssCoordinateNumber(value, units);
}

function insetPairSuppressesField(
  first: string,
  second: string,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const firstPx = cssLengthToPx(first, axisSize, units);
  const secondPx = cssLengthToPx(second, axisSize, units);
  if (axisSize > 0 && firstPx !== null && secondPx !== null) {
    return axisSize - (firstPx + secondPx) <= MIN_CREDENTIAL_FIELD_SIZE_PX;
  }

  const calcVisibleLength = calcInsetPairVisibleLengthWithoutAxis(first, second, units);
  if (calcVisibleLength !== null) {
    return calcVisibleLength <= MIN_CREDENTIAL_FIELD_SIZE_PX;
  }

  const firstPercent = cssInsetPercent(first);
  const secondPercent = cssInsetPercent(second);
  if (firstPercent !== null || secondPercent !== null) {
    const visiblePercent = 100 - ((firstPercent ?? 0) + (secondPercent ?? 0));
    return visiblePercent <= MIN_CLIPPED_VISIBLE_FRACTION * 100;
  }

  const firstLength = cssInsetLength(first, units);
  const secondLength = cssInsetLength(second, units);
  return (
    axisSize > 0 &&
    firstLength !== null &&
    secondLength !== null &&
    axisSize - (firstLength + secondLength) <= MIN_CREDENTIAL_FIELD_SIZE_PX
  );
}

function insetBoxTokens(value: string) {
  const tokens = splitCssFunctionArgs(value);
  const roundIndex = tokens.findIndex((token) => token.toLowerCase() === "round");
  return roundIndex < 0 ? tokens : tokens.slice(0, roundIndex);
}

function svgLengthToPx(
  value: string | null,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  if (value === null) {
    return 0;
  }
  return cssLengthToPx(value, axisSize, units) ?? numericCssValue(value, units) ?? 0;
}

interface SvgMatrix2d {
  a: number;
  b: number;
  c: number;
  d: number;
  e: number;
  f: number;
}

function identitySvgMatrix(): SvgMatrix2d {
  return { a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 };
}

function svgMatrixMultiply(left: SvgMatrix2d, right: SvgMatrix2d): SvgMatrix2d {
  return {
    a: left.a * right.a + left.c * right.b,
    b: left.b * right.a + left.d * right.b,
    c: left.a * right.c + left.c * right.d,
    d: left.b * right.c + left.d * right.d,
    e: left.a * right.e + left.c * right.f + left.e,
    f: left.b * right.e + left.d * right.f + left.f
  };
}

function svgTransformArg(value: string | undefined, units: { emPx?: number; remPx?: number }) {
  return value === undefined ? null : numericCssValue(value, units);
}

function svgTransformMatrix(
  value: string | null | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return identitySvgMatrix();
  }

  let matrix = identitySvgMatrix();
  for (const transform of normalized.matchAll(/(matrix|translate|scale)\(([^)]*)\)/g)) {
    const name = transform[1];
    const args = splitCssFunctionArgs(transform[2]);
    let next: SvgMatrix2d | null = null;

    if (name === "matrix" && args.length >= 6) {
      const values = args.map((arg) => svgTransformArg(arg, units));
      if (values.every((arg) => arg !== null)) {
        const [a, b, c, d, e, f] = values as number[];
        next = { a, b, c, d, e, f };
      }
    } else if (name === "translate") {
      const x = svgTransformArg(args[0], units);
      const y = args[1] === undefined ? 0 : svgTransformArg(args[1], units);
      if (x !== null && y !== null) {
        next = { a: 1, b: 0, c: 0, d: 1, e: x, f: y };
      }
    } else if (name === "scale") {
      const x = svgTransformArg(args[0], units);
      const y = args[1] === undefined ? x : svgTransformArg(args[1], units);
      if (x !== null && y !== null) {
        next = { a: x, b: 0, c: 0, d: y, e: 0, f: 0 };
      }
    }

    if (next !== null) {
      matrix = svgMatrixMultiply(matrix, next);
    }
  }

  return matrix;
}

function svgUsePositionMatrix(
  shape: Element,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const x = svgLengthToPx(shape.getAttribute("x"), rect.width, units);
  const y = svgLengthToPx(shape.getAttribute("y"), rect.height, units);
  return { a: 1, b: 0, c: 0, d: 1, e: x, f: y };
}

function svgElementTransformMatrix(
  shape: Element,
  inherited: SvgMatrix2d,
  units: { emPx?: number; remPx?: number }
) {
  const styled = shape as SVGElement;
  const computedTransform =
    shape.ownerDocument.defaultView?.getComputedStyle(shape).getPropertyValue("transform") ??
    "";
  if (isMeaningfulCssValue(computedTransform)) {
    return svgMatrixMultiply(inherited, svgTransformMatrix(computedTransform, units));
  }

  const attributeTransform = svgTransformMatrix(shape.getAttribute("transform"), units);
  const inlineTransform = svgTransformMatrix(styled.style?.getPropertyValue("transform"), units);
  return svgMatrixMultiply(svgMatrixMultiply(inherited, attributeTransform), inlineTransform);
}

function transformSvgPoint(matrix: SvgMatrix2d, point: { x: number; y: number }) {
  return {
    x: matrix.a * point.x + matrix.c * point.y + matrix.e,
    y: matrix.b * point.x + matrix.d * point.y + matrix.f
  };
}

function transformSvgPoints(points: Array<{ x: number; y: number }>, matrix: SvgMatrix2d) {
  return points.map((point) => transformSvgPoint(matrix, point));
}

function fieldLocalBounds(rect: DOMRect) {
  return { left: 0, top: 0, right: rect.width, bottom: rect.height };
}

function visibleBoundsOverlap(
  bounds: { left: number; top: number; right: number; bottom: number },
  rect: DOMRect
) {
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const fieldBounds = fieldLocalBounds(rect);
  const width = Math.max(
    0,
    Math.min(bounds.right, fieldBounds.right) - Math.max(bounds.left, fieldBounds.left)
  );
  const height = Math.max(
    0,
    Math.min(bounds.bottom, fieldBounds.bottom) - Math.max(bounds.top, fieldBounds.top)
  );
  return { width, height, area: width * height };
}

function svgPointListToPoints(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const tokens = value.trim().split(/[\s,]+/).filter(Boolean);
  const points: Array<{ x: number; y: number }> = [];
  for (let index = 0; index + 1 < tokens.length; index += 2) {
    points.push({
      x: svgLengthToPx(tokens[index], rect.width, units),
      y: svgLengthToPx(tokens[index + 1], rect.height, units)
    });
  }
  return points;
}

function svgPathDataToPoints(value: string) {
  const numbers = (value.match(/-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?/gi) ?? []).map(Number);
  const points: Array<{ x: number; y: number }> = [];
  for (let index = 0; index + 1 < numbers.length; index += 2) {
    const x = numbers[index];
    const y = numbers[index + 1];
    if (Number.isFinite(x) && Number.isFinite(y)) {
      points.push({ x, y });
    }
  }
  return points;
}

function pathPointKey(point: { x: number; y: number }) {
  return `${Number(point.x.toFixed(4))},${Number(point.y.toFixed(4))}`;
}

function canonicalPathPointSequence(points: Array<{ x: number; y: number }>) {
  const normalized = [...points];
  if (
    normalized.length > 1 &&
    pathPointKey(normalized[0]) === pathPointKey(normalized[normalized.length - 1])
  ) {
    normalized.pop();
  }
  if (normalized.length === 0) {
    return "";
  }

  const keys = normalized.map(pathPointKey);
  const sequences: string[] = [];
  for (const source of [keys, [...keys].reverse()]) {
    for (let index = 0; index < source.length; index += 1) {
      sequences.push([...source.slice(index), ...source.slice(0, index)].join("|"));
    }
  }
  return sequences.sort()[0];
}

function svgPathDataToSubpathPoints(value: string) {
  const subpaths = value.match(/[Mm][^Mm]*/g) ?? [value];
  return subpaths.map(svgPathDataToPoints).filter((points) => points.length > 0);
}

function evenOddDuplicateSubpathsSuppressPath(value: string) {
  const subpathKeys = svgPathDataToSubpathPoints(value)
    .map(canonicalPathPointSequence)
    .filter(Boolean);
  if (subpathKeys.length < 2) {
    return false;
  }

  const counts = new Map<string, number>();
  for (const key of subpathKeys) {
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.values()).every((count) => count % 2 === 0);
}

function svgPathUsesEvenOdd(shape: Element) {
  const style = shape.ownerDocument.defaultView?.getComputedStyle(shape);
  const inlineStyle = (shape as SVGElement).style;
  return [
    shape.getAttribute("clip-rule"),
    inlineStyle?.getPropertyValue("clip-rule"),
    style?.getPropertyValue("clip-rule"),
    shape.getAttribute("fill-rule"),
    inlineStyle?.getPropertyValue("fill-rule"),
    style?.getPropertyValue("fill-rule")
  ].some((value) => value?.trim().toLowerCase() === "evenodd");
}

function polygonArea(points: Array<{ x: number; y: number }>) {
  const doubledArea = points.reduce((sum, point, index) => {
    const next = points[(index + 1) % points.length];
    return sum + point.x * next.y - next.x * point.y;
  }, 0);
  return Math.abs(doubledArea) / 2;
}

function pointRegionSuppressesField(
  points: Array<{ x: number; y: number }>,
  rect: DOMRect,
  requiresArea: boolean
) {
  if (points.length < (requiresArea ? 3 : 2)) {
    return true;
  }
  const xValues = points.map((point) => point.x);
  const yValues = points.map((point) => point.y);
  const width = Math.max(...xValues) - Math.min(...xValues);
  const height = Math.max(...yValues) - Math.min(...yValues);
  const area = polygonArea(points);
  const rectArea = rect.width * rect.height;
  const overlap = visibleBoundsOverlap(
    {
      left: Math.min(...xValues),
      top: Math.min(...yValues),
      right: Math.max(...xValues),
      bottom: Math.max(...yValues)
    },
    rect
  );
  return (
    width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    height <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    (requiresArea && area <= Number.EPSILON) ||
    (overlap !== null &&
      (overlap.width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
        overlap.height <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
        overlap.area <= rectArea * MIN_CLIPPED_VISIBLE_FRACTION)) ||
    (rectArea > 0 && area <= rectArea * MIN_CLIPPED_VISIBLE_FRACTION)
  );
}

function pathRegionSuppressesField(points: Array<{ x: number; y: number }>, rect: DOMRect) {
  if (points.length < 2) {
    return true;
  }
  return pointRegionSuppressesField(points, rect, points.length >= 3);
}

function svgClipShapeSuppressesField(
  current: HTMLElement,
  shape: Element,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set(),
  inheritedMatrix: SvgMatrix2d = identitySvgMatrix()
): boolean {
  if (seen.has(shape)) {
    return true;
  }
  seen.add(shape);

  const shapeStyle = shape.ownerDocument.defaultView?.getComputedStyle(shape);
  const inlineStyle = (shape as SVGElement).style;
  const display = shapeStyle?.display || inlineStyle?.display;
  const visibility = shapeStyle?.visibility || inlineStyle?.visibility;
  if (display === "none" || visibility === "hidden" || visibility === "collapse") {
    return true;
  }

  const rect = current.getBoundingClientRect();
  const tagName = shape.tagName.toLowerCase();
  const matrix = svgElementTransformMatrix(shape, inheritedMatrix, units);
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    const useMatrix = svgMatrixMultiply(matrix, svgUsePositionMatrix(shape, rect, units));
    return (
      target === null || svgClipShapeSuppressesField(current, target, units, seen, useMatrix)
    );
  }
  if (tagName === "rect") {
    const x = svgLengthToPx(shape.getAttribute("x"), rect.width, units);
    const y = svgLengthToPx(shape.getAttribute("y"), rect.height, units);
    const width = svgLengthToPx(shape.getAttribute("width"), rect.width, units);
    const height = svgLengthToPx(shape.getAttribute("height"), rect.height, units);
    return pointRegionSuppressesField(
      transformSvgPoints(
        [
          { x, y },
          { x: x + width, y },
          { x: x + width, y: y + height },
          { x, y: y + height }
        ],
        matrix
      ),
      rect,
      true
    );
  }
  if (tagName === "circle") {
    const radius = svgLengthToPx(shape.getAttribute("r"), Math.min(rect.width, rect.height), units);
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units);
    return pointRegionSuppressesField(
      transformSvgPoints(
        [
          { x: cx - radius, y: cy - radius },
          { x: cx + radius, y: cy - radius },
          { x: cx + radius, y: cy + radius },
          { x: cx - radius, y: cy + radius }
        ],
        matrix
      ),
      rect,
      true
    );
  }
  if (tagName === "ellipse") {
    const radiusX = svgLengthToPx(shape.getAttribute("rx"), rect.width, units);
    const radiusY = svgLengthToPx(shape.getAttribute("ry"), rect.height, units);
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units);
    return pointRegionSuppressesField(
      transformSvgPoints(
        [
          { x: cx - radiusX, y: cy - radiusY },
          { x: cx + radiusX, y: cy - radiusY },
          { x: cx + radiusX, y: cy + radiusY },
          { x: cx - radiusX, y: cy + radiusY }
        ],
        matrix
      ),
      rect,
      true
    );
  }
  if (tagName === "line") {
    return pointRegionSuppressesField(
      transformSvgPoints(
        [
          {
            x: svgLengthToPx(shape.getAttribute("x1"), rect.width, units),
            y: svgLengthToPx(shape.getAttribute("y1"), rect.height, units)
          },
          {
            x: svgLengthToPx(shape.getAttribute("x2"), rect.width, units),
            y: svgLengthToPx(shape.getAttribute("y2"), rect.height, units)
          }
        ],
        matrix
      ),
      rect,
      false
    );
  }
  if (tagName === "text") {
    return shape.textContent?.trim() === "";
  }
  if (tagName === "polygon" || tagName === "polyline") {
    const points = svgPointListToPoints(shape.getAttribute("points") ?? "", rect, units);
    return pointRegionSuppressesField(
      transformSvgPoints(points, matrix),
      rect,
      tagName === "polygon"
    );
  }
  if (tagName === "path") {
    const pathData = shape.getAttribute("d") ?? "";
    if (svgPathUsesEvenOdd(shape) && evenOddDuplicateSubpathsSuppressPath(pathData)) {
      return true;
    }
    const points = svgPathDataToPoints(pathData);
    return pathRegionSuppressesField(transformSvgPoints(points, matrix), rect);
  }
  if (tagName === "g" || tagName === "svg") {
    const children = Array.from(shape.children);
    return children.length === 0 || children.every((child) =>
      svgClipShapeSuppressesField(current, child, units, seen, matrix)
    );
  }
  return false;
}

function svgClipPathFullyClips(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const [id] = localCssUrlReferenceIds(value);
  if (!id) {
    return false;
  }
  const clipPath = current.ownerDocument.getElementById(id);
  if (!clipPath) {
    return false;
  }
  const shapes = Array.from(clipPath.children);
  const clipPathMatrix = svgElementTransformMatrix(clipPath, identitySvgMatrix(), units);
  return (
    shapes.length === 0 ||
    shapes.every((shape) =>
      svgClipShapeSuppressesField(current, shape, units, new Set(), clipPathMatrix)
    )
  );
}

function clipPathFullyClips(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  if (localCssUrlReferenceIds(value).length > 0) {
    return svgClipPathFullyClips(current, value, units);
  }

  const normalized = value.trim().toLowerCase();
  const insetMatch = normalized.match(/^inset\((.*)\)$/);
  if (insetMatch) {
    const inset = expandBoxValues(insetBoxTokens(insetMatch[1]));
    const rect = current.getBoundingClientRect();
    return (
      insetPairSuppressesField(inset.left, inset.right, rect.width, units) ||
      insetPairSuppressesField(inset.top, inset.bottom, rect.height, units)
    );
  }

  const circleMatch = normalized.match(/^circle\((.*)\)$/);
  if (circleMatch) {
    const [radius] = splitCssFunctionArgs(circleMatch[1]);
    return (
      radius !== undefined &&
      (cssLengthOrPercentIsZero(radius, units) || cssRadiusVisibleSizeIsTiny(radius, units))
    );
  }

  const ellipseMatch = normalized.match(/^ellipse\((.*)\)$/);
  if (ellipseMatch) {
    const [radiusX, radiusY] = splitCssFunctionArgs(ellipseMatch[1]);
    return (
      radiusX !== undefined &&
      radiusY !== undefined &&
      (cssLengthOrPercentIsZero(radiusX, units) ||
        cssLengthOrPercentIsZero(radiusY, units) ||
        cssRadiusVisibleSizeIsTiny(radiusX, units) ||
        cssRadiusVisibleSizeIsTiny(radiusY, units))
    );
  }

  const rectMatch = normalized.match(/^rect\((.*)\)$/);
  if (rectMatch) {
    return legacyClipFullyClips(normalized, units);
  }

  const xywhMatch = normalized.match(/^xywh\((.*)\)$/);
  if (xywhMatch) {
    const [, , width, height] = splitCssFunctionArgs(xywhMatch[1]);
    const rect = current.getBoundingClientRect();
    const widthPx = width === undefined ? null : cssLengthToPx(width, rect.width, units);
    const heightPx = height === undefined ? null : cssLengthToPx(height, rect.height, units);
    return (
      (widthPx !== null && widthPx <= MIN_CREDENTIAL_FIELD_SIZE_PX) ||
      (heightPx !== null && heightPx <= MIN_CREDENTIAL_FIELD_SIZE_PX)
    );
  }

  const polygonMatch = normalized.match(/^polygon\((.*)\)$/);
  if (polygonMatch) {
    const rect = current.getBoundingClientRect();
    const points = splitCssCommaList(polygonMatch[1]).flatMap((point) => {
      const [x, y] = splitCssFunctionArgs(point);
      const parsedX = x === undefined ? null : cssCoordinateToPx(x, rect.width, units);
      const parsedY = y === undefined ? null : cssCoordinateToPx(y, rect.height, units);
      return parsedX === null || parsedY === null ? [] : [{ x: parsedX, y: parsedY }];
    });
    return pointRegionSuppressesField(points, rect, true);
  }

  const pathMatch = normalized.match(/^path\((.*)\)$/);
  if (pathMatch) {
    const fillRule = pathMatch[1].match(/^\s*(evenodd|nonzero)\s*,/i)?.[1].toLowerCase();
    const pathData =
      pathMatch[1].match(/(['"])(.*?)\1/)?.[2] ?? pathMatch[1].replace(/^evenodd\s*,/i, "");
    if (fillRule === "evenodd" && evenOddDuplicateSubpathsSuppressPath(pathData)) {
      return true;
    }
    return pathRegionSuppressesField(
      svgPathDataToPoints(pathData),
      current.getBoundingClientRect()
    );
  }

  return false;
}

function legacyClipFullyClips(value: string, units: { emPx?: number; remPx?: number }) {
  const match = value.trim().toLowerCase().match(/^rect\((.*)\)$/);
  if (!match) {
    return false;
  }
  const rect = expandBoxValues(splitCssFunctionArgs(match[1]));
  const top = numericCssValue(rect.top, units);
  const right = numericCssValue(rect.right, units);
  const bottom = numericCssValue(rect.bottom, units);
  const left = numericCssValue(rect.left, units);
  if (top === null || right === null || bottom === null || left === null) {
    return false;
  }
  const visibleWidth = right - left;
  const visibleHeight = bottom - top;
  return (
    visibleWidth <= 0 ||
    visibleHeight <= 0 ||
    visibleWidth <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    visibleHeight <= MIN_CREDENTIAL_FIELD_SIZE_PX
  );
}

function hasFullyClippingStyle(
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const clipPath = cssPropertyValue(style, current, "clip-path");
  const clip = cssPropertyValue(style, current, "clip");
  return (
    (isMeaningfulCssValue(clipPath) && clipPathFullyClips(current, clipPath, units)) ||
    (isMeaningfulCssValue(clip) && legacyClipFullyClips(clip, units))
  );
}

function credentialHintText(element: HTMLElement) {
  const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
  return [
    element.tagName.toLowerCase() === "input" ? (element as HTMLInputElement).type : undefined,
    field.autocomplete,
    field.name,
    element.id,
    element.className,
    element.getAttribute("aria-label")
  ]
    .filter((value): value is string => typeof value === "string")
    .join(",")
    .toLowerCase();
}

function isCredentialLikeField(element: HTMLElement) {
  const tagName = element.tagName.toLowerCase();
  if (tagName !== "input" && tagName !== "textarea") {
    return false;
  }

  const text = credentialHintText(element);
  return (
    text.includes("password") ||
    text.includes("username") ||
    text.includes("userid") ||
    text.includes("login") ||
    text.includes("email")
  );
}

function isTinyCredentialField(
  element: HTMLElement,
  width: number | null,
  height: number | null
) {
  if (!isCredentialLikeField(element)) {
    return false;
  }
  const rect = element.getBoundingClientRect();
  if (
    hasMeaningfulClientRect(rect) &&
    (rect.width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
      rect.height <= MIN_CREDENTIAL_FIELD_SIZE_PX)
  ) {
    return true;
  }
  return (
    (width !== null && width <= MIN_CREDENTIAL_FIELD_SIZE_PX) ||
    (height !== null && height <= MIN_CREDENTIAL_FIELD_SIZE_PX)
  );
}

function hasCollapsedRenderedAxis(element: HTMLElement) {
  const rect = element.getBoundingClientRect();
  return (rect.width <= 0 && rect.height > 0) || (rect.height <= 0 && rect.width > 0);
}

export function getFieldVisibility(element: HTMLElement): FieldVisibilityResult {
  const reasons: string[] = [];
  const inputType =
    element.tagName.toLowerCase() === "input"
      ? (element as HTMLInputElement).type.toLowerCase()
      : undefined;

  if (inputType === "hidden") {
    addReason(reasons, "not-viewable:hidden");
  }
  const viewportExit = viewportExitForRect(element);
  let cumulativeOpacity = 1;
  let cumulativeFilterOpacity = 1;
  for (
    let current: HTMLElement | null = element;
    current;
    current = parentElementOrShadowHost(current)
  ) {
    if (isUnslottedShadowHostChild(current)) {
      addReason(reasons, "not-viewable:unslotted");
    }
    if (current.hidden) {
      addReason(reasons, "not-viewable:hidden");
    }
    if (isClosedDetailsContent(element, current)) {
      addReason(reasons, "not-viewable:details-closed");
    }

    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    const rootStyle = current.ownerDocument.defaultView?.getComputedStyle(
      current.ownerDocument.documentElement
    );
    const emPx = numericCssValue(style?.fontSize || current.style.fontSize) ?? 16;
    const remPx = numericCssValue(rootStyle?.fontSize) ?? emPx;
    const viewport = viewportSize(current);
    const inlineDisplay = current.style.display;
    const inlineVisibility = current.style.visibility;
    const opacity = cssOpacityValue(style?.opacity) ?? cssOpacityValue(current.style.opacity);
    const filter = cssPropertyValue(style, current, "filter");
    const filterOpacity = filterOpacityValue(filter);
    const contentVisibility = cssPropertyValue(style, current, "content-visibility")
      .trim()
      .toLowerCase();
    const position = current.style.position || style?.position;
    const cssUnits = { emPx, remPx, viewportWidth: viewport.width, viewportHeight: viewport.height };
    const left = computedCssValue(style?.left, current.style.left, cssUnits);
    const top = computedCssValue(style?.top, current.style.top, cssUnits);
    const right = computedCssValue(style?.right, current.style.right, cssUnits);
    const bottom = computedCssValue(style?.bottom, current.style.bottom, cssUnits);
    const marginLeft = computedCssValue(style?.marginLeft, current.style.marginLeft, cssUnits);
    const marginTop = computedCssValue(style?.marginTop, current.style.marginTop, cssUnits);
    const width = computedCssValue(style?.width, current.style.width, cssUnits);
    const height = computedCssValue(style?.height, current.style.height, cssUnits);
    const transform = combinedTranslateOffset(style, current, cssUnits);
    const isPositioned =
      position !== undefined && position !== "" && position !== "static";
    if (opacity !== null) {
      cumulativeOpacity *= opacity;
    }
    if (filterOpacity !== null) {
      cumulativeFilterOpacity *= filterOpacity;
    }
    const hasDirectionalTransformOffset =
      transform !== null &&
      (horizontalOffsetMatchesViewportExit(viewportExit, transform.x) ||
        verticalOffsetMovesBeforeViewport(viewportExit, transform.y) ||
        verticalOffsetMovesAfterViewport(viewportExit, transform.y));
    const hasFixedPositionAfterViewportOffset =
      position === "fixed" &&
      (verticalOffsetMovesAfterViewport(viewportExit, top) ||
        verticalOffsetMovesAfterViewport(viewportExit, inverseOffset(bottom)));
    const hasDirectionalPositionOffset =
      isPositioned &&
      (horizontalOffsetMatchesViewportExit(viewportExit, left) ||
        horizontalOffsetMatchesViewportExit(viewportExit, inverseOffset(right)) ||
        verticalOffsetMovesBeforeViewport(viewportExit, top) ||
        verticalOffsetMovesBeforeViewport(viewportExit, inverseOffset(bottom)) ||
        hasFixedPositionAfterViewportOffset);
    const hasDirectionalMarginOffset =
      horizontalOffsetMatchesViewportExit(viewportExit, marginLeft) ||
      verticalOffsetMovesBeforeViewport(viewportExit, marginTop);
    const hasMotionPathViewportExit =
      viewportExit !== null &&
      hasMotionPathOffset(style, current) &&
      (viewportExit.beforeX ||
        viewportExit.afterX ||
        viewportExit.beforeY ||
        viewportExit.afterY);
    const hasHiddenVisibility =
      inlineVisibility === "hidden" ||
      style?.visibility === "hidden" ||
      style?.visibility === "collapse";
    if (
      inlineDisplay === "none" ||
      style?.display === "none" ||
      contentVisibility === "hidden" ||
      (hasHiddenVisibility &&
        !(
          current !== element &&
          style?.visibility === "hidden" &&
          hasExplicitVisibleDescendantOverride(element, current)
        ))
    ) {
      addReason(reasons, "not-viewable:css");
    }
    if (
      isEffectivelyTransparent(opacity) ||
      isEffectivelyTransparent(cumulativeOpacity) ||
      isEffectivelyTransparent(filterOpacity) ||
      isEffectivelyTransparent(cumulativeFilterOpacity) ||
      svgFilterSuppressesPaint(current, filter) ||
      maskStyleSuppressesPaint(style, current, cssUnits) ||
      (current === element &&
        isCredentialLikeField(element) &&
        fieldChromePaintIsTransparent(style, current, cssUnits))
    ) {
      addReason(reasons, "not-viewable:transparent");
    }
    if (hasFullyClippingStyle(current, style, cssUnits)) {
      addReason(reasons, "not-viewable:clipped");
    }
    if (
      (position === "absolute" || position === "fixed") &&
      (left !== null || top !== null || right !== null || bottom !== null)
    ) {
      if ([left, top, right, bottom].some(isLargeOffscreenOffset)) {
        addReason(reasons, "not-viewable:offscreen");
      }
    }
    if (
      transform &&
      (isLargeOffscreenOffset(transform.x) || isLargeOffscreenOffset(transform.y))
    ) {
      addReason(reasons, "not-viewable:offscreen");
    }
    if (
      viewportExit !== null &&
      (hasDirectionalTransformOffset ||
        hasDirectionalPositionOffset ||
        hasDirectionalMarginOffset ||
        hasMotionPathViewportExit)
    ) {
      addReason(reasons, "not-viewable:offscreen");
    }
    if (
      transformStyleFullyCollapses(style, current, cssUnits) ||
      zoomStyleFullyCollapses(style, current) ||
      rotateStyleFullyCollapses(style, current) ||
      backfaceStyleHidesElement(style, current)
    ) {
      addReason(reasons, "not-viewable:zero-size");
    }
    if (
      (current === element && width === 0 && height === 0) ||
      (current === element && hasCollapsedRenderedAxis(element)) ||
      (current !== element && isClippedZeroSizeAncestor(current, width, height, style))
    ) {
      addReason(reasons, "not-viewable:zero-size");
    }
    if (current === element && isTinyCredentialField(element, width, height)) {
      addReason(reasons, "not-viewable:tiny");
    }
    if (
      current === element &&
      isCredentialLikeField(element) &&
      (isFullyOccludedByHitTesting(element) || isFullyOccludedByPaintedOverlay(element))
    ) {
      addReason(reasons, "not-viewable:occluded");
    }
    if (
      current !== element &&
      (isClippedTinyAncestor(current, width, height, style) ||
        (clipsDescendantPaint(current, style) && isFullyClippedByAncestor(element, current)))
    ) {
      addReason(reasons, "not-viewable:clipped");
    }
  }

  return {
    viewable: reasons.length === 0,
    reasons
  };
}

export function getFieldFillability(element: HTMLElement): FieldFillabilityResult {
  const reasons: string[] = [];
  const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
  const style = element.ownerDocument.defaultView?.getComputedStyle(element);

  if (field.disabled || element.matches(":disabled")) {
    reasons.push("not-fillable:disabled");
  }

  if ((style?.pointerEvents || element.style.pointerEvents) === "none") {
    reasons.push("not-fillable:pointer-events");
  }

  for (
    let current: HTMLElement | null = element;
    current;
    current = parentElementOrShadowHost(current)
  ) {
    if (current.hasAttribute("inert")) {
      reasons.push("not-fillable:inert");
      break;
    }
  }

  if ("readOnly" in field && field.readOnly) {
    reasons.push("not-fillable:readonly");
  }

  return {
    fillable: reasons.length === 0,
    reasons
  };
}
