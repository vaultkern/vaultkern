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
  const calcMatch = trimmed.match(/^calc\((.*)\)$/);
  if (calcMatch) {
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
      const tokenValue = cssOpacityValue(token);
      if (tokenValue === null) {
        return null;
      }
      total += sign * tokenValue;
      sign = 1;
    }
    return clampCssAlphaChannel(total);
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
  const computedValue = style?.getPropertyValue(property).trim() ?? "";
  const styleValue = element.style.getPropertyValue(property).trim();
  const validStyleValue = (value: string) =>
    value !== "" && value.trim().toLowerCase() !== "nan";
  if (validStyleValue(computedValue)) {
    return computedValue;
  }
  if (validStyleValue(styleValue)) {
    return styleValue;
  }
  return inlineMatch?.[1]?.trim() ?? "";
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

function cssFilterPaintCollapseColor(value: string | undefined): CssColorRgba | null {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  let collapsedColor: CssColorRgba | null = null;
  let collapsedAlpha = 1;
  for (const match of normalized.matchAll(/([a-z-]+)\(([^)]*)\)/g)) {
    const name = match[1];
    const body = match[2];
    if (name === "brightness") {
      const brightness = cssOpacityValue(body);
      if (brightness !== null && brightness <= 0) {
        collapsedColor = { r: 0, g: 0, b: 0, a: collapsedAlpha };
      }
      continue;
    }
    if (name === "contrast") {
      const contrast = cssOpacityValue(body);
      if (contrast !== null && contrast <= 0) {
        collapsedColor = { r: 128, g: 128, b: 128, a: collapsedAlpha };
      }
      continue;
    }
    if (collapsedColor === null) {
      continue;
    }
    if (name === "opacity") {
      const opacity = cssOpacityValue(body);
      if (opacity !== null) {
        collapsedAlpha *= opacity;
        collapsedColor = { ...collapsedColor, a: collapsedAlpha };
      }
      continue;
    }
    if (name === "blur") {
      continue;
    }
    return null;
  }

  return collapsedColor;
}

function cssFilterAmount(value: string | undefined, defaultValue = 1) {
  return cssOpacityValue(value) ?? defaultValue;
}

function cssFilterPaintColor(value: string | undefined, color: CssColorRgba | null) {
  if (color === null) {
    return null;
  }

  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return color;
  }

  let result = { ...color };
  for (const match of normalized.matchAll(/([a-z-]+)\(([^)]*)\)/g)) {
    const name = match[1];
    const amount = cssFilterAmount(match[2]);
    if (name === "opacity") {
      result = { ...result, a: clampCssAlphaChannel(result.a * amount) };
      continue;
    }
    if (name === "brightness") {
      result = {
        ...result,
        r: clampCssColorChannel(result.r * amount),
        g: clampCssColorChannel(result.g * amount),
        b: clampCssColorChannel(result.b * amount)
      };
      continue;
    }
    if (name === "contrast") {
      result = {
        ...result,
        r: clampCssColorChannel((result.r - 128) * amount + 128),
        g: clampCssColorChannel((result.g - 128) * amount + 128),
        b: clampCssColorChannel((result.b - 128) * amount + 128)
      };
      continue;
    }
    if (name === "invert") {
      result = {
        ...result,
        r: clampCssColorChannel(result.r * (1 - amount) + (255 - result.r) * amount),
        g: clampCssColorChannel(result.g * (1 - amount) + (255 - result.g) * amount),
        b: clampCssColorChannel(result.b * (1 - amount) + (255 - result.b) * amount)
      };
      continue;
    }
    if (name === "blur") {
      continue;
    }
    return null;
  }

  return result;
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

function svgFilterFloodSuppressesPaint(primitive: Element) {
  const styled = primitive as SVGElement;
  const floodOpacity =
    cssOpacityValue(primitive.getAttribute("flood-opacity") ?? undefined) ??
    cssOpacityValue(styled.style?.getPropertyValue("flood-opacity")) ??
    1;
  const floodColor =
    primitive.getAttribute("flood-color") ??
    styled.style?.getPropertyValue("flood-color") ??
    "black";
  return isEffectivelyTransparent(floodOpacity) || cssColorLooksTransparent(floodColor);
}

function svgNumberList(value: string | null) {
  const numbers = (value ?? "")
    .trim()
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);
  return numbers.every((number) => Number.isFinite(number)) ? numbers : null;
}

function svgAlphaUpperBound(value: number) {
  return clampCssAlphaChannel(value);
}

function svgAlphaTransferOpacityValue(func: Element) {
  const type = func.getAttribute("type")?.toLowerCase() ?? "identity";
  if (type === "identity") {
    return 1;
  }

  if (type === "table" || type === "discrete") {
    const tableValues = svgNumberList(func.getAttribute("tableValues"));
    return tableValues !== null && tableValues.length > 0
      ? svgAlphaUpperBound(Math.max(...tableValues))
      : null;
  }

  if (type === "linear") {
    const slope = Number(func.getAttribute("slope") ?? "1");
    const intercept = Number(func.getAttribute("intercept") ?? "0");
    return Number.isFinite(slope) && Number.isFinite(intercept)
      ? svgAlphaUpperBound(Math.max(intercept, slope + intercept))
      : null;
  }

  if (type === "gamma") {
    const amplitude = Number(func.getAttribute("amplitude") ?? "1");
    const offset = Number(func.getAttribute("offset") ?? "0");
    return Number.isFinite(amplitude) && Number.isFinite(offset)
      ? svgAlphaUpperBound(Math.max(offset, amplitude + offset))
      : null;
  }

  return null;
}

function svgColorMatrixAlphaOpacityValue(matrix: Element) {
  const type = matrix.getAttribute("type")?.toLowerCase() ?? "matrix";
  if (type === "saturate" || type === "huerotate") {
    return 1;
  }
  if (type !== "matrix") {
    return null;
  }

  const values = svgNumberList(matrix.getAttribute("values"));
  if (values === null || values.length < 20) {
    return null;
  }

  const [red, green, blue, alpha, offset] = values.slice(15, 20);
  if (red <= 0 && green <= 0 && blue <= 0 && alpha >= 0 && offset >= 0) {
    return svgAlphaUpperBound(alpha + offset);
  }
  if ([red, green, blue, alpha, offset].every((value) => value <= 0)) {
    return 0;
  }
  return null;
}

function svgFilterKnownInputOpacity(
  value: string,
  previousOutputOpacity: number | null,
  resultOpacities: ReadonlyMap<string, number | null>
) {
  if (value === "") {
    return previousOutputOpacity;
  }
  if (svgFilterInputIsSourcePaint(value)) {
    return 1;
  }
  if (value === "transparentblack") {
    return 0;
  }
  return resultOpacities.has(value) ? resultOpacities.get(value) ?? null : null;
}

function svgFilterPrimitiveInputOpacity(
  primitive: Element,
  attribute: "in" | "in2",
  previousOutputOpacity: number | null,
  resultOpacities: ReadonlyMap<string, number | null>
) {
  return svgFilterKnownInputOpacity(
    svgFilterInputName(primitive, attribute),
    previousOutputOpacity,
    resultOpacities
  );
}

function svgComponentTransferAlphaOpacityValue(primitive: Element) {
  const alphaFunc = Array.from(primitive.children).find(
    (child) => child.tagName.toLowerCase() === "fefunca"
  );
  return alphaFunc === undefined ? 1 : svgAlphaTransferOpacityValue(alphaFunc);
}

function svgFloodOpacityValue(primitive: Element) {
  const styled = primitive as SVGElement;
  const floodOpacity =
    cssOpacityValue(primitive.getAttribute("flood-opacity") ?? undefined) ??
    cssOpacityValue(styled.style?.getPropertyValue("flood-opacity")) ??
    1;
  const floodColor =
    primitive.getAttribute("flood-color") ??
    styled.style?.getPropertyValue("flood-color") ??
    "black";
  const colorAlpha = cssColorLooksTransparent(floodColor)
    ? 0
    : cssColorRgba(floodColor)?.a ?? 1;
  return clampCssAlphaChannel(floodOpacity * colorAlpha);
}

function svgMergeOpacityValue(
  primitive: Element,
  previousOutputOpacity: number | null,
  resultOpacities: ReadonlyMap<string, number | null>
) {
  const mergeNodes = Array.from(primitive.children).filter(
    (child) => child.tagName.toLowerCase() === "femergenode"
  );
  if (mergeNodes.length === 0) {
    return previousOutputOpacity;
  }

  const opacities = mergeNodes.map((node) =>
    svgFilterKnownInputOpacity(
      svgFilterInputName(node, "in"),
      previousOutputOpacity,
      resultOpacities
    )
  );
  return opacities.every((opacity): opacity is number => opacity !== null)
    ? Math.max(...opacities)
    : null;
}

function svgFilterPrimitiveOpacityValue(
  primitive: Element,
  previousOutputOpacity: number | null,
  resultOpacities: ReadonlyMap<string, number | null>
) {
  const tagName = primitive.tagName.toLowerCase();
  if (tagName === "feflood") {
    return svgFloodOpacityValue(primitive);
  }
  if (tagName === "femerge") {
    return svgMergeOpacityValue(primitive, previousOutputOpacity, resultOpacities);
  }
  if (tagName === "fecomposite" && svgFilterCompositeSuppressesPaint(primitive)) {
    return 0;
  }

  const inputOpacity = svgFilterPrimitiveInputOpacity(
    primitive,
    "in",
    previousOutputOpacity,
    resultOpacities
  );
  if (inputOpacity === null) {
    return null;
  }
  if (tagName === "fecomponenttransfer") {
    const alpha = svgComponentTransferAlphaOpacityValue(primitive);
    return alpha === null ? null : clampCssAlphaChannel(inputOpacity * alpha);
  }
  if (tagName === "fecolormatrix") {
    const alpha = svgColorMatrixAlphaOpacityValue(primitive);
    return alpha === null ? null : clampCssAlphaChannel(inputOpacity * alpha);
  }
  return inputOpacity;
}

function svgFilterGraphOpacityValue(filter: Element) {
  const resultOpacities = new Map<string, number | null>();
  let previousOutputOpacity: number | null = 1;
  let sawPrimitive = false;

  for (const primitive of Array.from(filter.children)) {
    sawPrimitive = true;
    const outputOpacity = svgFilterPrimitiveOpacityValue(
      primitive,
      previousOutputOpacity,
      resultOpacities
    );
    const resultName = svgFilterResultName(primitive.getAttribute("result"));
    if (resultName !== null) {
      resultOpacities.set(resultName, outputOpacity);
    }
    previousOutputOpacity = outputOpacity;
  }

  return sawPrimitive ? previousOutputOpacity : null;
}

function svgFilterOpacityValue(filterTarget: HTMLElement, value: string | undefined) {
  let opacity = 1;
  let found = false;
  for (const id of localCssUrlReferenceIds(value)) {
    const filter = filterTarget.ownerDocument.getElementById(id);
    if (!filter) {
      continue;
    }
    const graphOpacity = svgFilterGraphOpacityValue(filter);
    if (graphOpacity !== null) {
      opacity *= graphOpacity;
      found = true;
    }
  }

  return found ? opacity : null;
}

function paintFilterOpacityValue(filterTarget: HTMLElement, value: string | undefined) {
  const cssOpacity = filterOpacityValue(value);
  const svgOpacity = svgFilterOpacityValue(filterTarget, value);
  return cssOpacity === null && svgOpacity === null
    ? null
    : (cssOpacity ?? 1) * (svgOpacity ?? 1);
}

function svgFilterPrimitiveUnits(primitive: Element): SvgClipCoordinateSpace {
  return primitive.closest("filter")?.getAttribute("primitiveUnits")?.trim() ===
    "objectBoundingBox"
    ? "objectBoundingBox"
    : "userSpaceOnUse";
}

function svgFilterLengthToPx(
  value: string | null,
  axisSize: number,
  units: { emPx?: number; remPx?: number },
  coordinateSpace: SvgClipCoordinateSpace
) {
  if (coordinateSpace === "objectBoundingBox") {
    return svgNormalizedLength(value, units) * axisSize;
  }
  return cssLengthToPx(value ?? "0", axisSize, units) ?? numericCssValue(value ?? "0", units) ?? 0;
}

function offsetRectOverlapSuppressesPaint(rect: DOMRect, dx: number, dy: number) {
  if (!hasMeaningfulClientRect(rect)) {
    return isLargeOffscreenOffset(dx) || isLargeOffscreenOffset(dy);
  }
  const overlapWidth = Math.max(0, rect.width - Math.abs(dx));
  const overlapHeight = Math.max(0, rect.height - Math.abs(dy));
  return (
    overlapWidth <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    overlapHeight <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    overlapWidth * overlapHeight <=
      rect.width * rect.height * MIN_CLIPPED_VISIBLE_FRACTION
  );
}

function svgFilterOffsetSuppressesPaint(
  filterTarget: HTMLElement,
  affectedElement: HTMLElement,
  primitive: Element,
  units: { emPx?: number; remPx?: number }
) {
  const targetRect = filterTarget.getBoundingClientRect();
  const affectedRect = affectedElement.getBoundingClientRect();
  const coordinateSpace = svgFilterPrimitiveUnits(primitive);
  const dx = svgFilterLengthToPx(
    primitive.getAttribute("dx"),
    targetRect.width,
    units,
    coordinateSpace
  );
  const dy = svgFilterLengthToPx(
    primitive.getAttribute("dy"),
    targetRect.height,
    units,
    coordinateSpace
  );
  return offsetRectOverlapSuppressesPaint(affectedRect, dx, dy);
}

function svgFilterInputName(primitive: Element, attribute: "in" | "in2") {
  return (primitive.getAttribute(attribute) ?? "")
    .trim()
    .toLowerCase();
}

function svgFilterInputIsSourcePaint(value: string) {
  return value === "sourcegraphic" || value === "sourcealpha";
}

function svgFilterCompositeSuppressesPaint(primitive: Element) {
  const operator = (primitive.getAttribute("operator") ?? "over").trim().toLowerCase();
  if (operator === "out") {
    const input = svgFilterInputName(primitive, "in");
    const input2 = svgFilterInputName(primitive, "in2");
    return svgFilterInputIsSourcePaint(input) && svgFilterInputIsSourcePaint(input2);
  }
  if (operator === "arithmetic") {
    const coefficients = ["k1", "k2", "k3", "k4"].map((attribute) =>
      Number(primitive.getAttribute(attribute) ?? "0")
    );
    return coefficients.every((value) => Number.isFinite(value) && value <= 0);
  }
  return false;
}

function svgFilterPrimitiveSuppressesFinalPaint(
  filterTarget: HTMLElement,
  affectedElement: HTMLElement,
  primitive: Element,
  units: { emPx?: number; remPx?: number }
) {
  const tagName = primitive.tagName.toLowerCase();
  if (tagName === "feflood") {
    return svgFilterFloodSuppressesPaint(primitive);
  }
  if (tagName === "feoffset") {
    return svgFilterOffsetSuppressesPaint(filterTarget, affectedElement, primitive, units);
  }
  if (tagName === "fecomposite") {
    return svgFilterCompositeSuppressesPaint(primitive);
  }
  return false;
}

function svgFilterResultName(value: string | null) {
  const normalized = value?.trim().toLowerCase();
  return normalized || null;
}

function svgFilterMergeSuppressesPaint(
  primitive: Element,
  suppressedResults: ReadonlyMap<string, boolean>
) {
  const mergeNodes = Array.from(primitive.children).filter(
    (child) => child.tagName.toLowerCase() === "femergenode"
  );
  return (
    mergeNodes.length > 0 &&
    mergeNodes.every((node) => {
      const input = svgFilterInputName(node, "in");
      return input !== "" && suppressedResults.get(input) === true;
    })
  );
}

function svgFilterGraphSuppressesPaint(
  filterTarget: HTMLElement,
  affectedElement: HTMLElement,
  filter: Element,
  units: { emPx?: number; remPx?: number }
) {
  const suppressedResults = new Map<string, boolean>();
  let previousOutputSuppressesPaint = false;

  for (const primitive of Array.from(filter.children)) {
    const tagName = primitive.tagName.toLowerCase();
    const outputSuppressesPaint =
      tagName === "femerge"
        ? svgFilterMergeSuppressesPaint(primitive, suppressedResults)
        : svgFilterPrimitiveSuppressesFinalPaint(
            filterTarget,
            affectedElement,
            primitive,
            units
          );
    const resultName = svgFilterResultName(primitive.getAttribute("result"));
    if (resultName !== null) {
      suppressedResults.set(resultName, outputSuppressesPaint);
    }
    previousOutputSuppressesPaint = outputSuppressesPaint;
  }

  return previousOutputSuppressesPaint;
}

function svgFilterSuppressesPaint(
  filterTarget: HTMLElement,
  value: string | undefined,
  units: { emPx?: number; remPx?: number },
  affectedElement: HTMLElement = filterTarget
) {
  for (const id of localCssUrlReferenceIds(value)) {
    const filter = filterTarget.ownerDocument.getElementById(id);
    if (!filter) {
      continue;
    }
    if (isEffectivelyTransparent(svgFilterGraphOpacityValue(filter))) {
      return true;
    }
    const primitives = Array.from(filter.children);
    const finalPrimitive = primitives[primitives.length - 1];
    if (
      finalPrimitive &&
      svgFilterPrimitiveSuppressesFinalPaint(
        filterTarget,
        affectedElement,
        finalPrimitive,
        units
      )
    ) {
      return true;
    }
    if (svgFilterGraphSuppressesPaint(filterTarget, affectedElement, filter, units)) {
      return true;
    }
  }
  return false;
}

function cssColorLooksTransparent(value: string) {
  const normalized = value.trim().toLowerCase();
  const functionalColor = normalized.match(/^([a-z][a-z0-9-]*)\((.*)\)$/);
  const functionalColorAlpha =
    functionalColor && functionalColor[2].includes("/")
      ? cssAlphaChannel(
          splitCssFunctionArgs(functionalColor[2].slice(functionalColor[2].lastIndexOf("/") + 1))[0]
        )
      : null;
  return (
    normalized === "transparent" ||
    normalized.startsWith("transparent ") ||
    /^rgba\([^)]*,\s*0(?:\.0+)?\s*\)$/.test(normalized) ||
    /^rgba?\([^)]*\/\s*0(?:%|\.0+)?\s*\)$/.test(normalized) ||
    (functionalColorAlpha !== null && functionalColorAlpha <= MIN_VISIBLE_OPACITY) ||
    (/^#[0-9a-f]{4}$/.test(normalized) && normalized.endsWith("0")) ||
    (/^#[0-9a-f]{8}$/.test(normalized) && normalized.endsWith("00"))
  );
}

interface CssColorRgba {
  r: number;
  g: number;
  b: number;
  a: number;
}

function clampCssColorChannel(value: number) {
  return Math.min(255, Math.max(0, value));
}

function clampCssAlphaChannel(value: number) {
  return Math.min(1, Math.max(0, value));
}

function cssColorChannel(value: string) {
  const trimmed = value.trim();
  if (trimmed.endsWith("%")) {
    const parsed = Number.parseFloat(trimmed.slice(0, -1));
    return Number.isFinite(parsed) ? clampCssColorChannel((parsed * 255) / 100) : null;
  }
  const parsed = Number.parseFloat(trimmed);
  return Number.isFinite(parsed) ? clampCssColorChannel(parsed) : null;
}

function cssAlphaChannel(value: string | undefined) {
  const trimmed = value?.trim();
  if (!trimmed) {
    return 1;
  }
  if (trimmed.endsWith("%")) {
    const parsed = Number.parseFloat(trimmed.slice(0, -1));
    return Number.isFinite(parsed) ? clampCssAlphaChannel(parsed / 100) : null;
  }
  const parsed = Number.parseFloat(trimmed);
  return Number.isFinite(parsed) ? clampCssAlphaChannel(parsed) : null;
}

function cssHexColor(value: string): CssColorRgba | null {
  const normalized = value.trim().toLowerCase();
  const match = normalized.match(/^#([0-9a-f]{3,8})$/);
  if (!match) {
    return null;
  }

  const hex = match[1];
  if (hex.length === 3 || hex.length === 4) {
    const r = Number.parseInt(hex[0] + hex[0], 16);
    const g = Number.parseInt(hex[1] + hex[1], 16);
    const b = Number.parseInt(hex[2] + hex[2], 16);
    const a = hex.length === 4 ? Number.parseInt(hex[3] + hex[3], 16) / 255 : 1;
    return { r, g, b, a };
  }
  if (hex.length === 6 || hex.length === 8) {
    const r = Number.parseInt(hex.slice(0, 2), 16);
    const g = Number.parseInt(hex.slice(2, 4), 16);
    const b = Number.parseInt(hex.slice(4, 6), 16);
    const a = hex.length === 8 ? Number.parseInt(hex.slice(6, 8), 16) / 255 : 1;
    return { r, g, b, a };
  }
  return null;
}

function cssRgbColor(value: string): CssColorRgba | null {
  const normalized = value.trim().toLowerCase();
  const body = cssFunctionBody(normalized, "rgb") ?? cssFunctionBody(normalized, "rgba");
  if (body === null) {
    return null;
  }

  const channels = splitCssFunctionArgs(body.replace(/\//g, " "));
  if (channels.length < 3) {
    return null;
  }
  const r = cssColorChannel(channels[0]);
  const g = cssColorChannel(channels[1]);
  const b = cssColorChannel(channels[2]);
  const a = cssAlphaChannel(channels[3]);
  if (r === null || g === null || b === null || a === null) {
    return null;
  }
  return { r, g, b, a };
}

function cssColorRgba(value: string): CssColorRgba | null {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  if (normalized === "transparent") {
    return { r: 0, g: 0, b: 0, a: 0 };
  }
  if (normalized === "black") {
    return { r: 0, g: 0, b: 0, a: 1 };
  }
  if (normalized === "white") {
    return { r: 255, g: 255, b: 255, a: 1 };
  }
  return cssHexColor(normalized) ?? cssRgbColor(normalized);
}

function cssColorIsOpaque(color: CssColorRgba | null): color is CssColorRgba {
  return color !== null && color.a >= 0.99;
}

function cssColorsMatch(left: CssColorRgba | null, right: CssColorRgba | null) {
  if (!cssColorIsOpaque(left) || !cssColorIsOpaque(right)) {
    return false;
  }
  return (
    Math.abs(left.r - right.r) <= 1 &&
    Math.abs(left.g - right.g) <= 1 &&
    Math.abs(left.b - right.b) <= 1
  );
}

function cssColorChannelsMatch(left: CssColorRgba | null, right: CssColorRgba | null) {
  if (left === null || right === null) {
    return false;
  }
  return (
    Math.abs(left.r - right.r) <= 1 &&
    Math.abs(left.g - right.g) <= 1 &&
    Math.abs(left.b - right.b) <= 1 &&
    Math.abs(left.a - right.a) <= 0.01
  );
}

function cssColorCompositedOver(
  color: CssColorRgba,
  background: CssColorRgba
): CssColorRgba {
  const sourceAlpha = clampCssAlphaChannel(color.a);
  const backgroundAlpha = clampCssAlphaChannel(background.a);
  const alpha = sourceAlpha + backgroundAlpha * (1 - sourceAlpha);
  if (alpha <= 0.01) {
    return { r: 0, g: 0, b: 0, a: 0 };
  }
  return {
    r: (color.r * sourceAlpha + background.r * backgroundAlpha * (1 - sourceAlpha)) / alpha,
    g: (color.g * sourceAlpha + background.g * backgroundAlpha * (1 - sourceAlpha)) / alpha,
    b: (color.b * sourceAlpha + background.b * backgroundAlpha * (1 - sourceAlpha)) / alpha,
    a: alpha
  };
}

function cssColorPaintedOverBackground(
  color: CssColorRgba | null,
  background: CssColorRgba
) {
  if (color === null) {
    return null;
  }
  const alpha = clampCssAlphaChannel(color.a);
  return {
    r: color.r * alpha + background.r * (1 - alpha),
    g: color.g * alpha + background.g * (1 - alpha),
    b: color.b * alpha + background.b * (1 - alpha),
    a: 1
  };
}

type CssBlendMode =
  | "normal"
  | "multiply"
  | "screen"
  | "darken"
  | "lighten"
  | "difference"
  | "exclusion";

function cssBlendMode(value: string | undefined): CssBlendMode {
  const normalized = value?.trim().toLowerCase();
  if (
    normalized === "multiply" ||
    normalized === "screen" ||
    normalized === "darken" ||
    normalized === "lighten" ||
    normalized === "difference" ||
    normalized === "exclusion"
  ) {
    return normalized;
  }
  return "normal";
}

function cssBlendChannel(source: number, backdrop: number, mode: CssBlendMode) {
  if (mode === "multiply") {
    return (source * backdrop) / 255;
  }
  if (mode === "screen") {
    return 255 - ((255 - source) * (255 - backdrop)) / 255;
  }
  if (mode === "darken") {
    return Math.min(source, backdrop);
  }
  if (mode === "lighten") {
    return Math.max(source, backdrop);
  }
  if (mode === "difference") {
    return Math.abs(backdrop - source);
  }
  if (mode === "exclusion") {
    return backdrop + source - (2 * backdrop * source) / 255;
  }
  return source;
}

function cssColorBlendedOverBackground(
  color: CssColorRgba | null,
  background: CssColorRgba,
  blendMode: string | undefined
) {
  if (color === null) {
    return null;
  }
  const mode = cssBlendMode(blendMode);
  const alpha = clampCssAlphaChannel(color.a);
  const blended = {
    r: cssBlendChannel(color.r, background.r, mode),
    g: cssBlendChannel(color.g, background.g, mode),
    b: cssBlendChannel(color.b, background.b, mode)
  };
  return {
    r: blended.r * alpha + background.r * (1 - alpha),
    g: blended.g * alpha + background.g * (1 - alpha),
    b: blended.b * alpha + background.b * (1 - alpha),
    a: 1
  };
}

function cssPaintColorOnBackground(
  filter: string | undefined,
  blendMode: string | undefined,
  color: CssColorRgba | null,
  background: CssColorRgba
) {
  const filteredColor = cssFilterPaintColor(filter, color);
  return cssColorBlendedOverBackground(filteredColor ?? color, background, blendMode);
}

function cssColorContrastsWithBackground(
  color: CssColorRgba | null,
  background: CssColorRgba
) {
  if (color === null) {
    return true;
  }
  if (color.a <= 0.01) {
    return false;
  }
  return !cssColorsMatch(cssColorPaintedOverBackground(color, background), background);
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

function cssLinePaintsWithContrast(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  prefix: string,
  background: CssColorRgba,
  units: { emPx?: number; remPx?: number } = {},
  filter = "",
  blendMode = ""
) {
  const lineStyle = cssPropertyValue(style, current, `${prefix}-style`).toLowerCase();
  const lineWidth = cssPropertyValue(style, current, `${prefix}-width`);
  const lineColor = cssPropertyValue(style, current, `${prefix}-color`);
  return (
    lineStyle !== "" &&
    lineStyle !== "none" &&
    lineStyle !== "hidden" &&
    !cssLengthLooksZero(lineWidth, units) &&
    cssColorContrastsWithBackground(
      cssPaintColorOnBackground(filter, blendMode, cssColorRgba(lineColor), background),
      background
    )
  );
}

function fieldTextPaintColor(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  const textFillColor = cssPropertyValue(style, current, "-webkit-text-fill-color");
  return isMeaningfulCssValue(textFillColor) && textFillColor.toLowerCase() !== "currentcolor"
    ? textFillColor
    : cssPropertyValue(style, current, "color");
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

  return cssColorLooksTransparent(fieldTextPaintColor(style, current));
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

function fieldBorderPaintContrastsWithBackground(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  background: CssColorRgba,
  units: { emPx?: number; remPx?: number },
  filter = "",
  blendMode = ""
) {
  return ["top", "right", "bottom", "left"].some((side) =>
    cssLinePaintsWithContrast(
      style,
      current,
      `border-${side}`,
      background,
      units,
      filter,
      blendMode
    )
  );
}

function fieldOutlinePaintContrastsWithBackground(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  background: CssColorRgba,
  units: { emPx?: number; remPx?: number },
  filter = "",
  blendMode = ""
) {
  return cssLinePaintsWithContrast(
    style,
    current,
    "outline",
    background,
    units,
    filter,
    blendMode
  );
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

interface AncestorBackgroundPaint {
  color: CssColorRgba;
  element: HTMLElement | null;
}

function nearestOpaqueAncestorBackground(current: HTMLElement): AncestorBackgroundPaint {
  let ancestor = parentElementOrShadowHost(current);
  while (ancestor) {
    const style = ancestor.ownerDocument.defaultView?.getComputedStyle(ancestor);
    const color = elementBackgroundPaintColor(style, ancestor);
    if (cssColorIsOpaque(color)) {
      return { color, element: ancestor };
    }
    ancestor = parentElementOrShadowHost(ancestor);
  }
  return { color: { r: 255, g: 255, b: 255, a: 1 }, element: null };
}

function nearestOpaqueAncestorBackgroundColor(current: HTMLElement) {
  return nearestOpaqueAncestorBackground(current).color;
}

function cssFilterChainForPaintSource(current: HTMLElement | null) {
  const filters: string[] = [];
  for (
    let paintSource: HTMLElement | null = current;
    paintSource;
    paintSource = parentElementOrShadowHost(paintSource)
  ) {
    const style = paintSource.ownerDocument.defaultView?.getComputedStyle(paintSource);
    const filter = cssPropertyValue(style, paintSource, "filter");
    if (isMeaningfulCssValue(filter)) {
      filters.push(filter);
    }
  }
  return filters.join(" ");
}

function cssBlendModeForPaintSource(current: HTMLElement | null) {
  for (
    let paintSource: HTMLElement | null = current;
    paintSource;
    paintSource = parentElementOrShadowHost(paintSource)
  ) {
    const style = paintSource.ownerDocument.defaultView?.getComputedStyle(paintSource);
    const blendMode = cssPropertyValue(style, paintSource, "mix-blend-mode");
    if (cssBlendMode(blendMode) !== "normal") {
      return blendMode;
    }
  }
  return "";
}

function fieldHasPlaceholderText(current: HTMLElement) {
  const tagName = current.tagName.toLowerCase();
  if (tagName !== "input" && tagName !== "textarea") {
    return false;
  }
  return (current.getAttribute("placeholder") ?? "").trim() !== "";
}

function fieldOwnBackgroundColor(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  return elementBackgroundPaintColor(style, current);
}

function fieldEffectiveBackgroundColor(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  const ownBackground = fieldOwnBackgroundColor(style, current);
  const ancestorBackground = nearestOpaqueAncestorBackgroundColor(current);
  return cssColorPaintedOverBackground(ownBackground, ancestorBackground) ?? ancestorBackground;
}

function fieldBackgroundPaintBlendsWithAncestor(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  if (!cssPaintListLooksEmpty(cssPropertyValue(style, current, "background-image"))) {
    return false;
  }
  const ownBackground = fieldOwnBackgroundColor(style, current);
  if (ownBackground === null) {
    return true;
  }
  return !cssColorContrastsWithBackground(
    ownBackground,
    nearestOpaqueAncestorBackgroundColor(current)
  );
}

function fieldTextPaintBlendsWithBackground(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  return !cssColorContrastsWithBackground(
    cssColorRgba(fieldTextPaintColor(style, current)),
    fieldEffectiveBackgroundColor(style, current)
  );
}

function cssShadowLayerPaintsWithContrast(
  value: string,
  background: CssColorRgba,
  fallbackColor: CssColorRgba | null,
  filter = "",
  blendMode = ""
) {
  const colorToken = splitCssFunctionArgs(value.toLowerCase()).find((token) => {
    const normalized = token.trim();
    return normalized === "currentcolor" || cssColorRgba(normalized) !== null;
  });
  const color =
    colorToken === undefined || colorToken === "currentcolor"
      ? fallbackColor
      : cssColorRgba(colorToken);
  return cssColorContrastsWithBackground(
    cssPaintColorOnBackground(filter, blendMode, color, background),
    background
  );
}

function cssShadowPaintsWithContrast(
  value: string,
  background: CssColorRgba,
  fallbackColor: CssColorRgba | null,
  filter = "",
  blendMode = ""
) {
  if (cssPaintListLooksEmpty(value)) {
    return false;
  }
  return splitCssCommaList(value).some((layer) =>
    cssShadowLayerPaintsWithContrast(layer, background, fallbackColor, filter, blendMode)
  );
}

function fieldChromePaintBlendsIntoBackground(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const filter = cssFilterChainForPaintSource(current);
  const blendMode = cssBlendModeForPaintSource(current);
  const backgroundImage = cssPropertyValue(style, current, "background-image");
  const hasUnmodeledBackgroundImage =
    !cssPaintListLooksEmpty(backgroundImage) &&
    cssBackgroundImageSolidColor(backgroundImage) === null;
  const backgroundPaint = nearestOpaqueAncestorBackground(current);
  const ancestorBackground =
    cssFilterPaintColor(
      cssFilterChainForPaintSource(backgroundPaint.element),
      backgroundPaint.color
    ) ?? backgroundPaint.color;
  const ownBackground = fieldOwnBackgroundColor(style, current);
  const paintedOwnBackground = cssPaintColorOnBackground(
    filter,
    blendMode,
    ownBackground,
    ancestorBackground
  );
  const textColor = cssPaintColorOnBackground(
    filter,
    blendMode,
    cssColorRgba(fieldTextPaintColor(style, current)),
    ancestorBackground
  );
  const collapsedFilterColor = cssFilterPaintCollapseColor(filter);
  if (collapsedFilterColor !== null) {
    return !cssColorContrastsWithBackground(
      collapsedFilterColor,
      ancestorBackground
    );
  }
  return (
    !fieldHasPlaceholderText(current) &&
    !hasUnmodeledBackgroundImage &&
    !cssColorContrastsWithBackground(textColor, ancestorBackground) &&
    !cssColorContrastsWithBackground(paintedOwnBackground, ancestorBackground) &&
    !fieldBorderPaintContrastsWithBackground(
      style,
      current,
      ancestorBackground,
      units,
      filter,
      blendMode
    ) &&
    !fieldOutlinePaintContrastsWithBackground(
      style,
      current,
      ancestorBackground,
      units,
      filter,
      blendMode
    ) &&
    !cssShadowPaintsWithContrast(
      cssPropertyValue(style, current, "box-shadow"),
      ancestorBackground,
      textColor,
      filter,
      blendMode
    ) &&
    !cssShadowPaintsWithContrast(
      cssPropertyValue(style, current, "text-shadow"),
      ancestorBackground,
      textColor,
      filter,
      blendMode
    )
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

function cssColorStopColor(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  const functionColor = normalized.match(/^(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\([^)]*\)/);
  if (functionColor) {
    return functionColor[0];
  }
  const firstToken = splitCssFunctionArgs(normalized)[0];
  if (firstToken !== undefined && cssColorRgba(firstToken) !== null) {
    return firstToken;
  }
  return null;
}

function gradientColorStops(value: string) {
  return splitCssCommaList(value)
    .map(cssColorStopColor)
    .filter((color): color is string => color !== null);
}

function cssGradientSolidColor(value: string) {
  const normalized = value.trim().toLowerCase();
  const gradientName = normalized.match(
    /^((?:repeating-)?(?:linear|radial|conic)-gradient)\(/
  )?.[1];
  if (!gradientName) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const colors: CssColorRgba[] = [];
  let sawColorStop = false;
  for (const part of splitCssCommaList(body)) {
    const stopColor = cssColorStopColor(part);
    if (stopColor === null) {
      if (sawColorStop) {
        return null;
      }
      continue;
    }
    const color = cssColorRgba(stopColor);
    if (color === null) {
      return null;
    }
    colors.push(color);
    sawColorStop = true;
  }

  if (colors.length === 0) {
    return null;
  }
  const [first, ...rest] = colors;
  return rest.every((color) => cssColorChannelsMatch(first, color)) ? first : null;
}

function cssBackgroundImageSolidColor(value: string) {
  if (cssPaintListLooksEmpty(value)) {
    return null;
  }

  let result: CssColorRgba = { r: 0, g: 0, b: 0, a: 0 };
  for (const layer of splitCssCommaList(value).reverse()) {
    const layerColor = cssGradientSolidColor(layer);
    if (layerColor === null) {
      return null;
    }
    result = cssColorCompositedOver(layerColor, result);
  }
  return result;
}

function elementBackgroundPaintColor(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement
) {
  const backgroundColor =
    cssColorRgba(cssPropertyValue(style, current, "background-color")) ??
    ({ r: 0, g: 0, b: 0, a: 0 } satisfies CssColorRgba);
  const backgroundImage = cssBackgroundImageSolidColor(
    cssPropertyValue(style, current, "background-image")
  );
  return backgroundImage === null
    ? backgroundColor
    : cssColorCompositedOver(backgroundImage, backgroundColor);
}

function maskModePaintsByLuminance(value: string | undefined) {
  return splitCssCommaList(value?.trim().toLowerCase() ?? "").some(
    (layer) => layer.trim() === "luminance"
  );
}

function maskImageFullySuppressesPaint(value: string | undefined, modeValue: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }
  const gradientMatch = normalized.match(/^([a-z-]*gradient)\(/);
  if (!gradientMatch) {
    return false;
  }
  const gradientBody = cssFunctionBody(normalized, gradientMatch[1]);
  if (gradientBody === null) {
    return false;
  }
  const colorStops = gradientColorStops(gradientBody);
  return (
    colorStops.length > 0 &&
    (colorStops.every(cssColorLooksTransparent) ||
      (maskModePaintsByLuminance(modeValue) && colorStops.every(cssColorLooksBlack)))
  );
}

function maskColorStopPaints(value: string, modeValue: string | undefined) {
  const color = cssColorRgba(value);
  return (
    !cssColorLooksTransparent(value) &&
    (color === null || color.a > MIN_VISIBLE_OPACITY) &&
    !(maskModePaintsByLuminance(modeValue) && cssColorLooksBlack(value))
  );
}

type LinearMaskGradientDirection = { axis: "x" | "y"; reverse: boolean };
type CssMaskGradientPoint = { offset: number | null; paints: boolean };

function linearMaskGradientDirection(value: string): LinearMaskGradientDirection | null {
  const tokens = splitCssFunctionArgs(value.trim().toLowerCase());
  if (tokens.length === 2 && tokens[0] === "to") {
    if (tokens[1] === "right") {
      return { axis: "x", reverse: false };
    }
    if (tokens[1] === "left") {
      return { axis: "x", reverse: true };
    }
    if (tokens[1] === "bottom") {
      return { axis: "y", reverse: false };
    }
    if (tokens[1] === "top") {
      return { axis: "y", reverse: true };
    }
  }

  const angle = tokens[0]?.match(/^(-?\d+(?:\.\d+)?)deg$/);
  if (!angle) {
    return null;
  }
  const normalizedAngle = ((Number.parseFloat(angle[1]) % 360) + 360) % 360;
  if (Math.abs(normalizedAngle - 90) <= 0.001) {
    return { axis: "x", reverse: false };
  }
  if (Math.abs(normalizedAngle - 270) <= 0.001) {
    return { axis: "x", reverse: true };
  }
  if (Math.abs(normalizedAngle - 180) <= 0.001) {
    return { axis: "y", reverse: true };
  }
  if (normalizedAngle <= 0.001 || Math.abs(normalizedAngle - 360) <= 0.001) {
    return { axis: "y", reverse: false };
  }
  return null;
}

function linearGradientDescriptorWithoutColorInterpolation(value: string) {
  const tokens = splitCssFunctionArgs(value.trim().toLowerCase());
  const inIndex = tokens.findIndex((token) => token === "in");
  return inIndex < 0 ? value : tokens.slice(0, inIndex).join(" ");
}

function linearGradientDescriptorHasColorInterpolation(value: string) {
  return splitCssFunctionArgs(value.trim().toLowerCase()).includes("in");
}

function cssMaskLinearGradientStopPoints(
  value: string,
  axisSize: number,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): CssMaskGradientPoint[] | null {
  const normalized = value.trim().toLowerCase();
  const color = cssColorStopColor(normalized);
  if (color === null) {
    return null;
  }

  const positions = splitCssFunctionArgs(normalized.slice(color.length).trim());
  const paints = maskColorStopPaints(color, modeValue);
  if (positions.length === 0) {
    return [{ offset: null, paints }];
  }

  const points = positions.slice(0, 2).map((position) => {
    const offset = cssLengthToPx(position, axisSize, units);
    return offset === null ? null : { offset, paints };
  });
  return points.every((point): point is { offset: number; paints: boolean } => point !== null)
    ? points
    : null;
}

function normalizeCssMaskGradientStopOffsets(
  points: CssMaskGradientPoint[],
  axisSize: number
): Array<{ offset: number; paints: boolean }> | null {
  if (points.length === 0) {
    return [];
  }

  const offsets = points.map((point) => point.offset);
  if (offsets[0] === null) {
    offsets[0] = 0;
  }
  if (offsets[offsets.length - 1] === null) {
    offsets[offsets.length - 1] = axisSize;
  }

  let index = 0;
  while (index < offsets.length) {
    if (offsets[index] !== null) {
      index += 1;
      continue;
    }

    const startIndex = index - 1;
    let endIndex = index + 1;
    while (endIndex < offsets.length && offsets[endIndex] === null) {
      endIndex += 1;
    }
    const start = startIndex >= 0 ? offsets[startIndex] : null;
    const end = endIndex < offsets.length ? offsets[endIndex] : null;
    if (start === null || end === null) {
      return null;
    }

    const step = (end - start) / (endIndex - startIndex);
    for (let fillIndex = index; fillIndex < endIndex; fillIndex += 1) {
      offsets[fillIndex] = start + step * (fillIndex - startIndex);
    }
    index = endIndex + 1;
  }

  return points.map((point, pointIndex) => {
    const offset = offsets[pointIndex];
    return offset === null ? null : { ...point, offset };
  }).filter((point): point is { offset: number; paints: boolean } => point !== null);
}

function cssMaskLinearGradientPaintedRanges(
  body: string,
  axisSize: number,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number },
  repeatsGradient = false
) {
  const parts = splitCssCommaList(body);
  let direction: LinearMaskGradientDirection = { axis: "y", reverse: false };
  let stopParts = parts;
  const firstPart = parts[0] ?? "";
  const parsedDirection = linearMaskGradientDirection(
    linearGradientDescriptorWithoutColorInterpolation(firstPart)
  );
  if (parsedDirection !== null) {
    direction = parsedDirection;
    stopParts = parts.slice(1);
  } else if (linearGradientDescriptorHasColorInterpolation(firstPart)) {
    stopParts = parts.slice(1);
  } else if (cssColorStopColor(parts[0] ?? "") === null) {
    return null;
  }

  const rawPoints: CssMaskGradientPoint[] = [];
  for (const part of stopParts) {
    const stopPoints = cssMaskLinearGradientStopPoints(part, axisSize, modeValue, units);
    if (stopPoints === null) {
      return null;
    }
    rawPoints.push(...stopPoints);
  }
  if (rawPoints.length < 2) {
    return null;
  }
  const normalizedPoints = normalizeCssMaskGradientStopOffsets(rawPoints, axisSize);
  if (normalizedPoints === null) {
    return null;
  }
  let points = normalizedPoints;
  let previousOffset = points[0].offset;
  points = points.map((point, index) => {
    if (index === 0) {
      return point;
    }
    previousOffset = Math.max(previousOffset, point.offset);
    return { ...point, offset: previousOffset };
  });

  if (repeatsGradient) {
    const first = points[0];
    const last = points[points.length - 1];
    const period = last.offset - first.offset;
    if (period <= 0) {
      return null;
    }

    const baseRanges: Array<{ start: number; end: number }> = [];
    for (let index = 0; index < points.length - 1; index += 1) {
      const left = points[index];
      const right = points[index + 1];
      if (left.paints || right.paints) {
        const start = Math.min(left.offset, right.offset);
        const end = Math.max(left.offset, right.offset);
        if (end > start) {
          baseRanges.push({ start, end });
        }
      }
    }

    const ranges: Array<{ start: number; end: number }> = [];
    for (const range of baseRanges) {
      const firstShift = Math.floor((0 - range.end) / period) * period;
      for (
        let shift = firstShift;
        range.start + shift < axisSize;
        shift += period
      ) {
        const start = Math.max(0, range.start + shift);
        const end = Math.min(axisSize, range.end + shift);
        if (end > start) {
          ranges.push({ start, end });
        }
      }
    }
    return { direction, ranges };
  }

  const ranges: Array<{ start: number; end: number }> = [];
  const addRange = (start: number, end: number) => {
    const rangeStart = Math.min(start, end);
    const rangeEnd = Math.max(start, end);
    if (rangeEnd > rangeStart) {
      ranges.push({ start: rangeStart, end: rangeEnd });
    }
  };

  const [first] = points;
  if (first.paints && first.offset > 0) {
    addRange(0, first.offset);
  }
  for (let index = 0; index < points.length - 1; index += 1) {
    const left = points[index];
    const right = points[index + 1];
    if (left.paints || right.paints) {
      addRange(left.offset, right.offset);
    }
  }
  const last = points[points.length - 1];
  if (last.paints && last.offset < axisSize) {
    addRange(last.offset, axisSize);
  }

  return { direction, ranges };
}

function intervalOverlapLength(
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number
) {
  return Math.max(0, Math.min(leftEnd, rightEnd) - Math.max(leftStart, rightStart));
}

function linearMaskLayerSuppressesField(
  layer: string,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  fieldBounds: RectBounds,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): boolean | null {
  const normalized = layer.trim().toLowerCase();
  const gradientName = normalized.startsWith("linear-gradient(")
    ? "linear-gradient"
    : normalized.startsWith("repeating-linear-gradient(")
      ? "repeating-linear-gradient"
      : null;
  if (gradientName === null) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const size = maskLayerSize(sizeValue, rect, units);
  if (size.width <= 0 || size.height <= 0) {
    return true;
  }
  const repeatsX = maskRepeatRepeatsAxis(repeatValue, "x");
  const repeatsY = maskRepeatRepeatsAxis(repeatValue, "y");
  if ((repeatsX && size.width < rect.width) || (repeatsY && size.height < rect.height)) {
    return null;
  }

  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  if (
    (x === null && Math.abs(rect.width - size.width) > 0.001) ||
    (y === null && Math.abs(rect.height - size.height) > 0.001)
  ) {
    return null;
  }

  const axisSize = bodyAxisSize(body, size);
  const painted = cssMaskLinearGradientPaintedRanges(
    body,
    axisSize,
    modeValue,
    units,
    gradientName === "repeating-linear-gradient"
  );
  if (painted === null) {
    return null;
  }
  if (painted.ranges.length === 0) {
    return true;
  }

  const fieldStart =
    painted.direction.axis === "x" ? fieldBounds.left - (x ?? 0) : fieldBounds.top - (y ?? 0);
  const fieldEnd =
    painted.direction.axis === "x" ? fieldBounds.right - (x ?? 0) : fieldBounds.bottom - (y ?? 0);
  const fieldLength = Math.max(0, fieldEnd - fieldStart);
  if (fieldLength <= 0) {
    return true;
  }

  const paintedLength = painted.ranges.reduce((total, range) => {
    const start = painted.direction.reverse ? axisSize - range.end : range.start;
    const end = painted.direction.reverse ? axisSize - range.start : range.end;
    return total + intervalOverlapLength(fieldStart, fieldEnd, start, end);
  }, 0);

  return (
    paintedLength <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    paintedLength <= fieldLength * MIN_CLIPPED_VISIBLE_FRACTION
  );
}

function cssMaskLinearGradientVisibleBounds(
  layer: string,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const normalized = layer.trim().toLowerCase();
  const gradientName = normalized.startsWith("linear-gradient(")
    ? "linear-gradient"
    : normalized.startsWith("repeating-linear-gradient(")
      ? "repeating-linear-gradient"
      : null;
  if (gradientName === null) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const size = maskLayerSize(sizeValue, rect, units);
  if (size.width <= 0 || size.height <= 0) {
    return null;
  }
  const repeatsX = maskRepeatRepeatsAxis(repeatValue, "x");
  const repeatsY = maskRepeatRepeatsAxis(repeatValue, "y");
  if ((repeatsX && size.width < rect.width) || (repeatsY && size.height < rect.height)) {
    return null;
  }

  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  if (
    (x === null && Math.abs(rect.width - size.width) > 0.001) ||
    (y === null && Math.abs(rect.height - size.height) > 0.001)
  ) {
    return null;
  }

  const axisSize = bodyAxisSize(body, size);
  const painted = cssMaskLinearGradientPaintedRanges(
    body,
    axisSize,
    modeValue,
    units,
    gradientName === "repeating-linear-gradient"
  );
  if (painted === null || painted.ranges.length === 0) {
    return null;
  }

  const bounds = painted.ranges.map((range): RectBounds => {
    const start = painted.direction.reverse ? axisSize - range.end : range.start;
    const end = painted.direction.reverse ? axisSize - range.start : range.end;
    if (painted.direction.axis === "x") {
      return {
        left: (x ?? 0) + start,
        top: y ?? 0,
        right: (x ?? 0) + end,
        bottom: (y ?? 0) + size.height
      };
    }
    return {
      left: x ?? 0,
      top: (y ?? 0) + start,
      right: (x ?? 0) + size.width,
      bottom: (y ?? 0) + end
    };
  });
  return unionBounds(bounds);
}

function cssMaskRadialGradientPaintedRanges(
  body: string,
  axisSize: number,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number },
  repeatsGradient = false
) {
  const parts = splitCssCommaList(body);
  const stopParts = cssColorStopColor(parts[0] ?? "") === null ? parts.slice(1) : parts;
  if (stopParts.length < 2) {
    return null;
  }

  const rawPoints: CssMaskGradientPoint[] = [];
  for (const part of stopParts) {
    const stopPoints = cssMaskLinearGradientStopPoints(part, axisSize, modeValue, units);
    if (stopPoints === null) {
      return null;
    }
    rawPoints.push(...stopPoints);
  }
  if (rawPoints.length < 2) {
    return null;
  }

  const normalizedPoints = normalizeCssMaskGradientStopOffsets(rawPoints, axisSize);
  if (normalizedPoints === null) {
    return null;
  }

  let previousOffset = normalizedPoints[0].offset;
  const points = normalizedPoints.map((point, index) => {
    if (index === 0) {
      return point;
    }
    previousOffset = Math.max(previousOffset, point.offset);
    return { ...point, offset: previousOffset };
  });

  if (repeatsGradient) {
    const first = points[0];
    const last = points[points.length - 1];
    const period = last.offset - first.offset;
    if (period <= 0) {
      return null;
    }

    const baseRanges: Array<{ start: number; end: number }> = [];
    for (let index = 0; index < points.length - 1; index += 1) {
      const left = points[index];
      const right = points[index + 1];
      if (left.paints || right.paints) {
        const start = Math.min(left.offset, right.offset);
        const end = Math.max(left.offset, right.offset);
        if (end > start) {
          baseRanges.push({ start, end });
        }
      }
    }

    const ranges: Array<{ start: number; end: number }> = [];
    for (const range of baseRanges) {
      const firstShift = Math.floor((0 - range.end) / period) * period;
      for (
        let shift = firstShift;
        range.start + shift < axisSize;
        shift += period
      ) {
        const start = Math.max(0, range.start + shift);
        const end = Math.min(axisSize, range.end + shift);
        if (end > start) {
          ranges.push({ start, end });
        }
      }
    }
    return ranges;
  }

  const ranges: Array<{ start: number; end: number }> = [];
  const addRange = (start: number, end: number) => {
    const rangeStart = Math.min(start, end);
    const rangeEnd = Math.max(start, end);
    if (rangeEnd > rangeStart) {
      ranges.push({ start: rangeStart, end: rangeEnd });
    }
  };

  const [first] = points;
  if (first.paints && first.offset > 0) {
    addRange(0, first.offset);
  }
  for (let index = 0; index < points.length - 1; index += 1) {
    const left = points[index];
    const right = points[index + 1];
    if (left.paints || right.paints) {
      addRange(left.offset, right.offset);
    }
  }
  const last = points[points.length - 1];
  if (last.paints && last.offset < axisSize) {
    addRange(last.offset, axisSize);
  }

  return ranges;
}

function cssMaskRadialGradientVisibleBounds(
  layer: string,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const normalized = layer.trim().toLowerCase();
  const gradientName = normalized.startsWith("radial-gradient(")
    ? "radial-gradient"
    : normalized.startsWith("repeating-radial-gradient(")
      ? "repeating-radial-gradient"
      : null;
  if (gradientName === null) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const size = maskLayerSize(sizeValue, rect, units);
  if (size.width <= 0 || size.height <= 0) {
    return null;
  }
  const repeatsX = maskRepeatRepeatsAxis(repeatValue, "x");
  const repeatsY = maskRepeatRepeatsAxis(repeatValue, "y");
  if ((repeatsX && size.width < rect.width) || (repeatsY && size.height < rect.height)) {
    return null;
  }

  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  if (
    (x === null && Math.abs(rect.width - size.width) > 0.001) ||
    (y === null && Math.abs(rect.height - size.height) > 0.001)
  ) {
    return null;
  }

  const parts = splitCssCommaList(body);
  const descriptor = cssColorStopColor(parts[0] ?? "") === null ? parts[0] ?? "" : "";
  const descriptorTokens = splitCssFunctionArgs(descriptor);
  const atIndex = descriptorTokens.findIndex((token) => token.toLowerCase() === "at");
  const center = basicPositionToPx(
    atIndex < 0 ? [] : descriptorTokens.slice(atIndex + 1),
    size.width,
    size.height,
    units
  );
  if (center === null) {
    return null;
  }

  const paintedRanges = cssMaskRadialGradientPaintedRanges(
    body,
    Math.max(size.width, size.height),
    modeValue,
    units,
    gradientName === "repeating-radial-gradient"
  );
  if (paintedRanges === null || paintedRanges.length === 0) {
    return null;
  }
  const radius = Math.max(...paintedRanges.map((range) => range.end));
  if (radius <= 0) {
    return null;
  }

  return {
    left: (x ?? 0) + center.x - radius,
    top: (y ?? 0) + center.y - radius,
    right: (x ?? 0) + center.x + radius,
    bottom: (y ?? 0) + center.y + radius
  };
}

function rectBoundsSamplePoints(bounds: RectBounds) {
  const width = bounds.right - bounds.left;
  const height = bounds.bottom - bounds.top;
  if (width <= 0 || height <= 0) {
    return [];
  }
  const insetX = Math.min(4, width / 2);
  const insetY = Math.min(4, height / 2);
  return [
    { x: bounds.left + width / 2, y: bounds.top + height / 2 },
    { x: bounds.left + insetX, y: bounds.top + insetY },
    { x: bounds.right - insetX, y: bounds.top + insetY },
    { x: bounds.left + insetX, y: bounds.bottom - insetY },
    { x: bounds.right - insetX, y: bounds.bottom - insetY }
  ];
}

function radialPaintedRangesContainDistance(
  ranges: Array<{ start: number; end: number }>,
  distance: number
) {
  return ranges.some(
    (range) => distance >= range.start - 1e-6 && distance <= range.end + 1e-6
  );
}

function radialMaskLayerSuppressesField(
  layer: string,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  fieldBounds: RectBounds,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): boolean | null {
  const normalized = layer.trim().toLowerCase();
  const gradientName = normalized.startsWith("radial-gradient(")
    ? "radial-gradient"
    : normalized.startsWith("repeating-radial-gradient(")
      ? "repeating-radial-gradient"
      : null;
  if (gradientName === null) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const size = maskLayerSize(sizeValue, rect, units);
  if (size.width <= 0 || size.height <= 0) {
    return true;
  }
  const repeatsX = maskRepeatRepeatsAxis(repeatValue, "x");
  const repeatsY = maskRepeatRepeatsAxis(repeatValue, "y");
  if ((repeatsX && size.width < rect.width) || (repeatsY && size.height < rect.height)) {
    return null;
  }

  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  if (
    (x === null && Math.abs(rect.width - size.width) > 0.001) ||
    (y === null && Math.abs(rect.height - size.height) > 0.001)
  ) {
    return null;
  }

  const parts = splitCssCommaList(body);
  const descriptor = cssColorStopColor(parts[0] ?? "") === null ? parts[0] ?? "" : "";
  const descriptorTokens = splitCssFunctionArgs(descriptor);
  const atIndex = descriptorTokens.findIndex((token) => token.toLowerCase() === "at");
  const center = basicPositionToPx(
    atIndex < 0 ? [] : descriptorTokens.slice(atIndex + 1),
    size.width,
    size.height,
    units
  );
  if (center === null) {
    return null;
  }

  const paintedRanges = cssMaskRadialGradientPaintedRanges(
    body,
    Math.max(size.width, size.height),
    modeValue,
    units,
    gradientName === "repeating-radial-gradient"
  );
  if (paintedRanges === null) {
    return null;
  }
  if (paintedRanges.length === 0) {
    return true;
  }

  const offsetX = x ?? 0;
  const offsetY = y ?? 0;
  const samples = rectBoundsSamplePoints(fieldBounds);
  for (const sample of samples) {
    const sampleX = sample.x - offsetX;
    const sampleY = sample.y - offsetY;
    if (sampleX < 0 || sampleY < 0 || sampleX > size.width || sampleY > size.height) {
      continue;
    }
    if (
      radialPaintedRangesContainDistance(
        paintedRanges,
        Math.hypot(sampleX - center.x, sampleY - center.y)
      )
    ) {
      return false;
    }
  }

  return true;
}

function cssAngleToDegrees(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  if (normalized.endsWith("%")) {
    const percent = Number.parseFloat(normalized.slice(0, -1));
    return Number.isFinite(percent) ? percent * 3.6 : null;
  }
  const match = normalized.match(/^(-?\d+(?:\.\d+)?)(deg|grad|rad|turn)?$/);
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
  if (unit === "grad") {
    return parsed * 0.9;
  }
  if (unit === "rad") {
    return (parsed * 180) / Math.PI;
  }
  return parsed;
}

function normalizeDegrees(value: number) {
  return ((value % 360) + 360) % 360;
}

function cssMaskConicGradientStopPoints(
  value: string,
  modeValue: string | undefined
): CssMaskGradientPoint[] | null {
  const normalized = value.trim().toLowerCase();
  const color = cssColorStopColor(normalized);
  if (color === null) {
    return null;
  }

  const positions = splitCssFunctionArgs(normalized.slice(color.length).trim());
  const paints = maskColorStopPaints(color, modeValue);
  if (positions.length === 0) {
    return [{ offset: null, paints }];
  }

  const points = positions.slice(0, 2).map((position) => {
    const offset = cssAngleToDegrees(position);
    return offset === null ? null : { offset, paints };
  });
  return points.every((point): point is { offset: number; paints: boolean } => point !== null)
    ? points
    : null;
}

function cssMaskConicGradientPaintedRanges(
  body: string,
  modeValue: string | undefined,
  repeatsGradient = false
) {
  const parts = splitCssCommaList(body);
  const stopParts = cssColorStopColor(parts[0] ?? "") === null ? parts.slice(1) : parts;
  if (stopParts.length < 2) {
    return null;
  }

  const rawPoints: CssMaskGradientPoint[] = [];
  for (const part of stopParts) {
    const stopPoints = cssMaskConicGradientStopPoints(part, modeValue);
    if (stopPoints === null) {
      return null;
    }
    rawPoints.push(...stopPoints);
  }
  if (rawPoints.length < 2) {
    return null;
  }

  const normalizedPoints = normalizeCssMaskGradientStopOffsets(rawPoints, 360);
  if (normalizedPoints === null) {
    return null;
  }

  let previousOffset = normalizedPoints[0].offset;
  const points = normalizedPoints.map((point, index) => {
    if (index === 0) {
      return point;
    }
    previousOffset = Math.max(previousOffset, point.offset);
    return { ...point, offset: previousOffset };
  });

  if (repeatsGradient) {
    const first = points[0];
    const last = points[points.length - 1];
    const period = last.offset - first.offset;
    if (period <= 0) {
      return null;
    }

    const baseRanges: Array<{ start: number; end: number }> = [];
    for (let index = 0; index < points.length - 1; index += 1) {
      const left = points[index];
      const right = points[index + 1];
      if (left.paints || right.paints) {
        const start = Math.min(left.offset, right.offset);
        const end = Math.max(left.offset, right.offset);
        if (end > start) {
          baseRanges.push({ start, end });
        }
      }
    }

    const ranges: Array<{ start: number; end: number }> = [];
    for (const range of baseRanges) {
      const firstShift = Math.floor((0 - range.end) / period) * period;
      for (let shift = firstShift; range.start + shift < 360; shift += period) {
        const start = Math.max(0, range.start + shift);
        const end = Math.min(360, range.end + shift);
        if (end > start) {
          ranges.push({ start, end });
        }
      }
    }
    return ranges;
  }

  const ranges: Array<{ start: number; end: number }> = [];
  const addRange = (start: number, end: number) => {
    const rangeStart = Math.min(start, end);
    const rangeEnd = Math.max(start, end);
    if (rangeEnd > rangeStart) {
      ranges.push({ start: rangeStart, end: rangeEnd });
    }
  };

  const [first] = points;
  if (first.paints && first.offset > 0) {
    addRange(0, first.offset);
  }
  for (let index = 0; index < points.length - 1; index += 1) {
    const left = points[index];
    const right = points[index + 1];
    if (left.paints || right.paints) {
      addRange(left.offset, right.offset);
    }
  }
  const last = points[points.length - 1];
  if (last.paints && last.offset < 360) {
    addRange(last.offset, 360);
  }

  return ranges;
}

function conicMaskLayerSuppressesField(
  layer: string,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  fieldBounds: RectBounds,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
): boolean | null {
  const normalized = layer.trim().toLowerCase();
  const gradientName = normalized.startsWith("conic-gradient(")
    ? "conic-gradient"
    : normalized.startsWith("repeating-conic-gradient(")
      ? "repeating-conic-gradient"
      : null;
  if (gradientName === null) {
    return null;
  }
  const body = cssFunctionBody(normalized, gradientName);
  if (body === null) {
    return null;
  }

  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }
  const size = maskLayerSize(sizeValue, rect, units);
  if (size.width <= 0 || size.height <= 0) {
    return true;
  }
  const repeatsX = maskRepeatRepeatsAxis(repeatValue, "x");
  const repeatsY = maskRepeatRepeatsAxis(repeatValue, "y");
  if ((repeatsX && size.width < rect.width) || (repeatsY && size.height < rect.height)) {
    return null;
  }

  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  if (
    (x === null && Math.abs(rect.width - size.width) > 0.001) ||
    (y === null && Math.abs(rect.height - size.height) > 0.001)
  ) {
    return null;
  }

  const parts = splitCssCommaList(body);
  const descriptor = cssColorStopColor(parts[0] ?? "") === null ? parts[0] ?? "" : "";
  const descriptorTokens = splitCssFunctionArgs(descriptor);
  const fromIndex = descriptorTokens.findIndex((token) => token.toLowerCase() === "from");
  const fromAngle =
    fromIndex < 0 ? 0 : cssAngleToDegrees(descriptorTokens[fromIndex + 1]) ?? 0;
  const atIndex = descriptorTokens.findIndex((token) => token.toLowerCase() === "at");
  const center = basicPositionToPx(
    atIndex < 0 ? [] : descriptorTokens.slice(atIndex + 1),
    size.width,
    size.height,
    units
  );
  if (center === null) {
    return null;
  }

  const paintedRanges = cssMaskConicGradientPaintedRanges(
    body,
    modeValue,
    gradientName === "repeating-conic-gradient"
  );
  if (paintedRanges === null) {
    return null;
  }
  if (paintedRanges.length === 0) {
    return true;
  }

  const offsetX = x ?? 0;
  const offsetY = y ?? 0;
  const samples = rectBoundsSamplePoints(fieldBounds);
  let paintedSamples = 0;
  for (const sample of samples) {
    const sampleX = sample.x - offsetX;
    const sampleY = sample.y - offsetY;
    if (sampleX < 0 || sampleY < 0 || sampleX > size.width || sampleY > size.height) {
      continue;
    }
    const angle = normalizeDegrees(
      (Math.atan2(sampleY - center.y, sampleX - center.x) * 180) / Math.PI
    );
    const relativeAngle = normalizeDegrees(angle - fromAngle);
    if (radialPaintedRangesContainDistance(paintedRanges, relativeAngle)) {
      paintedSamples += 1;
    }
  }

  return paintedSamples < Math.ceil(samples.length / 2);
}

function bodyAxisSize(
  body: string,
  size: { width: number; height: number }
) {
  const parsedDirection = linearMaskGradientDirection(
    linearGradientDescriptorWithoutColorInterpolation(splitCssCommaList(body)[0] ?? "")
  );
  const axis = parsedDirection?.axis ?? "y";
  return axis === "x" ? size.width : size.height;
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
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "auto") {
    return false;
  }
  const rect = current.getBoundingClientRect();
  const widthAxis = hasMeaningfulClientRect(rect) ? rect.width : 0;
  const heightAxis = hasMeaningfulClientRect(rect) ? rect.height : 0;
  const repeatLayers = splitCssCommaList(repeatValue?.trim().toLowerCase() ?? "");
  return splitCssCommaList(normalized).some((layer, index) => {
    const repeatLayer = repeatLayers[index] ?? repeatLayers[repeatLayers.length - 1];
    const [width, height = width] = splitCssFunctionArgs(layer);
    const widthPx = width === undefined ? null : cssLengthToPx(width, widthAxis, units);
    const heightPx = height === undefined ? null : cssLengthToPx(height, heightAxis, units);
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

function maskAxisVisibleBounds(
  axisSize: number,
  imageSize: number,
  offset: number | null,
  repeatsAxis: boolean
) {
  if (offset === null || repeatsAxis) {
    return { start: 0, end: axisSize };
  }
  return {
    start: Math.max(0, offset),
    end: Math.min(axisSize, offset + imageSize)
  };
}

function maskLayerVisibleBounds(
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const rect = current.getBoundingClientRect();
  if (!hasMeaningfulClientRect(rect)) {
    return null;
  }

  const size = maskLayerSize(sizeValue, rect, units);
  const position = positionValue?.trim() || "0% 0%";
  const x = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "x"),
    rect.width,
    size.width,
    units
  );
  const y = maskPositionOffsetToPx(
    maskPositionAxisComponent(position, "y"),
    rect.height,
    size.height,
    units
  );
  const xBounds = maskAxisVisibleBounds(
    rect.width,
    size.width,
    x,
    maskRepeatRepeatsAxis(repeatValue, "x")
  );
  const yBounds = maskAxisVisibleBounds(
    rect.height,
    size.height,
    y,
    maskRepeatRepeatsAxis(repeatValue, "y")
  );
  return {
    left: xBounds.start,
    top: yBounds.start,
    right: xBounds.end,
    bottom: yBounds.end
  };
}

function cssMaskVisibleBounds(
  current: HTMLElement,
  imageValue: string | undefined,
  positionValue: string | undefined,
  sizeValue: string | undefined,
  repeatValue: string | undefined,
  modeValue: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const trimmed = imageValue?.trim();
  const normalized = trimmed?.toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  const imageLayers = splitCssCommaList(trimmed ?? "");
  const positionLayers = splitCssCommaList(positionValue?.trim().toLowerCase() ?? "");
  const sizeLayers = splitCssCommaList(sizeValue?.trim().toLowerCase() ?? "");
  const repeatLayers = splitCssCommaList(repeatValue?.trim().toLowerCase() ?? "");
  const bounds = imageLayers.flatMap((layer, index) => {
    const svgBounds = svgMaskVisibleBounds(current, layer, units);
    if (svgBounds !== null) {
      return [svgBounds];
    }
    if (maskImageFullySuppressesPaint(layer, modeValue)) {
      return [];
    }
    const gradientBounds = cssMaskLinearGradientVisibleBounds(
      layer,
      maskLayerValue(positionLayers, index),
      maskLayerValue(sizeLayers, index),
      maskLayerValue(repeatLayers, index),
      current,
      modeValue,
      units
    );
    if (gradientBounds !== null) {
      return [gradientBounds];
    }
    const radialGradientBounds = cssMaskRadialGradientVisibleBounds(
      layer,
      maskLayerValue(positionLayers, index),
      maskLayerValue(sizeLayers, index),
      maskLayerValue(repeatLayers, index),
      current,
      modeValue,
      units
    );
    if (radialGradientBounds !== null) {
      return [radialGradientBounds];
    }
    const layerBounds = maskLayerVisibleBounds(
      maskLayerValue(positionLayers, index),
      maskLayerValue(sizeLayers, index),
      maskLayerValue(repeatLayers, index),
      current,
      units
    );
    return layerBounds === null ? [] : [layerBounds];
  });
  return unionBounds(bounds);
}

function maskStyleVisibleBounds(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const maskMode = cssPropertyValue(style, current, "mask-mode");
  const webkitMaskMode = cssPropertyValue(style, current, "-webkit-mask-mode") || maskMode;
  return unionBounds(
    [
      cssMaskVisibleBounds(
        current,
        cssPropertyValue(style, current, "mask-image"),
        cssPropertyValue(style, current, "mask-position"),
        cssPropertyValue(style, current, "mask-size"),
        cssPropertyValue(style, current, "mask-repeat"),
        maskMode,
        units
      ),
      cssMaskVisibleBounds(
        current,
        cssPropertyValue(style, current, "-webkit-mask-image"),
        cssPropertyValue(style, current, "-webkit-mask-position"),
        cssPropertyValue(style, current, "-webkit-mask-size"),
        cssPropertyValue(style, current, "-webkit-mask-repeat"),
        webkitMaskMode,
        units
      ),
      cssMaskVisibleBounds(
        current,
        cssPropertyValue(style, current, "mask"),
        cssPropertyValue(style, current, "mask-position"),
        cssPropertyValue(style, current, "mask-size"),
        cssPropertyValue(style, current, "mask-repeat"),
        maskMode,
        units
      ),
      cssMaskVisibleBounds(
        current,
        cssPropertyValue(style, current, "-webkit-mask"),
        cssPropertyValue(style, current, "-webkit-mask-position"),
        cssPropertyValue(style, current, "-webkit-mask-size"),
        cssPropertyValue(style, current, "-webkit-mask-repeat"),
        webkitMaskMode,
        units
      )
    ].filter((bounds): bounds is RectBounds => bounds !== null)
  );
}

function sampledMaskStyleSuppressesField(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  fieldBounds: RectBounds,
  units: { emPx?: number; remPx?: number }
) {
  const maskMode = cssPropertyValue(style, current, "mask-mode");
  const webkitMaskMode = cssPropertyValue(style, current, "-webkit-mask-mode") || maskMode;
  const sources = [
    {
      image: cssPropertyValue(style, current, "mask-image"),
      position: cssPropertyValue(style, current, "mask-position"),
      size: cssPropertyValue(style, current, "mask-size"),
      repeat: cssPropertyValue(style, current, "mask-repeat"),
      mode: maskMode
    },
    {
      image: cssPropertyValue(style, current, "-webkit-mask-image"),
      position: cssPropertyValue(style, current, "-webkit-mask-position"),
      size: cssPropertyValue(style, current, "-webkit-mask-size"),
      repeat: cssPropertyValue(style, current, "-webkit-mask-repeat"),
      mode: webkitMaskMode
    },
    {
      image: cssPropertyValue(style, current, "mask"),
      position: cssPropertyValue(style, current, "mask-position"),
      size: cssPropertyValue(style, current, "mask-size"),
      repeat: cssPropertyValue(style, current, "mask-repeat"),
      mode: maskMode
    },
    {
      image: cssPropertyValue(style, current, "-webkit-mask"),
      position: cssPropertyValue(style, current, "-webkit-mask-position"),
      size: cssPropertyValue(style, current, "-webkit-mask-size"),
      repeat: cssPropertyValue(style, current, "-webkit-mask-repeat"),
      mode: webkitMaskMode
    }
  ];

  let modeledSampledLayer = false;
  for (const source of sources) {
    if (!isMeaningfulCssValue(source.image)) {
      continue;
    }
    const layers = splitCssCommaList(source.image);
    const positions = splitCssCommaList(source.position?.trim().toLowerCase() ?? "");
    const sizes = splitCssCommaList(source.size?.trim().toLowerCase() ?? "");
    const repeats = splitCssCommaList(source.repeat?.trim().toLowerCase() ?? "");
    for (const [index, layer] of layers.entries()) {
      if (!isMeaningfulCssValue(layer)) {
        continue;
      }
      const position = maskLayerValue(positions, index);
      const size = maskLayerValue(sizes, index);
      const repeat = maskLayerValue(repeats, index);
      const suppressed =
        linearMaskLayerSuppressesField(
          layer,
          position,
          size,
          repeat,
          current,
          fieldBounds,
          source.mode,
          units
        ) ??
        radialMaskLayerSuppressesField(
          layer,
          position,
          size,
          repeat,
          current,
          fieldBounds,
          source.mode,
          units
        ) ??
        conicMaskLayerSuppressesField(
          layer,
          position,
          size,
          repeat,
          current,
          fieldBounds,
          source.mode,
          units
        );
      if (suppressed === null) {
        return false;
      }
      modeledSampledLayer = true;
      if (!suppressed) {
        return false;
      }
    }
  }

  return modeledSampledLayer;
}

function svgElementOpacityValue(
  shape: Element,
  attribute: string,
  style: CSSStyleDeclaration | undefined
) {
  const styled = shape as SVGElement;
  return (
    cssOpacityValue(shape.getAttribute(attribute) ?? undefined) ??
    cssOpacityValue(styled.style?.getPropertyValue(attribute)) ??
    cssOpacityValue(style?.getPropertyValue(attribute)) ??
    1
  );
}

function svgMaskOpacitySuppressesPaint(
  shape: Element,
  style: CSSStyleDeclaration | undefined
) {
  const opacity = svgElementOpacityValue(shape, "opacity", style);
  const fillOpacity = svgElementOpacityValue(shape, "fill-opacity", style);
  return isEffectivelyTransparent(opacity * fillOpacity);
}

function svgPaintSuppressesMask(shape: Element, style: CSSStyleDeclaration | undefined) {
  const fill =
    shape.getAttribute("fill") ??
    (shape as SVGElement).style?.fill ??
    style?.getPropertyValue("fill") ??
    null;
  return (
    svgMaskOpacitySuppressesPaint(shape, style) ||
    cssColorLooksTransparent(fill ?? "") ||
    cssColorLooksBlack(fill)
  );
}

function svgMaskShapeSuppressesPaint(
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

  const tagName = shape.tagName.toLowerCase();
  const shapeStyle = shape.ownerDocument.defaultView?.getComputedStyle(shape);
  const matrix = svgElementTransformMatrix(shape, inheritedMatrix, units);
  if (svgMaskOpacitySuppressesPaint(shape, shapeStyle)) {
    return true;
  }
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    const useMatrix = svgMatrixMultiply(
      matrix,
      svgUsePositionMatrix(shape, current.getBoundingClientRect(), units, "userSpaceOnUse")
    );
    return (
      target === null ||
      svgMaskShapeSuppressesPaint(current, target, units, seen, useMatrix)
    );
  }
  if (shape.children.length > 0 && (tagName === "g" || tagName === "svg" || tagName === "mask")) {
    return Array.from(shape.children).every((child) =>
      svgMaskShapeSuppressesPaint(current, child, units, seen, matrix)
    );
  }
  return (
    svgClipShapeSuppressesField(current, shape, units, new Set(), inheritedMatrix) ||
    svgPaintSuppressesMask(shape, shapeStyle)
  );
}

function svgMaskShapeVisibleBounds(
  current: HTMLElement,
  shape: Element,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set(),
  inheritedMatrix: SvgMatrix2d = identitySvgMatrix()
): RectBounds | null {
  if (seen.has(shape)) {
    return null;
  }
  seen.add(shape);

  const tagName = shape.tagName.toLowerCase();
  const shapeStyle = shape.ownerDocument.defaultView?.getComputedStyle(shape);
  const matrix = svgElementTransformMatrix(shape, inheritedMatrix, units);
  if (svgMaskOpacitySuppressesPaint(shape, shapeStyle)) {
    return null;
  }
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    const useMatrix = svgMatrixMultiply(
      matrix,
      svgUsePositionMatrix(shape, current.getBoundingClientRect(), units, "userSpaceOnUse")
    );
    return target === null
      ? null
      : svgMaskShapeVisibleBounds(current, target, units, seen, useMatrix);
  }
  if (shape.children.length > 0 && (tagName === "g" || tagName === "svg" || tagName === "mask")) {
    return unionBounds(
      Array.from(shape.children)
        .map((child) => svgMaskShapeVisibleBounds(current, child, units, seen, matrix))
        .filter((bounds): bounds is RectBounds => bounds !== null)
    );
  }
  if (svgPaintSuppressesMask(shape, shapeStyle)) {
    return null;
  }
  return svgClipShapeVisibleBounds(current, shape, units, new Set(), inheritedMatrix);
}

function svgMaskVisibleBounds(
  current: HTMLElement,
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const bounds = localCssUrlReferenceIds(value)
    .map((id) => {
      const mask = current.ownerDocument.getElementById(id);
      if (!mask || mask.tagName.toLowerCase() !== "mask") {
        return null;
      }
      const maskStyle = mask.ownerDocument.defaultView?.getComputedStyle(mask);
      if (svgMaskOpacitySuppressesPaint(mask, maskStyle)) {
        return null;
      }
      return unionBounds(
        Array.from(mask.children)
          .map((shape) => svgMaskShapeVisibleBounds(current, shape, units))
          .filter((shapeBounds): shapeBounds is RectBounds => shapeBounds !== null)
      );
    })
    .filter((maskBounds): maskBounds is RectBounds => maskBounds !== null);
  return unionBounds(bounds);
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
    const maskStyle = mask.ownerDocument.defaultView?.getComputedStyle(mask);
    if (svgMaskOpacitySuppressesPaint(mask, maskStyle)) {
      return true;
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
  const maskMode = cssPropertyValue(style, current, "mask-mode");
  const webkitMaskMode = cssPropertyValue(style, current, "-webkit-mask-mode") || maskMode;
  if (
    maskImages.some((maskImage) =>
      maskImageFullySuppressesPaint(maskImage, `${maskMode}, ${webkitMaskMode}`)
    )
  ) {
    return true;
  }
  if (maskImages.some((maskImage) => svgMaskSuppressesPaint(current, maskImage, units))) {
    return true;
  }
  return (
    maskSizeSuppressesPaint(
      cssPropertyValue(style, current, "mask-size"),
      cssPropertyValue(style, current, "mask-repeat"),
      current,
      units
    ) ||
    maskSizeSuppressesPaint(
      cssPropertyValue(style, current, "-webkit-mask-size"),
      cssPropertyValue(style, current, "-webkit-mask-repeat"),
      current,
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

function boxShadowLayerCoversPoint(
  layer: string,
  rect: DOMRect,
  point: { x: number; y: number },
  units: { emPx?: number; remPx?: number }
) {
  const normalized = layer.trim().toLowerCase();
  if (!normalized || normalized === "none" || /\binset\b/.test(normalized)) {
    return false;
  }
  const lengths = splitCssFunctionArgs(normalized)
    .map((token) => numericCssValue(token, units))
    .filter((value): value is number => value !== null);
  if (lengths.length < 2) {
    return false;
  }

  const [offsetX, offsetY, blur = 0, spread = 0] = lengths;
  const expansion = Math.max(0, blur) + spread;
  return (
    point.x >= rect.left + offsetX - expansion &&
    point.x <= rect.right + offsetX + expansion &&
    point.y >= rect.top + offsetY - expansion &&
    point.y <= rect.bottom + offsetY + expansion
  );
}

function boxShadowCoversPoint(
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  rect: DOMRect,
  point: { x: number; y: number }
) {
  const boxShadow = cssPropertyValue(style, current, "box-shadow");
  if (cssPaintListLooksEmpty(boxShadow)) {
    return false;
  }
  const rootStyle = current.ownerDocument.defaultView?.getComputedStyle(
    current.ownerDocument.documentElement
  );
  const emPx = numericCssValue(style?.fontSize || current.style.fontSize) ?? 16;
  const remPx = numericCssValue(rootStyle?.fontSize) ?? emPx;
  return splitCssCommaList(boxShadow).some((layer) =>
    boxShadowLayerCoversPoint(layer, rect, point, { emPx, remPx })
  );
}

function cssStyleValue(style: CSSStyleDeclaration | undefined, property: string) {
  return style?.getPropertyValue(property).trim() ?? "";
}

function cssStyleLinePaints(
  style: CSSStyleDeclaration | undefined,
  prefix: string,
  units: { emPx?: number; remPx?: number } = {}
) {
  const lineStyle = cssStyleValue(style, `${prefix}-style`).toLowerCase();
  const lineWidth = cssStyleValue(style, `${prefix}-width`);
  const lineColor = cssStyleValue(style, `${prefix}-color`);
  return (
    lineStyle !== "" &&
    lineStyle !== "none" &&
    lineStyle !== "hidden" &&
    !cssLengthLooksZero(lineWidth, units) &&
    !cssColorLooksTransparent(lineColor)
  );
}

function cssStylePaintsVisibleBox(
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  return (
    !cssPaintListLooksEmpty(cssStyleValue(style, "background-image")) ||
    !cssColorLooksTransparent(cssStyleValue(style, "background-color")) ||
    ["top", "right", "bottom", "left"].some((side) =>
      cssStyleLinePaints(style, `border-${side}`, units)
    ) ||
    cssStyleLinePaints(style, "outline", units) ||
    !cssPaintListLooksEmpty(cssStyleValue(style, "box-shadow"))
  );
}

function computedPseudoStyle(element: HTMLElement, pseudoElement: "::before" | "::after") {
  const view = element.ownerDocument.defaultView;
  if (!view) {
    return undefined;
  }
  const getComputedStyle = view.getComputedStyle as typeof view.getComputedStyle & {
    mock?: unknown;
  };
  if (
    view.navigator.userAgent.includes("jsdom") &&
    getComputedStyle.mock === undefined
  ) {
    return undefined;
  }
  try {
    return getComputedStyle(element, pseudoElement);
  } catch {
    return undefined;
  }
}

function pseudoContentPaints(style: CSSStyleDeclaration | undefined) {
  const content = cssStyleValue(style, "content").toLowerCase();
  return content !== "" && content !== "normal" && content !== "none";
}

function pseudoElementMayPaintAboveElement(
  element: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  pseudoElement: "::before" | "::after"
) {
  const pseudoZIndex = numericZIndex(cssStyleValue(style, "z-index"));
  const elementStyle = element.ownerDocument.defaultView?.getComputedStyle(element);
  const elementZIndex = numericZIndex(elementStyle?.zIndex || element.style.zIndex);
  if (pseudoZIndex === null) {
    return pseudoElement === "::after" && elementZIndex === null;
  }
  return pseudoZIndex > (elementZIndex ?? 0);
}

function cssStyleLengthToPx(
  style: CSSStyleDeclaration | undefined,
  property: string,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const value = cssStyleValue(style, property);
  return value === "" ? null : cssLengthToPx(value, axisSize, units);
}

function pseudoElementBounds(
  candidateRect: DOMRect,
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const width =
    cssStyleLengthToPx(style, "width", candidateRect.width, units) ?? candidateRect.width;
  const height =
    cssStyleLengthToPx(style, "height", candidateRect.height, units) ?? candidateRect.height;
  const left = cssStyleLengthToPx(style, "left", candidateRect.width, units);
  const right = cssStyleLengthToPx(style, "right", candidateRect.width, units);
  const top = cssStyleLengthToPx(style, "top", candidateRect.height, units);
  const bottom = cssStyleLengthToPx(style, "bottom", candidateRect.height, units);
  const position = cssStyleValue(style, "position").toLowerCase();
  const baseLeft = position === "fixed" ? 0 : candidateRect.left;
  const baseTop = position === "fixed" ? 0 : candidateRect.top;
  const x =
    left !== null
      ? baseLeft + left
      : right !== null
        ? baseLeft + candidateRect.width - right - width
        : baseLeft;
  const y =
    top !== null
      ? baseTop + top
      : bottom !== null
        ? baseTop + candidateRect.height - bottom - height
        : baseTop;
  return {
    left: x,
    top: y,
    right: x + width,
    bottom: y + height
  };
}

function boundsContainPoint(
  bounds: { left: number; top: number; right: number; bottom: number },
  point: { x: number; y: number }
) {
  return (
    point.x >= bounds.left &&
    point.x <= bounds.right &&
    point.y >= bounds.top &&
    point.y <= bounds.bottom
  );
}

function pseudoElementCoversPoint(
  element: HTMLElement,
  candidate: HTMLElement,
  pseudoElement: "::before" | "::after",
  candidateRect: DOMRect,
  point: { x: number; y: number }
) {
  const style = computedPseudoStyle(candidate, pseudoElement);
  const rootStyle = candidate.ownerDocument.defaultView?.getComputedStyle(
    candidate.ownerDocument.documentElement
  );
  const emPx = numericCssValue(cssStyleValue(style, "font-size")) ?? 16;
  const remPx = numericCssValue(rootStyle?.fontSize) ?? emPx;
  const cssUnits = { emPx, remPx };
  const opacity = cssOpacityValue(cssStyleValue(style, "opacity"));
  const filter = cssStyleValue(style, "filter");
  const display = cssStyleValue(style, "display");
  const visibility = cssStyleValue(style, "visibility");

  return (
    pseudoContentPaints(style) &&
    display !== "none" &&
    visibility !== "hidden" &&
    visibility !== "collapse" &&
    !isEffectivelyTransparent(opacity) &&
    !isEffectivelyTransparent(paintFilterOpacityValue(candidate, filter)) &&
    pseudoElementMayPaintAboveElement(element, style, pseudoElement) &&
    cssStylePaintsVisibleBox(style, cssUnits) &&
    boundsContainPoint(pseudoElementBounds(candidateRect, style, cssUnits), point)
  );
}

function ancestorPseudoElementCoversPoint(
  element: HTMLElement,
  candidate: HTMLElement,
  candidateRect: DOMRect,
  point: { x: number; y: number }
) {
  return (
    pseudoElementCoversPoint(element, candidate, "::before", candidateRect, point) ||
    pseudoElementCoversPoint(element, candidate, "::after", candidateRect, point)
  );
}

function elementVisualCoversPoint(
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  rect: DOMRect,
  point: { x: number; y: number }
) {
  return pointInsideRect(point, rect) || boxShadowCoversPoint(current, style, rect, point);
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
  const opacity = cssOpacityValue(cssPropertyValue(style, current, "opacity"));
  const filter = cssPropertyValue(style, current, "filter");
  return (
    style?.display !== "none" &&
    style?.visibility !== "hidden" &&
    style?.visibility !== "collapse" &&
    !isEffectivelyTransparent(opacity) &&
    !isEffectivelyTransparent(paintFilterOpacityValue(current, filter)) &&
    !svgFilterSuppressesPaint(current, filter, cssUnits) &&
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
    opacity *= cssOpacityValue(cssPropertyValue(style, current, "opacity")) ?? 1;
    const currentFilterOpacity = paintFilterOpacityValue(
      current,
      cssPropertyValue(style, current, "filter")
    );
    filterOpacity *= currentFilterOpacity ?? 1;
    if (
      isEffectivelyTransparent(opacity) ||
      isEffectivelyTransparent(filterOpacity) ||
      isEffectivelyTransparent(opacity * filterOpacity)
    ) {
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
      if (!(candidate instanceof ownerWindow.HTMLElement)) {
        continue;
      }
      const style = candidate.ownerDocument.defaultView?.getComputedStyle(candidate);
      const candidateRect = candidate.getBoundingClientRect();
      if (candidate !== element && candidate.contains(element)) {
        if (
          ancestorPseudoElementCoversPoint(element, candidate, candidateRect, point) &&
          elementCumulativePaintIsVisible(candidate)
        ) {
          return true;
        }
        continue;
      }
      if (
        candidate === element ||
        element.contains(candidate) ||
        !elementMayPaintAboveElement(element, candidate) ||
        !elementVisualCoversPoint(candidate, style, candidateRect, point)
      ) {
        continue;
      }

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

interface RectBounds {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

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

function boundsFromPoints(points: Array<{ x: number; y: number }>): RectBounds | null {
  if (points.length === 0) {
    return null;
  }
  const xValues = points.map((point) => point.x);
  const yValues = points.map((point) => point.y);
  return {
    left: Math.min(...xValues),
    top: Math.min(...yValues),
    right: Math.max(...xValues),
    bottom: Math.max(...yValues)
  };
}

function unionBounds(bounds: RectBounds[]): RectBounds | null {
  if (bounds.length === 0) {
    return null;
  }
  return {
    left: Math.min(...bounds.map((bound) => bound.left)),
    top: Math.min(...bounds.map((bound) => bound.top)),
    right: Math.max(...bounds.map((bound) => bound.right)),
    bottom: Math.max(...bounds.map((bound) => bound.bottom))
  };
}

function elementRectRelativeToAncestor(element: HTMLElement, ancestor: HTMLElement): RectBounds | null {
  const elementRect = element.getBoundingClientRect();
  const ancestorRect = ancestor.getBoundingClientRect();
  if (!hasMeaningfulClientRect(elementRect) || !hasMeaningfulClientRect(ancestorRect)) {
    return null;
  }
  return {
    left: elementRect.left - ancestorRect.left,
    top: elementRect.top - ancestorRect.top,
    right: elementRect.right - ancestorRect.left,
    bottom: elementRect.bottom - ancestorRect.top
  };
}

function boundsOverlap(
  left: RectBounds,
  right: RectBounds
) {
  const width = Math.max(0, Math.min(left.right, right.right) - Math.max(left.left, right.left));
  const height = Math.max(0, Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top));
  return { width, height, area: width * height };
}

function boundsArea(bounds: RectBounds) {
  return Math.max(0, bounds.right - bounds.left) * Math.max(0, bounds.bottom - bounds.top);
}

function boundsOverlapSuppressesField(visibleBounds: RectBounds, fieldBounds: RectBounds) {
  const overlap = boundsOverlap(visibleBounds, fieldBounds);
  const fieldArea = boundsArea(fieldBounds);
  return (
    overlap.width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    overlap.height <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    (fieldArea > 0 && overlap.area <= fieldArea * MIN_CLIPPED_VISIBLE_FRACTION)
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

function clippedAncestorVisibleOverlapSuppressesField(
  element: HTMLElement,
  ancestor: HTMLElement
) {
  const elementRect = element.getBoundingClientRect();
  const ancestorRect = ancestor.getBoundingClientRect();
  if (!hasMeaningfulClientRect(elementRect) || !hasMeaningfulClientRect(ancestorRect)) {
    return false;
  }

  const width = Math.max(
    0,
    Math.min(elementRect.right, ancestorRect.right) - Math.max(elementRect.left, ancestorRect.left)
  );
  const height = Math.max(
    0,
    Math.min(elementRect.bottom, ancestorRect.bottom) - Math.max(elementRect.top, ancestorRect.top)
  );
  const area = width * height;
  const elementArea = elementRect.width * elementRect.height;
  return (
    width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    height <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
    (elementArea > 0 && area <= elementArea * MIN_CLIPPED_VISIBLE_FRACTION)
  );
}

function insetClipVisibleBounds(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const inset = expandBoxValues(insetBoxTokens(value));
  const top = cssLengthToPx(inset.top, rect.height, units);
  const right = cssLengthToPx(inset.right, rect.width, units);
  const bottom = cssLengthToPx(inset.bottom, rect.height, units);
  const left = cssLengthToPx(inset.left, rect.width, units);
  if (top === null || right === null || bottom === null || left === null) {
    return null;
  }
  return {
    left,
    top,
    right: rect.width - right,
    bottom: rect.height - bottom
  };
}

function legacyClipVisibleBounds(
  value: string,
  units: { emPx?: number; remPx?: number },
  fieldRect: DOMRect
): RectBounds | null {
  const match = value.trim().toLowerCase().match(/^rect\((.*)\)$/);
  if (!match) {
    return null;
  }
  const rect = expandBoxValues(splitCssFunctionArgs(match[1]));
  const top = cssLengthToPx(rect.top, fieldRect.height, units);
  const right = cssLengthToPx(rect.right, fieldRect.width, units);
  const bottom = cssLengthToPx(rect.bottom, fieldRect.height, units);
  const left = cssLengthToPx(rect.left, fieldRect.width, units);
  return top === null || right === null || bottom === null || left === null
    ? null
    : { left, top, right, bottom };
}

function circleClipVisibleBounds(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const tokens = splitCssFunctionArgs(value);
  const atIndex = tokens.findIndex((token) => token.toLowerCase() === "at");
  const radius = atIndex === 0 ? "closest-side" : tokens[0] ?? "closest-side";
  const center = basicShapePositionToPx(atIndex < 0 ? [] : tokens.slice(atIndex + 1), rect, units);
  if (center === null) {
    return null;
  }
  const radiusPx = circleRadiusToPx(radius, center, rect, units);
  return radiusPx === null
    ? null
    : {
        left: center.x - radiusPx,
        top: center.y - radiusPx,
        right: center.x + radiusPx,
        bottom: center.y + radiusPx
      };
}

function ellipseClipVisibleBounds(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const tokens = splitCssFunctionArgs(value);
  const atIndex = tokens.findIndex((token) => token.toLowerCase() === "at");
  const radiusTokens = atIndex < 0 ? tokens : tokens.slice(0, atIndex);
  const radiusX = radiusTokens[0] ?? "closest-side";
  const radiusY = radiusTokens[1] ?? radiusX;
  const center = basicShapePositionToPx(atIndex < 0 ? [] : tokens.slice(atIndex + 1), rect, units);
  if (center === null) {
    return null;
  }
  const radiusXPx = ellipseRadiusToPx(radiusX, "x", center, rect, units);
  const radiusYPx = ellipseRadiusToPx(radiusY, "y", center, rect, units);
  return radiusXPx === null || radiusYPx === null
    ? null
    : {
        left: center.x - radiusXPx,
        top: center.y - radiusYPx,
        right: center.x + radiusXPx,
        bottom: center.y + radiusYPx
      };
}

function xywhClipVisibleBounds(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const [x, y, width, height] = splitCssFunctionArgs(value);
  const xPx = x === undefined ? null : cssLengthToPx(x, rect.width, units);
  const yPx = y === undefined ? null : cssLengthToPx(y, rect.height, units);
  const widthPx = width === undefined ? null : cssLengthToPx(width, rect.width, units);
  const heightPx = height === undefined ? null : cssLengthToPx(height, rect.height, units);
  return xPx === null || yPx === null || widthPx === null || heightPx === null
    ? null
    : { left: xPx, top: yPx, right: xPx + widthPx, bottom: yPx + heightPx };
}

function svgClipShapeVisibleBounds(
  current: HTMLElement,
  shape: Element,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set(),
  inheritedMatrix: SvgMatrix2d = identitySvgMatrix(),
  coordinateSpace: SvgClipCoordinateSpace = "userSpaceOnUse"
): RectBounds | null {
  if (seen.has(shape)) {
    return null;
  }
  seen.add(shape);

  const shapeStyle = shape.ownerDocument.defaultView?.getComputedStyle(shape);
  const inlineStyle = (shape as SVGElement).style;
  const display = shapeStyle?.display || inlineStyle?.display;
  const visibility = shapeStyle?.visibility || inlineStyle?.visibility;
  if (display === "none" || visibility === "hidden" || visibility === "collapse") {
    return null;
  }

  const rect = current.getBoundingClientRect();
  const tagName = shape.tagName.toLowerCase();
  const matrix = svgElementTransformMatrix(shape, inheritedMatrix, units);
  if (svgClipElementIsNonRendering(tagName)) {
    return null;
  }
  if (
    svgElementClipPathValues(shape, shapeStyle).some((clipPath) =>
      svgClipPathFullyClips(current, clipPath, units, seen)
    )
  ) {
    return { left: 0, top: 0, right: 0, bottom: 0 };
  }
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    const useMatrix = svgMatrixMultiply(
      matrix,
      svgUsePositionMatrix(shape, rect, units, coordinateSpace)
    );
    return target === null
      ? { left: 0, top: 0, right: 0, bottom: 0 }
      : svgClipShapeVisibleBounds(current, target, units, seen, useMatrix, coordinateSpace);
  }
  if (tagName === "rect") {
    const x = svgLengthToPx(shape.getAttribute("x"), rect.width, units, coordinateSpace);
    const y = svgLengthToPx(shape.getAttribute("y"), rect.height, units, coordinateSpace);
    const width = svgLengthToPx(
      shape.getAttribute("width"),
      rect.width,
      units,
      coordinateSpace
    );
    const height = svgLengthToPx(
      shape.getAttribute("height"),
      rect.height,
      units,
      coordinateSpace
    );
    return boundsFromPoints(
      transformSvgPoints(
        [
          { x, y },
          { x: x + width, y },
          { x: x + width, y: y + height },
          { x, y: y + height }
        ],
        matrix
      )
    );
  }
  if (tagName === "circle") {
    const radius = svgLengthToPx(
      shape.getAttribute("r"),
      Math.min(rect.width, rect.height),
      units,
      coordinateSpace
    );
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units, coordinateSpace);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units, coordinateSpace);
    return boundsFromPoints(
      transformSvgPoints(
        [
          { x: cx - radius, y: cy - radius },
          { x: cx + radius, y: cy - radius },
          { x: cx + radius, y: cy + radius },
          { x: cx - radius, y: cy + radius }
        ],
        matrix
      )
    );
  }
  if (tagName === "ellipse") {
    const radiusX = svgLengthToPx(
      shape.getAttribute("rx"),
      rect.width,
      units,
      coordinateSpace
    );
    const radiusY = svgLengthToPx(
      shape.getAttribute("ry"),
      rect.height,
      units,
      coordinateSpace
    );
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units, coordinateSpace);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units, coordinateSpace);
    return boundsFromPoints(
      transformSvgPoints(
        [
          { x: cx - radiusX, y: cy - radiusY },
          { x: cx + radiusX, y: cy - radiusY },
          { x: cx + radiusX, y: cy + radiusY },
          { x: cx - radiusX, y: cy + radiusY }
        ],
        matrix
      )
    );
  }
  if (tagName === "line") {
    return boundsFromPoints(
      transformSvgPoints(
        [
          {
            x: svgLengthToPx(shape.getAttribute("x1"), rect.width, units, coordinateSpace),
            y: svgLengthToPx(shape.getAttribute("y1"), rect.height, units, coordinateSpace)
          },
          {
            x: svgLengthToPx(shape.getAttribute("x2"), rect.width, units, coordinateSpace),
            y: svgLengthToPx(shape.getAttribute("y2"), rect.height, units, coordinateSpace)
          }
        ],
        matrix
      )
    );
  }
  if (tagName === "polygon" || tagName === "polyline") {
    return boundsFromPoints(
      transformSvgPoints(
        svgPointListToPoints(
          shape.getAttribute("points") ?? "",
          rect,
          units,
          coordinateSpace
        ),
        matrix
      )
    );
  }
  if (tagName === "path") {
    return boundsFromPoints(
      transformSvgPoints(svgPathDataToPoints(shape.getAttribute("d") ?? ""), matrix)
    );
  }
  if (svgClipElementIsContainer(tagName)) {
    return unionBounds(
      Array.from(shape.children)
        .map((child) =>
          svgClipShapeVisibleBounds(current, child, units, seen, matrix, coordinateSpace)
        )
        .filter((bounds): bounds is RectBounds => bounds !== null)
    );
  }
  return null;
}

function svgClipPathVisibleBounds(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  const [id] = localCssUrlReferenceIds(value);
  if (!id) {
    return null;
  }
  const clipPath = current.ownerDocument.getElementById(id);
  if (!clipPath) {
    return null;
  }
  const shapes = Array.from(clipPath.children);
  if (shapes.length === 0) {
    return { left: 0, top: 0, right: 0, bottom: 0 };
  }
  const rect = current.getBoundingClientRect();
  const coordinateSpace =
    clipPath.getAttribute("clipPathUnits")?.trim() === "objectBoundingBox"
      ? "objectBoundingBox"
      : "userSpaceOnUse";
  const baseMatrix =
    coordinateSpace === "objectBoundingBox"
      ? { a: rect.width, b: 0, c: 0, d: rect.height, e: 0, f: 0 }
      : identitySvgMatrix();
  const clipPathMatrix = svgElementTransformMatrix(clipPath, baseMatrix, units);
  return unionBounds(
    shapes
      .map((shape) =>
        svgClipShapeVisibleBounds(
          current,
          shape,
          units,
          new Set([clipPath]),
          clipPathMatrix,
          coordinateSpace
        )
      )
      .filter((bounds): bounds is RectBounds => bounds !== null)
  );
}

function clipPathVisibleBounds(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number }
): RectBounds | null {
  if (localCssUrlReferenceIds(value).length > 0) {
    return svgClipPathVisibleBounds(current, value, units);
  }

  const normalized = value.trim().toLowerCase();
  const rect = current.getBoundingClientRect();
  const insetBody = cssFunctionBody(normalized, "inset");
  if (insetBody !== null) {
    return insetClipVisibleBounds(insetBody, rect, units);
  }

  const circleBody = cssFunctionBody(normalized, "circle");
  if (circleBody !== null) {
    return circleClipVisibleBounds(circleBody, rect, units);
  }

  const ellipseBody = cssFunctionBody(normalized, "ellipse");
  if (ellipseBody !== null) {
    return ellipseClipVisibleBounds(ellipseBody, rect, units);
  }

  const rectBody = cssFunctionBody(normalized, "rect");
  if (rectBody !== null) {
    return legacyClipVisibleBounds(`rect(${rectBody})`, units, rect);
  }

  const xywhBody = cssFunctionBody(normalized, "xywh");
  if (xywhBody !== null) {
    return xywhClipVisibleBounds(xywhBody, rect, units);
  }

  const polygonBody = cssFunctionBody(normalized, "polygon");
  if (polygonBody !== null) {
    const points = splitCssCommaList(polygonBody).flatMap((point) => {
      const [x, y] = splitCssFunctionArgs(point);
      const parsedX = x === undefined ? null : cssCoordinateToPx(x, rect.width, units);
      const parsedY = y === undefined ? null : cssCoordinateToPx(y, rect.height, units);
      return parsedX === null || parsedY === null ? [] : [{ x: parsedX, y: parsedY }];
    });
    return boundsFromPoints(points);
  }

  const shapeBody = cssFunctionBody(normalized, "shape");
  if (shapeBody !== null) {
    return boundsFromPoints(shapeCommandPoints(shapeBody, rect, units));
  }

  const pathBody = cssFunctionBody(normalized, "path");
  if (pathBody !== null) {
    const pathData =
      pathBody.match(/(['"])(.*?)\1/)?.[2] ?? pathBody.replace(/^evenodd\s*,/i, "");
    return boundsFromPoints(svgPathDataToPoints(pathData));
  }

  return null;
}

function ancestorClipStyleSuppressesField(
  element: HTMLElement,
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  if (current === element) {
    return false;
  }
  const fieldBounds = elementRectRelativeToAncestor(element, current);
  if (fieldBounds === null) {
    return false;
  }
  const clipPath = cssPropertyValue(style, current, "clip-path");
  const clip = cssPropertyValue(style, current, "clip");
  const clipBounds = [
    isMeaningfulCssValue(clipPath) ? clipPathVisibleBounds(current, clipPath, units) : null,
    isMeaningfulCssValue(clip)
      ? legacyClipVisibleBounds(clip, units, current.getBoundingClientRect())
      : null
  ];
  return clipBounds.some(
    (bounds): bounds is RectBounds =>
      bounds !== null && boundsOverlapSuppressesField(bounds, fieldBounds)
  );
}

function ancestorMaskStyleSuppressesField(
  element: HTMLElement,
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  if (current === element) {
    return false;
  }
  const fieldBounds = elementRectRelativeToAncestor(element, current);
  if (fieldBounds === null) {
    return false;
  }
  if (sampledMaskStyleSuppressesField(style, current, fieldBounds, units)) {
    return true;
  }
  const maskBounds = maskStyleVisibleBounds(style, current, units);
  return maskBounds !== null && boundsOverlapSuppressesField(maskBounds, fieldBounds);
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

function cssFunctionBody(value: string, functionName: string) {
  const normalized = value.trim().toLowerCase();
  const prefix = `${functionName}(`;
  const functionStart = normalized.indexOf(prefix);
  if (functionStart < 0) {
    return null;
  }

  let depth = 1;
  let quote: string | null = null;
  const bodyStart = functionStart + prefix.length;
  for (let index = bodyStart; index < value.length; index += 1) {
    const char = value[index];
    if (quote !== null) {
      if (char === quote && value[index - 1] !== "\\") {
        quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "(") {
      depth += 1;
      continue;
    }
    if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        return value.slice(bodyStart, index);
      }
    }
  }
  return null;
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

function rectBoundsSuppressField(
  bounds: { left: number; top: number; right: number; bottom: number },
  rect: DOMRect
) {
  if (bounds.right <= bounds.left || bounds.bottom <= bounds.top) {
    return true;
  }
  return pointRegionSuppressesField(
    [
      { x: bounds.left, y: bounds.top },
      { x: bounds.right, y: bounds.top },
      { x: bounds.right, y: bounds.bottom },
      { x: bounds.left, y: bounds.bottom }
    ],
    rect,
    true
  );
}

function insetBoxSuppressesField(
  inset: { top: string; right: string; bottom: string; left: string },
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const top = cssLengthToPx(inset.top, rect.height, units);
  const right = cssLengthToPx(inset.right, rect.width, units);
  const bottom = cssLengthToPx(inset.bottom, rect.height, units);
  const left = cssLengthToPx(inset.left, rect.width, units);
  if (top !== null && right !== null && bottom !== null && left !== null) {
    return rectBoundsSuppressField(
      {
        left,
        top,
        right: rect.width - right,
        bottom: rect.height - bottom
      },
      rect
    );
  }
  return (
    insetPairSuppressesField(inset.left, inset.right, rect.width, units) ||
    insetPairSuppressesField(inset.top, inset.bottom, rect.height, units)
  );
}

function insetBoxTokens(value: string) {
  const tokens = splitCssFunctionArgs(value);
  const roundIndex = tokens.findIndex((token) => token.toLowerCase() === "round");
  return roundIndex < 0 ? tokens : tokens.slice(0, roundIndex);
}

type SvgClipCoordinateSpace = "userSpaceOnUse" | "objectBoundingBox";

function svgNormalizedLength(
  value: string | null,
  units: { emPx?: number; remPx?: number }
) {
  if (value === null) {
    return 0;
  }
  const normalized = value.trim().toLowerCase();
  const percent = cssInsetPercent(normalized);
  if (percent !== null) {
    return percent / 100;
  }
  return numericCssValue(normalized, units) ?? 0;
}

function svgLengthToPx(
  value: string | null,
  axisSize: number,
  units: { emPx?: number; remPx?: number },
  coordinateSpace: SvgClipCoordinateSpace = "userSpaceOnUse"
) {
  if (value === null) {
    return 0;
  }
  if (coordinateSpace === "objectBoundingBox") {
    return svgNormalizedLength(value, units);
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
  for (const transform of normalized.matchAll(/(matrix|translate|scale|rotate)\(([^)]*)\)/g)) {
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
    } else if (name === "rotate") {
      const angle = svgTransformArg(args[0], units);
      if (angle !== null) {
        const radians = (angle * Math.PI) / 180;
        const cos = Math.cos(radians);
        const sin = Math.sin(radians);
        const cx = args[1] === undefined ? 0 : svgTransformArg(args[1], units);
        const cy = args[2] === undefined ? 0 : svgTransformArg(args[2], units);
        if (cx !== null && cy !== null) {
          next = {
            a: cos,
            b: sin,
            c: -sin,
            d: cos,
            e: cx - cos * cx + sin * cy,
            f: cy - sin * cx - cos * cy
          };
        }
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
  units: { emPx?: number; remPx?: number },
  coordinateSpace: SvgClipCoordinateSpace
) {
  const x = svgLengthToPx(shape.getAttribute("x"), rect.width, units, coordinateSpace);
  const y = svgLengthToPx(shape.getAttribute("y"), rect.height, units, coordinateSpace);
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
  units: { emPx?: number; remPx?: number },
  coordinateSpace: SvgClipCoordinateSpace = "userSpaceOnUse"
) {
  const tokens = value.trim().split(/[\s,]+/).filter(Boolean);
  const points: Array<{ x: number; y: number }> = [];
  for (let index = 0; index + 1 < tokens.length; index += 2) {
    points.push({
      x: svgLengthToPx(tokens[index], rect.width, units, coordinateSpace),
      y: svgLengthToPx(tokens[index + 1], rect.height, units, coordinateSpace)
    });
  }
  return points;
}

function numericSvgPathPoints(value: string) {
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

function svgPathTokens(value: string) {
  return value.match(/[a-zA-Z]|[-+]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?/gi) ?? [];
}

function isSvgPathCommand(token: string | undefined) {
  return token !== undefined && /^[a-zA-Z]$/.test(token);
}

function svgPathDataToPoints(value: string) {
  const tokens = svgPathTokens(value);
  const points: Array<{ x: number; y: number }> = [];
  let index = 0;
  let command = "";
  let current = { x: 0, y: 0 };
  let subpathStart = { x: 0, y: 0 };

  const hasNumber = () => index < tokens.length && !isSvgPathCommand(tokens[index]);
  const readNumber = () => {
    if (!hasNumber()) {
      return null;
    }
    const parsed = Number(tokens[index]);
    index += 1;
    return Number.isFinite(parsed) ? parsed : null;
  };
  const pushPoint = (point: { x: number; y: number }) => {
    current = point;
    points.push({ ...point });
  };
  const readPoint = (relative: boolean) => {
    const x = readNumber();
    const y = readNumber();
    if (x === null || y === null) {
      return null;
    }
    return relative ? { x: current.x + x, y: current.y + y } : { x, y };
  };
  const readControlPoint = (relative: boolean) => {
    const point = readPoint(relative);
    if (point === null) {
      return null;
    }
    points.push({ ...point });
    return point;
  };

  while (index < tokens.length) {
    if (isSvgPathCommand(tokens[index])) {
      command = tokens[index];
      index += 1;
    }
    if (!command) {
      return numericSvgPathPoints(value);
    }

    const relative = command === command.toLowerCase();
    switch (command.toLowerCase()) {
      case "m": {
        const first = readPoint(relative);
        if (first === null) {
          return numericSvgPathPoints(value);
        }
        pushPoint(first);
        subpathStart = first;
        command = relative ? "l" : "L";
        while (hasNumber()) {
          const point = readPoint(relative);
          if (point === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint(point);
        }
        break;
      }
      case "l":
        while (hasNumber()) {
          const point = readPoint(relative);
          if (point === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint(point);
        }
        break;
      case "h":
        while (hasNumber()) {
          const x = readNumber();
          if (x === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint({ x: relative ? current.x + x : x, y: current.y });
        }
        break;
      case "v":
        while (hasNumber()) {
          const y = readNumber();
          if (y === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint({ x: current.x, y: relative ? current.y + y : y });
        }
        break;
      case "c":
        while (hasNumber()) {
          const first = readControlPoint(relative);
          const second = readControlPoint(relative);
          const end = readPoint(relative);
          if (first === null || second === null || end === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint(end);
        }
        break;
      case "s":
      case "q":
        while (hasNumber()) {
          const control = readControlPoint(relative);
          const end = readPoint(relative);
          if (control === null || end === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint(end);
        }
        break;
      case "t":
        while (hasNumber()) {
          const end = readPoint(relative);
          if (end === null) {
            return numericSvgPathPoints(value);
          }
          pushPoint(end);
        }
        break;
      case "a":
        while (hasNumber()) {
          const radiusX = readNumber();
          const radiusY = readNumber();
          const rotation = readNumber();
          const largeArc = readNumber();
          const sweep = readNumber();
          const x = readNumber();
          const y = readNumber();
          if (
            radiusX === null ||
            radiusY === null ||
            rotation === null ||
            largeArc === null ||
            sweep === null ||
            x === null ||
            y === null
          ) {
            return numericSvgPathPoints(value);
          }
          points.push({
            x: relative ? current.x + radiusX : radiusX,
            y: relative ? current.y + radiusY : radiusY
          });
          pushPoint({ x: relative ? current.x + x : x, y: relative ? current.y + y : y });
        }
        break;
      case "z":
        pushPoint(subpathStart);
        command = "";
        break;
      default:
        return numericSvgPathPoints(value);
    }
  }

  return points;
}

function svgPathDataToSubpathPoints(value: string) {
  const subpaths = value.match(/[Mm][^Mm]*/g) ?? [value];
  return subpaths.map(svgPathDataToPoints).filter((points) => points.length > 0);
}

function pointOnSegment(
  point: { x: number; y: number },
  start: { x: number; y: number },
  end: { x: number; y: number }
) {
  const cross =
    (point.y - start.y) * (end.x - start.x) - (point.x - start.x) * (end.y - start.y);
  if (Math.abs(cross) > 1e-6) {
    return false;
  }
  const dot =
    (point.x - start.x) * (end.x - start.x) + (point.y - start.y) * (end.y - start.y);
  if (dot < 0) {
    return false;
  }
  const squaredLength = (end.x - start.x) ** 2 + (end.y - start.y) ** 2;
  return dot <= squaredLength + 1e-6;
}

function pointInsidePolygon(point: { x: number; y: number }, polygon: Array<{ x: number; y: number }>) {
  let inside = false;
  for (let index = 0, previous = polygon.length - 1; index < polygon.length; previous = index++) {
    const start = polygon[previous];
    const end = polygon[index];
    if (pointOnSegment(point, start, end)) {
      return true;
    }
    if (
      start.y > point.y !== end.y > point.y &&
      point.x < ((end.x - start.x) * (point.y - start.y)) / (end.y - start.y) + start.x
    ) {
      inside = !inside;
    }
  }
  return inside;
}

function fieldLocalSamplePoints(rect: DOMRect) {
  const bounds = fieldLocalBounds(rect);
  const insetX = Math.min(4, rect.width / 2);
  const insetY = Math.min(4, rect.height / 2);
  return [
    { x: rect.width / 2, y: rect.height / 2 },
    { x: bounds.left + insetX, y: bounds.top + insetY },
    { x: bounds.right - insetX, y: bounds.top + insetY },
    { x: bounds.left + insetX, y: bounds.bottom - insetY },
    { x: bounds.right - insetX, y: bounds.bottom - insetY }
  ];
}

function evenOddSubpathsSuppressField(
  value: string,
  rect: DOMRect,
  matrix: SvgMatrix2d = identitySvgMatrix()
) {
  if (!hasMeaningfulClientRect(rect)) {
    return false;
  }
  const polygons = svgPathDataToSubpathPoints(value)
    .map((points) => transformSvgPoints(points, matrix))
    .filter((points) => points.length >= 3);
  if (polygons.length < 2) {
    return false;
  }
  return fieldLocalSamplePoints(rect).every((sample) => {
    const containingPolygons = polygons.filter((polygon) =>
      pointInsidePolygon(sample, polygon)
    ).length;
    return containingPolygons % 2 === 0;
  });
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

function cssShapeCoordinatePairToPoint(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const [x, y] = splitCssFunctionArgs(value);
  const parsedX = x === undefined ? null : cssCoordinateToPx(x, rect.width, units);
  const parsedY = y === undefined ? null : cssCoordinateToPx(y, rect.height, units);
  return parsedX === null || parsedY === null ? null : { x: parsedX, y: parsedY };
}

function cssShapeLengthToPx(
  value: string | undefined,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  return value === undefined ? null : cssCoordinateToPx(value, axisSize, units);
}

function shapeCommandPoints(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const points: Array<{ x: number; y: number }> = [];
  let current = { x: 0, y: 0 };

  for (const command of splitCssCommaList(value)) {
    const normalized = command.trim().toLowerCase();
    if (normalized === "" || normalized === "close") {
      continue;
    }

    const absolutePair = normalized.match(
      /^(?:from|move\s+to|line\s+to|smooth\s+to|curve\s+to|arc\s+to)\s+(.+?)(?:\s+with\b|$)/
    );
    if (absolutePair) {
      const point = cssShapeCoordinatePairToPoint(absolutePair[1], rect, units);
      if (point === null) {
        return [];
      }
      current = point;
      points.push(point);
      continue;
    }

    const relativePair = normalized.match(/^(?:move\s+by|line\s+by)\s+(.+)$/);
    if (relativePair) {
      const offset = cssShapeCoordinatePairToPoint(relativePair[1], rect, units);
      if (offset === null) {
        return [];
      }
      current = { x: current.x + offset.x, y: current.y + offset.y };
      points.push(current);
      continue;
    }

    const horizontal = normalized.match(/^hline\s+(to|by)\s+(.+)$/);
    if (horizontal) {
      const x = cssShapeLengthToPx(horizontal[2], rect.width, units);
      if (x === null) {
        return [];
      }
      current = {
        x: horizontal[1] === "by" ? current.x + x : x,
        y: current.y
      };
      points.push(current);
      continue;
    }

    const vertical = normalized.match(/^vline\s+(to|by)\s+(.+)$/);
    if (vertical) {
      const y = cssShapeLengthToPx(vertical[2], rect.height, units);
      if (y === null) {
        return [];
      }
      current = {
        x: current.x,
        y: vertical[1] === "by" ? current.y + y : y
      };
      points.push(current);
      continue;
    }

    return [];
  }

  return points;
}

function shapeClipSuppressesField(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const points = shapeCommandPoints(value, rect, units);
  return points.length > 0 && pointRegionSuppressesField(points, rect, true);
}

function svgClipElementIsNonRendering(tagName: string) {
  return [
    "defs",
    "desc",
    "metadata",
    "title",
    "style",
    "script",
    "symbol",
    "marker",
    "pattern",
    "lineargradient",
    "radialgradient",
    "filter",
    "mask",
    "clippath"
  ].includes(tagName);
}

function svgClipElementIsContainer(tagName: string) {
  return tagName === "g" || tagName === "svg" || tagName === "a" || tagName === "switch";
}

function svgElementClipPathValues(shape: Element, style: CSSStyleDeclaration | undefined) {
  const inlineStyle = (shape as SVGElement).style;
  return [
    shape.getAttribute("clip-path") ?? "",
    inlineStyle?.getPropertyValue("clip-path") ?? "",
    style?.getPropertyValue("clip-path") ?? ""
  ].filter(isMeaningfulCssValue);
}

function svgClipShapeSuppressesField(
  current: HTMLElement,
  shape: Element,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set(),
  inheritedMatrix: SvgMatrix2d = identitySvgMatrix(),
  coordinateSpace: SvgClipCoordinateSpace = "userSpaceOnUse"
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
  if (svgClipElementIsNonRendering(tagName)) {
    return true;
  }
  if (
    svgElementClipPathValues(shape, shapeStyle).some((clipPath) =>
      svgClipPathFullyClips(current, clipPath, units, seen)
    )
  ) {
    return true;
  }
  if (tagName === "use") {
    const href =
      shape.getAttribute("href") ??
      shape.getAttribute("xlink:href") ??
      shape.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    const targetId = href?.startsWith("#") ? href.slice(1) : null;
    const target = targetId ? current.ownerDocument.getElementById(targetId) : null;
    const useMatrix = svgMatrixMultiply(
      matrix,
      svgUsePositionMatrix(shape, rect, units, coordinateSpace)
    );
    return (
      target === null ||
      svgClipShapeSuppressesField(current, target, units, seen, useMatrix, coordinateSpace)
    );
  }
  if (tagName === "rect") {
    const x = svgLengthToPx(shape.getAttribute("x"), rect.width, units, coordinateSpace);
    const y = svgLengthToPx(shape.getAttribute("y"), rect.height, units, coordinateSpace);
    const width = svgLengthToPx(
      shape.getAttribute("width"),
      rect.width,
      units,
      coordinateSpace
    );
    const height = svgLengthToPx(
      shape.getAttribute("height"),
      rect.height,
      units,
      coordinateSpace
    );
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
    const radius = svgLengthToPx(
      shape.getAttribute("r"),
      Math.min(rect.width, rect.height),
      units,
      coordinateSpace
    );
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units, coordinateSpace);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units, coordinateSpace);
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
    const radiusX = svgLengthToPx(
      shape.getAttribute("rx"),
      rect.width,
      units,
      coordinateSpace
    );
    const radiusY = svgLengthToPx(
      shape.getAttribute("ry"),
      rect.height,
      units,
      coordinateSpace
    );
    const cx = svgLengthToPx(shape.getAttribute("cx"), rect.width, units, coordinateSpace);
    const cy = svgLengthToPx(shape.getAttribute("cy"), rect.height, units, coordinateSpace);
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
            x: svgLengthToPx(shape.getAttribute("x1"), rect.width, units, coordinateSpace),
            y: svgLengthToPx(shape.getAttribute("y1"), rect.height, units, coordinateSpace)
          },
          {
            x: svgLengthToPx(shape.getAttribute("x2"), rect.width, units, coordinateSpace),
            y: svgLengthToPx(shape.getAttribute("y2"), rect.height, units, coordinateSpace)
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
    const points = svgPointListToPoints(
      shape.getAttribute("points") ?? "",
      rect,
      units,
      coordinateSpace
    );
    return pointRegionSuppressesField(
      transformSvgPoints(points, matrix),
      rect,
      tagName === "polygon"
    );
  }
  if (tagName === "path") {
    const pathData = shape.getAttribute("d") ?? "";
    if (svgPathUsesEvenOdd(shape) && evenOddSubpathsSuppressField(pathData, rect, matrix)) {
      return true;
    }
    const points = svgPathDataToPoints(pathData);
    return pathRegionSuppressesField(transformSvgPoints(points, matrix), rect);
  }
  if (svgClipElementIsContainer(tagName)) {
    const children = Array.from(shape.children);
    return children.length === 0 || children.every((child) =>
      svgClipShapeSuppressesField(current, child, units, seen, matrix, coordinateSpace)
    );
  }
  return false;
}

function svgClipPathFullyClips(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number },
  seen: Set<Element> = new Set()
) {
  const [id] = localCssUrlReferenceIds(value);
  if (!id) {
    return false;
  }
  const clipPath = current.ownerDocument.getElementById(id);
  if (!clipPath) {
    return false;
  }
  if (seen.has(clipPath)) {
    return true;
  }
  seen.add(clipPath);
  const shapes = Array.from(clipPath.children);
  const rect = current.getBoundingClientRect();
  const coordinateSpace =
    clipPath.getAttribute("clipPathUnits")?.trim() === "objectBoundingBox"
      ? "objectBoundingBox"
      : "userSpaceOnUse";
  const baseMatrix =
    coordinateSpace === "objectBoundingBox"
      ? { a: rect.width, b: 0, c: 0, d: rect.height, e: 0, f: 0 }
      : identitySvgMatrix();
  const clipPathMatrix = svgElementTransformMatrix(clipPath, baseMatrix, units);
  return (
    shapes.length === 0 ||
    shapes.every((shape) =>
      svgClipShapeSuppressesField(
        current,
        shape,
        units,
        seen,
        clipPathMatrix,
        coordinateSpace
      )
    )
  );
}

function cssPositionTokenToPx(
  token: string | undefined,
  axis: "x" | "y",
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = token?.trim().toLowerCase();
  if (!normalized || normalized === "center") {
    return axisSize / 2;
  }
  if (axis === "x") {
    if (normalized === "left") {
      return 0;
    }
    if (normalized === "right") {
      return axisSize;
    }
  } else {
    if (normalized === "top") {
      return 0;
    }
    if (normalized === "bottom") {
      return axisSize;
    }
  }
  return cssLengthToPx(normalized, axisSize, units);
}

function cssPositionComponentToPx(
  value: string,
  axis: "x" | "y",
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const [origin, offsetToken = "0"] = splitCssFunctionArgs(value.trim().toLowerCase());
  const start = axis === "x" ? "left" : "top";
  const end = axis === "x" ? "right" : "bottom";
  if (origin === start) {
    return cssLengthToPx(offsetToken, axisSize, units) ?? 0;
  }
  if (origin === end) {
    return axisSize - (cssLengthToPx(offsetToken, axisSize, units) ?? 0);
  }
  if (origin === "center") {
    return axisSize / 2 + (cssLengthToPx(offsetToken, axisSize, units) ?? 0);
  }
  return cssPositionTokenToPx(value, axis, axisSize, units);
}

function basicShapePositionToPx(
  tokens: string[],
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  return basicPositionToPx(tokens, rect.width, rect.height, units);
}

function basicPositionToPx(
  tokens: string[],
  width: number,
  height: number,
  units: { emPx?: number; remPx?: number }
) {
  const value = tokens.join(" ");
  const x =
    tokens.length === 0
      ? width / 2
      : cssPositionComponentToPx(
          maskPositionAxisComponent(value, "x"),
          "x",
          width,
          units
        );
  const y =
    tokens.length === 0
      ? height / 2
      : cssPositionComponentToPx(
          maskPositionAxisComponent(value, "y"),
          "y",
          height,
          units
        );
  return x === null || y === null ? null : { x, y };
}

function distanceToBoxSides(point: { x: number; y: number }, rect: DOMRect) {
  return {
    left: Math.abs(point.x),
    right: Math.abs(rect.width - point.x),
    top: Math.abs(point.y),
    bottom: Math.abs(rect.height - point.y)
  };
}

function circleRadiusToPx(
  value: string,
  center: { x: number; y: number },
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value.trim().toLowerCase();
  const distances = distanceToBoxSides(center, rect);
  if (normalized === "closest-side") {
    return Math.min(distances.left, distances.right, distances.top, distances.bottom);
  }
  if (normalized === "farthest-side") {
    return Math.max(distances.left, distances.right, distances.top, distances.bottom);
  }
  return cssLengthToPx(normalized, Math.min(rect.width, rect.height), units);
}

function ellipseRadiusToPx(
  value: string,
  axis: "x" | "y",
  center: { x: number; y: number },
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value.trim().toLowerCase();
  const distances = distanceToBoxSides(center, rect);
  if (normalized === "closest-side") {
    return axis === "x"
      ? Math.min(distances.left, distances.right)
      : Math.min(distances.top, distances.bottom);
  }
  if (normalized === "farthest-side") {
    return axis === "x"
      ? Math.max(distances.left, distances.right)
      : Math.max(distances.top, distances.bottom);
  }
  return cssLengthToPx(normalized, axis === "x" ? rect.width : rect.height, units);
}

function circleClipSuppressesField(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const tokens = splitCssFunctionArgs(value);
  const atIndex = tokens.findIndex((token) => token.toLowerCase() === "at");
  const radius = atIndex === 0 ? "closest-side" : tokens[0] ?? "closest-side";
  const center = basicShapePositionToPx(atIndex < 0 ? [] : tokens.slice(atIndex + 1), rect, units);
  if (center === null) {
    return false;
  }
  const radiusPx = circleRadiusToPx(radius, center, rect, units);
  if (radiusPx === null || center === null) {
    return false;
  }
  return rectBoundsSuppressField(
    {
      left: center.x - radiusPx,
      top: center.y - radiusPx,
      right: center.x + radiusPx,
      bottom: center.y + radiusPx
    },
    rect
  );
}

function ellipseClipSuppressesField(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const tokens = splitCssFunctionArgs(value);
  const atIndex = tokens.findIndex((token) => token.toLowerCase() === "at");
  const radiusTokens = atIndex < 0 ? tokens : tokens.slice(0, atIndex);
  const radiusX = radiusTokens[0] ?? "closest-side";
  const radiusY = radiusTokens[1] ?? radiusX;
  const center = basicShapePositionToPx(atIndex < 0 ? [] : tokens.slice(atIndex + 1), rect, units);
  if (center === null) {
    return false;
  }
  const radiusXPx = ellipseRadiusToPx(radiusX, "x", center, rect, units);
  const radiusYPx = ellipseRadiusToPx(radiusY, "y", center, rect, units);
  if (radiusXPx === null || radiusYPx === null) {
    return false;
  }
  return rectBoundsSuppressField(
    {
      left: center.x - radiusXPx,
      top: center.y - radiusYPx,
      right: center.x + radiusXPx,
      bottom: center.y + radiusYPx
    },
    rect
  );
}

function xywhClipSuppressesField(
  value: string,
  rect: DOMRect,
  units: { emPx?: number; remPx?: number }
) {
  const [x, y, width, height] = splitCssFunctionArgs(value);
  const widthPx = width === undefined ? null : cssLengthToPx(width, rect.width, units);
  const heightPx = height === undefined ? null : cssLengthToPx(height, rect.height, units);
  if (
    (widthPx !== null && widthPx <= MIN_CREDENTIAL_FIELD_SIZE_PX) ||
    (heightPx !== null && heightPx <= MIN_CREDENTIAL_FIELD_SIZE_PX)
  ) {
    return true;
  }

  const xPx = x === undefined ? null : cssLengthToPx(x, rect.width, units);
  const yPx = y === undefined ? null : cssLengthToPx(y, rect.height, units);
  if (xPx === null || yPx === null || widthPx === null || heightPx === null) {
    return false;
  }
  return rectBoundsSuppressField(
    {
      left: xPx,
      top: yPx,
      right: xPx + widthPx,
      bottom: yPx + heightPx
    },
    rect
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
  const insetBody = cssFunctionBody(normalized, "inset");
  if (insetBody !== null) {
    const inset = expandBoxValues(insetBoxTokens(insetBody));
    const rect = current.getBoundingClientRect();
    return insetBoxSuppressesField(inset, rect, units);
  }

  const circleBody = cssFunctionBody(normalized, "circle");
  if (circleBody !== null) {
    return circleClipSuppressesField(circleBody, current.getBoundingClientRect(), units);
  }

  const ellipseBody = cssFunctionBody(normalized, "ellipse");
  if (ellipseBody !== null) {
    return ellipseClipSuppressesField(ellipseBody, current.getBoundingClientRect(), units);
  }

  const rectBody = cssFunctionBody(normalized, "rect");
  if (rectBody !== null) {
    return legacyClipFullyClips(`rect(${rectBody})`, units, current.getBoundingClientRect());
  }

  const xywhBody = cssFunctionBody(normalized, "xywh");
  if (xywhBody !== null) {
    return xywhClipSuppressesField(xywhBody, current.getBoundingClientRect(), units);
  }

  const polygonBody = cssFunctionBody(normalized, "polygon");
  if (polygonBody !== null) {
    const rect = current.getBoundingClientRect();
    const points = splitCssCommaList(polygonBody).flatMap((point) => {
      const [x, y] = splitCssFunctionArgs(point);
      const parsedX = x === undefined ? null : cssCoordinateToPx(x, rect.width, units);
      const parsedY = y === undefined ? null : cssCoordinateToPx(y, rect.height, units);
      return parsedX === null || parsedY === null ? [] : [{ x: parsedX, y: parsedY }];
    });
    return pointRegionSuppressesField(points, rect, true);
  }

  const shapeBody = cssFunctionBody(normalized, "shape");
  if (shapeBody !== null) {
    return shapeClipSuppressesField(shapeBody, current.getBoundingClientRect(), units);
  }

  const pathBody = cssFunctionBody(normalized, "path");
  if (pathBody !== null) {
    const fillRule = pathBody.match(/^\s*(evenodd|nonzero)\s*,/i)?.[1].toLowerCase();
    const pathData =
      pathBody.match(/(['"])(.*?)\1/)?.[2] ?? pathBody.replace(/^evenodd\s*,/i, "");
    if (
      fillRule === "evenodd" &&
      evenOddSubpathsSuppressField(pathData, current.getBoundingClientRect())
    ) {
      return true;
    }
    return pathRegionSuppressesField(
      svgPathDataToPoints(pathData),
      current.getBoundingClientRect()
    );
  }

  return false;
}

function legacyClipFullyClips(
  value: string,
  units: { emPx?: number; remPx?: number },
  fieldRect?: DOMRect
) {
  const match = value.trim().toLowerCase().match(/^rect\((.*)\)$/);
  if (!match) {
    return false;
  }
  const rect = expandBoxValues(splitCssFunctionArgs(match[1]));
  const top = fieldRect
    ? cssLengthToPx(rect.top, fieldRect.height, units)
    : numericCssValue(rect.top, units);
  const right = fieldRect
    ? cssLengthToPx(rect.right, fieldRect.width, units)
    : numericCssValue(rect.right, units);
  const bottom = fieldRect
    ? cssLengthToPx(rect.bottom, fieldRect.height, units)
    : numericCssValue(rect.bottom, units);
  const left = fieldRect
    ? cssLengthToPx(rect.left, fieldRect.width, units)
    : numericCssValue(rect.left, units);
  if (top === null || right === null || bottom === null || left === null) {
    return false;
  }
  if (fieldRect) {
    return rectBoundsSuppressField({ left, top, right, bottom }, fieldRect);
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
    (isMeaningfulCssValue(clip) &&
      legacyClipFullyClips(clip, units, current.getBoundingClientRect()))
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
    const opacity = cssOpacityValue(cssPropertyValue(style, current, "opacity"));
    const filter = cssPropertyValue(style, current, "filter");
    const filterOpacity = paintFilterOpacityValue(current, filter);
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
      isEffectivelyTransparent(cumulativeOpacity * cumulativeFilterOpacity) ||
      svgFilterSuppressesPaint(current, filter, cssUnits, element) ||
      maskStyleSuppressesPaint(style, current, cssUnits) ||
      ancestorMaskStyleSuppressesField(element, current, style, cssUnits) ||
      (current === element &&
        isCredentialLikeField(element) &&
        (fieldChromePaintIsTransparent(style, current, cssUnits) ||
          fieldChromePaintBlendsIntoBackground(style, current, cssUnits)))
    ) {
      addReason(reasons, "not-viewable:transparent");
    }
    if (
      hasFullyClippingStyle(current, style, cssUnits) ||
      ancestorClipStyleSuppressesField(element, current, style, cssUnits)
    ) {
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
        (clipsDescendantPaint(current, style) &&
          (isFullyClippedByAncestor(element, current) ||
            clippedAncestorVisibleOverlapSuppressesField(element, current))))
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
