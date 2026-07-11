import { getBasicRenderFacts } from "./renderFacts";

export interface FieldVisibilityResult {
  vw: boolean;
  why: string[];
}

export interface FieldFillabilityResult {
  fl: boolean;
  why: string[];
}

export function getFieldVisibility(element: HTMLElement): FieldVisibilityResult {
  const facts = getBasicRenderFacts(element);
  return { vw: facts.vw, why: facts.why };
}

export function getFieldFillability(element: HTMLElement): FieldFillabilityResult {
  const facts = getBasicRenderFacts(element);
  return { fl: facts.fl, why: facts.fr };
}
