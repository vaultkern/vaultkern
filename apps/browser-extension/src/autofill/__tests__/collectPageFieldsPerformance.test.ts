import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  collectAutofillPageSnapshot,
  FIELD_SELECTOR
} from "../collectPageFields";
import type { AutofillFieldSnapshot } from "../types";
import { useDomRenderEnvironment } from "./renderEnvironment";

useDomRenderEnvironment();

const HEADING_SELECTOR = "h1, h2, h3, h4, h5, h6";
const HEADING_FORM_SELECTOR = `form, ${HEADING_SELECTOR}`;
const SEMANTIC_SCOPE_SELECTOR = "fieldset,section,article,main,aside";

function fieldByName(
  fields: AutofillFieldSnapshot[],
  name: string
) {
  const field = fields.find((candidate) => candidate.hn === name);
  expect(field, `expected field named ${name}`).toBeDefined();
  return field!;
}

function instrumentSubtreeQueries() {
  const counts = { field: 0, heading: 0 };
  const countSelector = (selector: string) => {
    if (selector === FIELD_SELECTOR) {
      counts.field += 1;
    } else if (selector === HEADING_SELECTOR) {
      counts.heading += 1;
    }
  };
  const elementQuerySelectorAll = Element.prototype.querySelectorAll;
  vi.spyOn(Element.prototype, "querySelectorAll").mockImplementation(
    function (this: Element, selector: string) {
      countSelector(selector);
      return elementQuerySelectorAll.call(this, selector);
    } as typeof Element.prototype.querySelectorAll
  );
  const shadowQuerySelectorAll = ShadowRoot.prototype.querySelectorAll;
  vi.spyOn(ShadowRoot.prototype, "querySelectorAll").mockImplementation(
    function (this: ShadowRoot, selector: string) {
      countSelector(selector);
      return shadowQuerySelectorAll.call(this, selector);
    } as typeof ShadowRoot.prototype.querySelectorAll
  );
  return counts;
}

function instrumentFieldSelectorMatches() {
  const count = { value: 0 };
  const matches = Element.prototype.matches;
  vi.spyOn(Element.prototype, "matches").mockImplementation(function (
    this: Element,
    selector: string
  ) {
    if (selector === FIELD_SELECTOR) {
      count.value += 1;
    }
    return matches.call(this, selector);
  });
  return count;
}

function instrumentFormControlSelectorMatches() {
  const count = { value: 0 };
  const matches = Element.prototype.matches;
  vi.spyOn(Element.prototype, "matches").mockImplementation(function (
    this: Element,
    selector: string
  ) {
    if (selector === "button, input") {
      count.value += 1;
    }
    return matches.call(this, selector);
  });
  return count;
}

function instrumentHeadingScopeWork(scope: Element) {
  const counts = { queries: 0, headingVisits: 0 };
  const querySelectorAll = Element.prototype.querySelectorAll;
  vi.spyOn(Element.prototype, "querySelectorAll").mockImplementation(
    function (this: Element, selector: string) {
      if (
        this === scope &&
        (selector === HEADING_SELECTOR ||
          selector === "form" ||
          selector === HEADING_FORM_SELECTOR)
      ) {
        counts.queries += 1;
      }
      return querySelectorAll.call(this, selector);
    } as typeof Element.prototype.querySelectorAll
  );
  const closest = Element.prototype.closest;
  vi.spyOn(Element.prototype, "closest").mockImplementation(
    function (this: Element, selector: string) {
      if (selector === "form" && /^H[1-6]$/.test(this.tagName)) {
        counts.headingVisits += 1;
      }
      return closest.call(this, selector);
    } as typeof Element.prototype.closest
  );
  return counts;
}

function instrumentNestedHeadingWork() {
  const counts = { formCandidates: 0, containerCandidates: 0 };
  const querySelectorAll = Element.prototype.querySelectorAll;
  vi.spyOn(Element.prototype, "querySelectorAll").mockImplementation(
    function (this: Element, selector: string) {
      const result = querySelectorAll.call(this, selector);
      if (selector === HEADING_FORM_SELECTOR) {
        counts.formCandidates += result.length;
      } else if (selector === HEADING_SELECTOR) {
        counts.containerCandidates += result.length;
      }
      return result;
    } as typeof Element.prototype.querySelectorAll
  );
  return counts;
}

function instrumentSharedLabelWork(source: Element) {
  const counts = { sourceClones: 0, detachedFieldMatches: 0 };
  const cloneNode = Element.prototype.cloneNode;
  vi.spyOn(Element.prototype, "cloneNode").mockImplementation(function (
    this: Element,
    deep?: boolean
  ) {
    if (this === source) {
      counts.sourceClones += 1;
    }
    return cloneNode.call(this, deep);
  });
  const matches = Element.prototype.matches;
  vi.spyOn(Element.prototype, "matches").mockImplementation(function (
    this: Element,
    selector: string
  ) {
    if (selector === FIELD_SELECTOR && !this.isConnected) {
      counts.detachedFieldMatches += 1;
    }
    return matches.call(this, selector);
  } as typeof Element.prototype.matches);
  return counts;
}

function instrumentLargeTextCleaning(minimumLength: number) {
  const count = { value: 0 };
  const replace = String.prototype.replace;
  vi.spyOn(String.prototype, "replace").mockImplementation(function (
    this: string,
    searchValue: string | RegExp,
    replaceValue: string | ((substring: string, ...args: unknown[]) => string)
  ) {
    if (this.length >= minimumLength) {
      count.value += 1;
    }
    return Reflect.apply(replace, this, [searchValue, replaceValue]);
  } as typeof String.prototype.replace);
  return count;
}

function appendDeepFieldChain(parent: Element, depth: number, prefix: string) {
  for (let index = 0; index < depth; index += 1) {
    const wrapper = document.createElement("div");
    const field = document.createElement("input");
    field.name = `${prefix}_${index}`;
    wrapper.append(field);
    parent.append(wrapper);
    parent = wrapper;
  }
}

function instrumentAncestorWork() {
  const counts = { numericDomMapSets: 0, semanticMatches: 0 };
  const mapSet = Map.prototype.set;
  Map.prototype.set = function (
    this: Map<unknown, unknown>,
    key: unknown,
    value: unknown
  ) {
    if (key instanceof Node && typeof value === "number") {
      counts.numericDomMapSets += 1;
    }
    return mapSet.call(this, key, value);
  };
  const matches = Element.prototype.matches;
  Element.prototype.matches = (function (
    this: Element,
    selector: string
  ) {
    if (selector === SEMANTIC_SCOPE_SELECTOR) {
      counts.semanticMatches += 1;
    }
    return matches.call(this, selector);
  }) as typeof Element.prototype.matches;
  return {
    counts,
    restore() {
      Map.prototype.set = mapSet;
      Element.prototype.matches = matches;
    }
  };
}

function stubComputedStyle() {
  vi.spyOn(window, "getComputedStyle").mockReturnValue({
    contentVisibility: "visible",
    display: "block",
    filter: "none",
    getPropertyValue: () => "",
    maskImage: "none",
    opacity: "1",
    pointerEvents: "auto",
    visibility: "visible"
  } as unknown as CSSStyleDeclaration);
}

describe("snapshot collection performance", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not rescan a shared wrapper for each of one thousand fields", () => {
    const fields = Array.from(
      { length: 1_000 },
      (_, index) => `<input name="field_${index}" />`
    ).join("");
    document.body.innerHTML = `
      <main id="shared" aria-label="Shared login">
        <h2>Sign in</h2>
        ${fields}
      </main>
    `;
    const queries = instrumentSubtreeQueries();

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.f).toHaveLength(1_000);
    expect(queries.field).toBe(0);
    expect(queries.heading).toBe(0);
    expect(new Set(snapshot.f.map((field) => field.co)).size).toBe(1);
    expect(new Set(snapshot.f.map((field) => field.so)).size).toBe(1);
    expect(snapshot.f[0].ct).toEqual(["shared", "Shared login", "Sign in"]);
    expect(snapshot.f[1].ct).toEqual(snapshot.f[0].ct);
    expect(snapshot.f[1].ct).not.toBe(snapshot.f[0].ct);
  });

  it("shares composed-ancestor render work across fields and form controls", () => {
    const depth = 200;
    const fieldCount = 128;
    let parent = document.body;
    for (let index = 0; index < depth; index += 1) {
      const wrapper = document.createElement("div");
      parent.append(wrapper);
      parent = wrapper;
    }
    const form = document.createElement("form");
    for (let index = 0; index < fieldCount; index += 1) {
      const field = document.createElement("input");
      field.name = `render_field_${index}`;
      form.append(field);
    }
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Sign in";
    form.append(submit);
    parent.append(form);

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
    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.f).toHaveLength(fieldCount);
    const physicalElements = depth + fieldCount + 4;
    expect(styleReads).toBeLessThanOrEqual(physicalElements);
  });

  it("preserves shared wrappers and semantic section scope boundaries", () => {
    document.body.innerHTML = `
      <div id="shared-wrapper">
        <section><input name="single_user" /></section>
        <section><input name="single_password" type="password" /></section>
        <section id="multi-one">
          <input name="multi_one_user" />
          <input name="multi_one_password" type="password" />
        </section>
        <section id="multi-two">
          <input name="multi_two_user" />
          <input name="multi_two_password" type="password" />
        </section>
      </div>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);
    const singleUser = fieldByName(fields, "single_user");
    const singlePassword = fieldByName(fields, "single_password");
    const multiOneUser = fieldByName(fields, "multi_one_user");
    const multiOnePassword = fieldByName(fields, "multi_one_password");
    const multiTwoUser = fieldByName(fields, "multi_two_user");

    expect(singleUser.co).toBe(singlePassword.co);
    expect(singleUser.so).toBe(singlePassword.so);
    expect(multiOneUser.co).toBe(multiOnePassword.co);
    expect(multiOneUser.so).toBe(multiOnePassword.so);
    expect(multiOneUser.co).not.toBe(multiTwoUser.co);
    expect(multiOneUser.so).not.toBe(multiTwoUser.so);
  });

  it("preserves direct body runs without merging across separators", () => {
    document.body.innerHTML = `
      <input name="outside_before" />
      <hr />
      <label for="run-user">Email</label>
      <input id="run-user" name="run_user" />
      <span>Credentials</span>
      <input name="run_password" type="password" />
      <hr />
      <input name="outside_after" />
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);
    const before = fieldByName(fields, "outside_before");
    const runUser = fieldByName(fields, "run_user");
    const runPassword = fieldByName(fields, "run_password");
    const after = fieldByName(fields, "outside_after");

    expect(runUser.co).toBeDefined();
    expect(runUser.co).toBe(runPassword.co);
    expect(runUser.so).toBe(runPassword.so);
    expect(before.co).toBeUndefined();
    expect(after.co).toBeUndefined();
    expect(before.so).toBe(after.so);
    expect(runUser.so).not.toBe(before.so);
  });

  it("precomputes long direct body and html runs in linear work", () => {
    const fieldCount = 1_000;
    document.body.innerHTML = [
      ...Array.from(
        { length: fieldCount / 2 },
        (_, index) => `<input name="body_${index}" />`
      ),
      "<hr />",
      ...Array.from(
        { length: fieldCount / 2 },
        (_, index) => `<input name="body_${index + fieldCount / 2}" />`
      )
    ].join("");
    const htmlUser = document.createElement("input");
    htmlUser.name = "html_user";
    const htmlPassword = document.createElement("input");
    htmlPassword.name = "html_password";
    htmlPassword.type = "password";
    document.documentElement.append(htmlUser, htmlPassword);
    const matches = instrumentFieldSelectorMatches();

    try {
      const { f: fields } = collectAutofillPageSnapshot(document);
      const firstBody = fieldByName(fields, "body_0");
      const firstRunLast = fieldByName(
        fields,
        `body_${fieldCount / 2 - 1}`
      );
      const secondRunFirst = fieldByName(fields, `body_${fieldCount / 2}`);
      const lastBody = fieldByName(fields, `body_${fieldCount - 1}`);
      const htmlUsername = fieldByName(fields, "html_user");
      const htmlPasswordField = fieldByName(fields, "html_password");

      expect(matches.value).toBeLessThan(fieldCount + 12);
      expect(firstBody.co).toBe(firstRunLast.co);
      expect(firstBody.so).toBe(firstRunLast.so);
      expect(secondRunFirst.co).toBe(lastBody.co);
      expect(secondRunFirst.so).toBe(lastBody.so);
      expect(firstBody.co).not.toBe(secondRunFirst.co);
      expect(htmlUsername.co).toBe(htmlPasswordField.co);
      expect(htmlUsername.so).toBe(htmlPasswordField.so);
      expect(firstBody.co).not.toBe(htmlUsername.co);
    } finally {
      htmlUser.remove();
      htmlPassword.remove();
    }
  });

  it("uses an open shadow root fallback without subtree field queries", () => {
    document.body.innerHTML = `
      <div id="light-fields">
        <input name="light_user" />
        <input name="light_password" type="password" />
      </div>
    `;
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <input name="shadow_user" />
      <input name="shadow_password" type="password" />
    `;
    const queries = instrumentSubtreeQueries();

    const { f: fields } = collectAutofillPageSnapshot(document);
    const lightUsername = fieldByName(fields, "light_user");
    const username = fieldByName(fields, "shadow_user");
    const password = fieldByName(fields, "shadow_password");

    expect(queries.field).toBe(0);
    expect(username.co).toBe(password.co);
    expect(username.so).toBe(password.so);
    expect(username.co).not.toBe(lightUsername.co);
    expect(username.so).not.toBe(lightUsername.so);
  });

  it("keeps sibling external-form fields isolated by their open shadow roots", () => {
    const hosts = [document.createElement("div"), document.createElement("div")];
    document.body.append(...hosts);
    const roots = hosts.map((host, index) => {
      const root = host.attachShadow({ mode: "open" });
      root.innerHTML = `
        <form id="owner-${index}"></form>
        <input form="owner-${index}" name="shadow_external_${index}" />
      `;
      return root;
    });

    const { f: fields } = collectAutofillPageSnapshot(document);
    const first = fieldByName(fields, "shadow_external_0");
    const second = fieldByName(fields, "shadow_external_1");

    expect(first.fo).toBeDefined();
    expect(second.fo).toBeDefined();
    expect(first.so).not.toBe(first.fo);
    expect(second.so).not.toBe(second.fo);
    expect(first.so).not.toBe(second.so);
    expect(roots).toHaveLength(2);
  });

  it("sweeps sibling form headings once per shared scope", () => {
    const formCount = 240;
    document.body.innerHTML = `
      <main id="shared-heading-scope">
        ${Array.from(
          { length: formCount },
          (_, index) => `
            <h2>Account ${index}</h2>
            <form id="heading-form-${index}">
              <input name="heading_field_${index}" />
            </form>
          `
        ).join("")}
      </main>
    `;
    const scope = document.querySelector("#shared-heading-scope")!;
    const work = instrumentHeadingScopeWork(scope);

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(formCount);
    expect(snapshot.fm[0].ht).toEqual(["Account 0"]);
    expect(snapshot.fm[formCount - 1].ht).toEqual([`Account ${formCount - 1}`]);
    expect.soft(work.queries).toBeLessThan(8);
    expect.soft(work.headingVisits).toBeLessThan(formCount * 4);
  });

  it("indexes controls for truly nested forms in one page sweep", () => {
    const depth = 80;
    let parent: Element = document.body;
    for (let index = 0; index < depth; index += 1) {
      const form = document.createElement("form");
      form.id = `nested-owner-${index}`;
      const field = document.createElement("input");
      field.name = `nested-owner-field-${index}`;
      form.append(field);
      parent.append(form);
      parent = form;
    }
    const work = instrumentFormControlSelectorMatches();

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(depth);
    expect(snapshot.f).toHaveLength(depth);
    expect.soft(work.value).toBeLessThan(depth * 4);
  });

  it("keeps the first bounded form headings", () => {
    const form = document.createElement("form");
    for (let index = 0; index < 8; index += 1) {
      const heading = document.createElement("h2");
      heading.textContent = `Noise ${index}`;
      form.append(heading);
    }
    const important = document.createElement("h2");
    important.textContent = "Important";
    const field = document.createElement("input");
    form.append(important, field);
    document.body.append(form);

    const [snapshotForm] = collectAutofillPageSnapshot(document).fm;

    expect(snapshotForm.ht).toEqual([
      "Noise 0",
      "Noise 1",
      "Noise 2",
      "Noise 3",
      "Noise 4",
      "Noise 5",
      "Noise 6",
      "Noise 7"
    ]);
  });

  it("assigns headings only to the nearest field scope", () => {
    document.body.innerHTML = `
      <section id="outer">
        <input name="outer_user" />
        <input name="outer_password" type="password" />
        <section id="inner">
          <h2>Inner</h2>
          <input name="inner_user" />
          <input name="inner_password" type="password" />
        </section>
      </section>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);

    expect(fieldByName(fields, "outer_user").ct).not.toContain("Inner");
    expect(fieldByName(fields, "inner_user").ct).toContain("Inner");
  });

  it("ignores legends that are not direct fieldset children", () => {
    document.body.innerHTML = `
      <fieldset id="credentials">
        <div><legend>Wrapped legend</legend></div>
        <input name="wrapped_user" />
        <input name="wrapped_password" type="password" />
      </fieldset>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);

    expect(fieldByName(fields, "wrapped_user").ct).not.toContain(
      "Wrapped legend"
    );
  });

  it("does not promote a nested fieldset legend into its outer fieldset", () => {
    document.body.innerHTML = `
      <fieldset id="outer-fieldset">
        <input name="outer_fieldset_user" />
        <input name="outer_fieldset_password" type="password" />
        <fieldset id="inner-fieldset">
          <legend>Inner fieldset legend</legend>
          <input name="inner_fieldset_user" />
          <input name="inner_fieldset_password" type="password" />
        </fieldset>
      </fieldset>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);

    expect(fieldByName(fields, "outer_fieldset_user").ct).not.toContain(
      "Inner fieldset legend"
    );
    expect(fieldByName(fields, "inner_fieldset_user").ct).toContain(
      "Inner fieldset legend"
    );
  });

  it("does not promote a nested fieldset legend into an outer section", () => {
    document.body.innerHTML = `
      <section id="outer-legend-scope">
        <input name="outer_legend_user" />
        <input name="outer_legend_password" type="password" />
        <fieldset>
          <legend>Inner fieldset</legend>
          <input name="inner_legend_user" />
          <input name="inner_legend_password" type="password" />
        </fieldset>
      </section>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);

    expect(fieldByName(fields, "outer_legend_user").ct).not.toContain(
      "Inner fieldset"
    );
    expect(fieldByName(fields, "inner_legend_user").ct).toContain(
      "Inner fieldset"
    );
  });

  it("bounds nested form and container heading work and output", () => {
    const depth = 200;
    const outer = document.createElement("section");
    let scope = outer;
    for (let index = 0; index < depth; index += 1) {
      scope.id = `nested-scope-${index}`;
      const heading = document.createElement("h2");
      heading.textContent = `Nested heading ${index}`;
      const form = document.createElement("form");
      form.id = `nested-form-${index}`;
      const formField = document.createElement("input");
      formField.name = `nested_form_field_${index}`;
      form.append(formField);
      const first = document.createElement("input");
      first.name = `nested_free_a_${index}`;
      const second = document.createElement("input");
      second.name = `nested_free_b_${index}`;
      scope.append(heading, form);
      if (index === 0) {
        for (let extra = 0; extra < 11; extra += 1) {
          const extraHeading = document.createElement("h3");
          extraHeading.textContent =
            `Nested heading extra ${extra} ` + "x".repeat(400);
          scope.append(extraHeading);
        }
      }
      scope.append(first, second);
      if (index + 1 < depth) {
        const childScope = document.createElement("section");
        scope.append(childScope);
        scope = childScope;
      }
    }
    document.body.append(outer);
    stubComputedStyle();
    const work = instrumentNestedHeadingWork();

    const snapshot = collectAutofillPageSnapshot(document);
    const firstForm = snapshot.fm.find((form) => form.hi === "nested-form-0");
    const lastForm = snapshot.fm.find(
      (form) => form.hi === `nested-form-${depth - 1}`
    );
    const headingCounts = snapshot.f.map(
      (field) =>
        field.ct?.filter((text) => text.startsWith("Nested heading ")).length ??
        0
    );
    const totalHeadingText = headingCounts.reduce(
      (total, count) => total + count,
      0
    );
    const headingLengths = snapshot.f.flatMap(
      (field) =>
        field.ct
          ?.filter((text) => text.startsWith("Nested heading "))
          .map((text) => text.length) ?? []
    );

    expect(firstForm?.ht).toEqual(["Nested heading 0"]);
    expect(lastForm?.ht).toEqual([`Nested heading ${depth - 1}`]);
    expect.soft(work.formCandidates).toBeLessThan(depth * 4);
    expect.soft(work.containerCandidates).toBeLessThan(depth * 4);
    expect.soft(totalHeadingText).toBeLessThan(depth * 4);
    expect.soft(Math.max(...headingCounts)).toBeLessThanOrEqual(8);
    expect.soft(Math.max(...headingLengths)).toBeLessThanOrEqual(256);
  });

  it("caps one form's owned heading output", { timeout: 30_000 }, () => {
    const headingCount = 3_000;
    const form = document.createElement("form");
    form.id = "large-heading-form";
    const fragment = document.createDocumentFragment();
    for (let index = 0; index < headingCount; index += 1) {
      const heading = document.createElement("h2");
      heading.textContent = `Owned heading ${index}`;
      fragment.append(heading);
    }
    const field = document.createElement("input");
    field.name = "large_heading_field";
    fragment.append(field);
    form.append(fragment);
    document.body.append(form);
    stubComputedStyle();

    const snapshot = collectAutofillPageSnapshot(document);
    const headingText = snapshot.fm.find(
      (candidate) => candidate.hi === "large-heading-form"
    )?.ht;

    expect(headingText).toHaveLength(8);
    expect(
      Math.max(...headingText!.map((text) => text.length))
    ).toBeLessThanOrEqual(256);
  });

  it("caps repeated container metadata values", () => {
    const longText = "x".repeat(400);
    document.body.innerHTML = `
      <fieldset id="id-${longText}" class="class-${longText}" aria-label="aria-${longText}">
        <legend>legend-${longText}</legend>
        <input name="bounded_meta_a" />
        <input name="bounded_meta_b" />
      </fieldset>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);
    const text = fieldByName(fields, "bounded_meta_a").ct!;

    expect(text).toHaveLength(4);
    expect(
      Math.max(...text.map((value) => value.length))
    ).toBeLessThanOrEqual(256);
  });

  it("cleans a shared aria-labelledby subtree once per snapshot", () => {
    const size = 200;
    document.body.innerHTML = `
      <div id="shared-label">
        ${Array.from(
          { length: size },
          (_, index) => `<span>Label ${index}</span>`
        ).join("")}
      </div>
      <main>
        ${Array.from(
          { length: size },
          (_, index) =>
            `<input name="labelled_${index}" aria-labelledby="shared-label" />`
        ).join("")}
      </main>
    `;
    const source = document.querySelector("#shared-label")!;
    const work = instrumentSharedLabelWork(source);

    const { f: fields } = collectAutofillPageSnapshot(document);

    expect(fields).toHaveLength(size);
    expect(fields[0].lt).toContain("Label 0");
    expect(fields[size - 1].lt).toBe(fields[0].lt);
    expect.soft(work.sourceClones).toBe(0);
    expect.soft(work.detachedFieldMatches).toBeLessThan(size * 4);
  });

  it("fails closed before scheduling an oversized label frontier", () => {
    const label = document.createElement("div");
    label.id = "oversized-label";
    const text = document.createTextNode("x");
    let childReads = 0;
    const childNodes = new Proxy(
      { length: 8_193 },
      {
        get(target, property) {
          if (typeof property === "string" && /^\d+$/.test(property)) {
            childReads += 1;
            return text;
          }
          return Reflect.get(target, property);
        }
      }
    ) as unknown as NodeListOf<ChildNode>;
    Object.defineProperty(label, "childNodes", { value: childNodes });
    const field = document.createElement("input");
    field.setAttribute("aria-labelledby", label.id);
    document.body.append(label, field);

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(0);
    expect(snapshot.f).toHaveLength(0);
    expect(childReads).toBe(0);
  });

  it("fails closed before joining an oversized multi-node label", () => {
    const label = document.createElement("div");
    label.id = "oversized-label-text";
    label.append(
      document.createTextNode("x".repeat(10_000)),
      document.createTextNode("y".repeat(10_000))
    );
    const field = document.createElement("input");
    field.setAttribute("aria-labelledby", label.id);
    document.body.append(label, field);
    const cleaning = instrumentLargeTextCleaning(20_000);

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(0);
    expect(snapshot.f).toHaveLength(0);
    expect(cleaning.value).toBe(0);
  });

  it("fails closed before expanding repeated cached label text", () => {
    const label = document.createElement("div");
    label.id = "repeated-large-label";
    label.textContent = "x".repeat(10_000);
    const field = document.createElement("input");
    field.setAttribute(
      "aria-labelledby",
      Array.from({ length: 120 }, () => label.id).join(" ")
    );
    document.body.append(label, field);
    const cleaning = instrumentLargeTextCleaning(1_000_000);

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(0);
    expect(snapshot.f).toHaveLength(0);
    expect(cleaning.value).toBe(0);
  });

  it("fails closed before materializing too many aria label references", () => {
    const label = document.createElement("div");
    label.id = "many-label-references";
    label.textContent = "Label";
    const labelledBy = Array.from({ length: 129 }, () => label.id).join(" ");
    const field = document.createElement("input");
    field.setAttribute("aria-labelledby", labelledBy);
    document.body.append(label, field);
    const split = vi.spyOn(String.prototype, "split");

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.fm).toHaveLength(0);
    expect(snapshot.f).toHaveLength(0);
    expect(split).not.toHaveBeenCalledWith(/\s+/);
  });

  it("keeps in-form semantic scopes inside their associated form", () => {
    document.body.innerHTML = `
      <section id="outside-form">
        <form id="owner-form">
          <input name="plain" />
          <section id="inside-form">
            <input name="scoped_user" />
            <input name="scoped_password" type="password" />
          </section>
        </form>
      </section>
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);
    const plain = fieldByName(fields, "plain");
    const scopedUsername = fieldByName(fields, "scoped_user");
    const scopedPassword = fieldByName(fields, "scoped_password");

    expect(plain.so).toBe(plain.fo);
    expect(scopedUsername.so).toBe(scopedPassword.so);
    expect(scopedUsername.so).not.toBe(scopedUsername.fo);
  });

  it("lets a semantic scope win for externally associated fields", () => {
    document.body.innerHTML = `
      <form id="external-owner"></form>
      <section id="external-scope">
        <input form="external-owner" name="external_scoped" />
      </section>
      <input form="external-owner" name="external_plain" />
    `;

    const { f: fields } = collectAutofillPageSnapshot(document);
    const scoped = fieldByName(fields, "external_scoped");
    const plain = fieldByName(fields, "external_plain");

    expect(scoped.fo).toBe(plain.fo);
    expect(scoped.so).not.toBe(scoped.fo);
    expect(plain.so).toBe(plain.fo);
  });

  it("keeps form-less deep-chain ancestor work linear", () => {
    const depth = 300;
    appendDeepFieldChain(document.body, depth, "formless");
    stubComputedStyle();
    const instrumentation = instrumentAncestorWork();
    let fields: AutofillFieldSnapshot[] = [];

    try {
      fields = collectAutofillPageSnapshot(document).f;
    } finally {
      instrumentation.restore();
    }
    const measured = { ...instrumentation.counts };

    expect(fields).toHaveLength(depth);
    expect.soft(measured.numericDomMapSets).toBeLessThan(depth * 4);
    expect.soft(measured.semanticMatches).toBeLessThan(depth * 4);
  });

  it("preindexes labels without per-field ancestor or label-list walks", () => {
    const depth = 300;
    appendDeepFieldChain(document.body, depth, "label-index");
    stubComputedStyle();
    const counts = { closest: 0, labels: 0 };
    const closest = Element.prototype.closest;
    vi.spyOn(Element.prototype, "closest").mockImplementation(function (
      this: Element,
      selector: string
    ) {
      if (selector === "label") {
        counts.closest += 1;
      }
      return closest.call(this, selector);
    });
    const labels = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "labels"
    )!.get!;
    vi.spyOn(HTMLInputElement.prototype, "labels", "get").mockImplementation(
      function (this: HTMLInputElement) {
        counts.labels += 1;
        return labels.call(this);
      }
    );

    const fields = collectAutofillPageSnapshot(document).f;

    expect(fields).toHaveLength(depth);
    expect(counts.closest).toBe(0);
    expect(counts.labels).toBe(0);
  });

  it("keeps form-associated deep-chain ancestor work linear", () => {
    const depth = 300;
    const form = document.createElement("form");
    document.body.append(form);
    appendDeepFieldChain(form, depth, "associated");
    stubComputedStyle();
    const instrumentation = instrumentAncestorWork();
    let fields: AutofillFieldSnapshot[] = [];

    try {
      fields = collectAutofillPageSnapshot(document).f;
    } finally {
      instrumentation.restore();
    }
    const measured = { ...instrumentation.counts };

    expect(fields).toHaveLength(depth);
    expect(new Set(fields.map((field) => field.fo))).toHaveLength(1);
    expect.soft(measured.numericDomMapSets).toBeLessThan(depth * 4);
    expect.soft(measured.semanticMatches).toBeLessThan(depth * 4);
  });

  it("collects a five-thousand-level page without overflowing the stack", () => {
    stubComputedStyle();
    const batchRoots: Element[] = [];
    let parent: Element = document.body;
    for (let batch = 0; batch < 5; batch += 1) {
      const batchRoot = document.createElement("div");
      let batchParent = batchRoot;
      for (let index = 1; index < 1_000; index += 1) {
        const wrapper = document.createElement("div");
        batchParent.append(wrapper);
        batchParent = wrapper;
      }
      parent.append(batchRoot);
      batchRoots.push(batchRoot);
      parent = batchParent;
    }
    const field = document.createElement("input");
    field.name = "deepest";
    parent.append(field);
    let fields: AutofillFieldSnapshot[] = [];

    try {
      fields = collectAutofillPageSnapshot(document).f;
    } finally {
      field.remove();
      batchRoots.reverse().forEach((batchRoot) => batchRoot.remove());
    }
    expect(fields).toHaveLength(1);
    expect(fields[0].hn).toBe("deepest");
  });

  describe("fail-closed collection budgets", () => {
    function expectEmptySnapshot() {
      const snapshot = collectAutofillPageSnapshot(document);
      expect(snapshot.fm).toHaveLength(0);
      expect(snapshot.f).toHaveLength(0);
    }

    it("accepts the large Chrome fixture's field count", () => {
      document.body.innerHTML = Array.from(
        { length: 1_140 },
        (_, index) => `<input name="fixture_field_${index}" />`
      ).join("");

      expect(collectAutofillPageSnapshot(document).f).toHaveLength(1_140);
    });

    it(
      "fails closed before scheduling an oversized page frontier",
      { timeout: 60_000 },
      () => {
        const wideRoot = document.createElement("div");
        const child = document.createElement("span");
        let childReads = 0;
        const children = new Proxy(
          { length: 65_537 },
          {
            get(target, property) {
              if (typeof property === "string" && /^\d+$/.test(property)) {
                childReads += 1;
                return child;
              }
              return Reflect.get(target, property);
            }
          }
        ) as unknown as HTMLCollection;
        Object.defineProperty(wideRoot, "children", { value: children });
        document.body.append(wideRoot);

        expectEmptySnapshot();
        expect(childReads).toBe(0);
      }
    );

    it("returns no forms or fields after the form budget is exceeded", () => {
      document.body.innerHTML = `${Array.from(
        { length: 257 },
        (_, index) => `<form id="budget-form-${index}"></form>`
      ).join("")}<input name="after_form_budget" />`;

      expectEmptySnapshot();
    });

    it("returns no forms or fields after the field budget is exceeded", () => {
      document.body.innerHTML = Array.from(
        { length: 2_049 },
        (_, index) => `<input name="budget_field_${index}" />`
      ).join("");

      expectEmptySnapshot();
    });

    it("returns no forms or fields after the unique label budget is exceeded", () => {
      document.body.innerHTML = Array.from(
        { length: 129 },
        (_, index) =>
          `<label for="budget-labelled-${index}">Label ${index}</label>` +
          `<input id="budget-labelled-${index}" />`
      ).join("");

      expectEmptySnapshot();
    });

    it("returns no forms or fields after the dataset value budget is exceeded", () => {
      const field = document.createElement("input");
      for (let index = 0; index < 129; index += 1) {
        field.dataset[`budget${index}`] = `value-${index}`;
      }
      document.body.append(field);
      let materialized = false;
      const objectValues = Object.values;
      vi.spyOn(Object, "values").mockImplementation(((value: object) => {
        if (value === field.dataset) {
          materialized = true;
        }
        return objectValues(value);
      }) as typeof Object.values);

      expectEmptySnapshot();
      expect(materialized).toBe(false);
    });

    it("returns no forms or fields after the select option budget is exceeded", () => {
      const select = document.createElement("select");
      for (let index = 0; index < 513; index += 1) {
        select.add(new Option(`Option ${index}`, `value-${index}`));
      }
      document.body.append(select);
      let iterated = false;
      const iterator = select.options[Symbol.iterator];
      vi.spyOn(select.options, Symbol.iterator).mockImplementation(function (
        this: HTMLOptionsCollection
      ) {
        iterated = true;
        return iterator.call(this);
      });

      expectEmptySnapshot();
      expect(iterated).toBe(false);
    });

    it("returns no forms or fields when the serialized snapshot is too large", () => {
      const field = document.createElement("input");
      field.id = "x".repeat(1_048_577);
      document.body.append(field);
      const cleaning = instrumentLargeTextCleaning(1_000_000);

      expectEmptySnapshot();
      expect(cleaning.value).toBe(0);
    });

    it("fails closed when lowercase expansion exceeds the per-value budget", () => {
      const field = document.createElement("input");
      field.setAttribute("autocomplete", "\u0130".repeat(5_462));
      document.body.append(field);

      expectEmptySnapshot();
    });

    it("charges lowercase expansion to the aggregate text budget", () => {
      const fragment = document.createDocumentFragment();
      for (let index = 0; index < 80; index += 1) {
        const field = document.createElement("input");
        field.setAttribute("autocomplete", "\u0130".repeat(3_500));
        fragment.append(field);
      }
      document.body.append(fragment);

      expectEmptySnapshot();
    });

    it("fails closed before cleaning every value past the text budget", () => {
      const value = "x".repeat(12_000);
      document.body.innerHTML = Array.from(
        { length: 100 },
        (_, index) => `<input name="text-budget-${index}" title="${value}" />`
      ).join("");
      const cleaning = instrumentLargeTextCleaning(value.length);

      expectEmptySnapshot();
      expect(cleaning.value).toBeLessThan(100);
    });

    it(
      "returns no forms or fields after the form control budget is exceeded",
      { timeout: 30_000 },
      () => {
        const form = document.createElement("form");
        const fragment = document.createDocumentFragment();
        for (let index = 0; index < 4_097; index += 1) {
          const button = document.createElement("button");
          button.type = "button";
          button.hidden = true;
          fragment.append(button);
        }
        fragment.append(document.createElement("input"));
        form.append(fragment);
        document.body.append(form);

        expectEmptySnapshot();
      }
    );
  });
});
