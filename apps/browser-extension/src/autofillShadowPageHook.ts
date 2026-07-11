(() => {
  const OPEN_SHADOW_ROOT_EVENT = "vaultkern:autofill:open-shadow-root";
  const elementPrototype = Element.prototype;
  const attachShadow = elementPrototype.attachShadow;
  const dispatchEvent = EventTarget.prototype.dispatchEvent;
  const CustomEventConstructor = globalThis.CustomEvent;

  elementPrototype.attachShadow = new Proxy(attachShadow, {
    apply(target, thisArg, argumentsList) {
      const shadowRoot = Reflect.apply(target, thisArg, argumentsList);
      if (shadowRoot.mode === "open") {
        try {
          dispatchEvent.call(
            thisArg,
            new CustomEventConstructor(OPEN_SHADOW_ROOT_EVENT, {
              bubbles: true,
              composed: true
            })
          );
        } catch {
          // Discovery is advisory and must not change attachShadow behavior.
        }
      }
      return shadowRoot;
    }
  });
})();
