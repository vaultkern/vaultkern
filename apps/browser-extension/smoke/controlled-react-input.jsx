import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";

const emptyEventCounts = () => ({
  nativeInput: 0,
  nativeChange: 0,
  nativeBlur: 0,
  reactInput: 0,
  reactChange: 0
});

function ControlledLogin() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [renderEpoch, setRenderEpoch] = useState(0);
  const [eventCounts, setEventCounts] = useState({
    username: emptyEventCounts(),
    password: emptyEventCounts()
  });
  const formRef = useRef(null);

  function increment(field, eventName) {
    setEventCounts((current) => ({
      ...current,
      [field]: {
        ...current[field],
        [eventName]: current[field][eventName] + 1
      }
    }));
  }

  useEffect(() => {
    const form = formRef.current;
    const observe = (event) => {
      const field = event.target?.dataset?.fixtureField;
      if (field !== "username" && field !== "password") {
        return;
      }
      const eventName =
        event.type === "input"
          ? "nativeInput"
          : event.type === "change"
            ? "nativeChange"
            : "nativeBlur";
      increment(field, eventName);
    };
    for (const eventName of ["input", "change", "blur"]) {
      form.addEventListener(eventName, observe, true);
    }
    globalThis.__vaultkernReactRerender = () =>
      setRenderEpoch((current) => current + 1);
    globalThis.__vaultkernReactReady = true;
    return () => {
      for (const eventName of ["input", "change", "blur"]) {
        form.removeEventListener(eventName, observe, true);
      }
      delete globalThis.__vaultkernReactRerender;
      delete globalThis.__vaultkernReactReady;
    };
  }, []);

  const state = {
    reactVersion: React.version,
    username,
    password,
    renderEpoch,
    eventCounts
  };

  return (
    <form ref={formRef} aria-label="Sign in">
      <h1>Sign in</h1>
      <label>
        Username
        <input
          id="react-username"
          data-fixture-field="username"
          type="email"
          name="username"
          autoComplete="username"
          value={username}
          onInput={() => increment("username", "reactInput")}
          onChange={(event) => {
            setUsername(event.currentTarget.value);
            increment("username", "reactChange");
          }}
        />
      </label>
      <label>
        Password
        <input
          id="react-password"
          data-fixture-field="password"
          type="password"
          name="password"
          autoComplete="current-password"
          value={password}
          onInput={() => increment("password", "reactInput")}
          onChange={(event) => {
            setPassword(event.currentTarget.value);
            increment("password", "reactChange");
          }}
        />
      </label>
      <output id="react-state">{JSON.stringify(state)}</output>
    </form>
  );
}

createRoot(document.querySelector("#react-root")).render(<ControlledLogin />);
