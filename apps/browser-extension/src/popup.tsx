import { createRoot } from "react-dom/client";

import { PopupShell } from "./popupShell";

const container = document.getElementById("root");

if (container) {
  createRoot(container).render(<PopupShell />);
}
