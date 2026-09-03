import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

function App() {
  return <main>Nexo — 联巢</main>;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

