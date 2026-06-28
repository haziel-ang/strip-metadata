import React from "react";
import { createRoot } from "react-dom/client";
import { analyzeAI } from "./metadata/ai";
import "./style.css";

function App() {
  const [status, setStatus] = React.useState("Core TypeScript pronto.");
  const [result, setResult] = React.useState<string>("");

  async function onFile(file: File) {
    setStatus("Analisi metadati...");
    const ai = await analyzeAI(await file.arrayBuffer(), file.type);
    setResult(`${ai.level}: ${ai.signals.map((s) => s.label).join(", ") || "nessun segnale"}`);
    setStatus(file.name);
  }

  return (
    <main className="react-shell">
      <section className="react-panel">
        <p className="eyebrow">noMeta React/TS migration</p>
        <h1>Migrazione sicura, un modulo alla volta</h1>
        <p>
          Questa shell usa il nuovo core TypeScript senza sostituire ancora la UI stabile in
          <code> app.js</code>. Serve per testare e confrontare le funzioni migrate.
        </p>
        <label className="upload">
          <span>Prova analisi AI metadata</span>
          <input
            type="file"
            accept="image/*"
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              if (file) void onFile(file);
            }}
          />
        </label>
        <div className="result">
          <b>{status}</b>
          {result ? <span>{result}</span> : null}
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
