import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/tokens.css";
import "./styles/global.css";
import "./styles/components.css";

const rootEl = document.getElementById("root");
if (!rootEl) {
  throw new Error("找不到挂载节点 #root");
}

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
