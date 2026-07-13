import ReactDOM from "react-dom/client";
import { IconContext } from "@phosphor-icons/react";
import "@fontsource-variable/space-grotesk";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/700.css";
import "./index.css";
import App from "./App.jsx";

ReactDOM.createRoot(document.getElementById("root")).render(
  <IconContext.Provider value={{ size: 18, weight: "regular" }}>
    <App />
  </IconContext.Provider>,
);
