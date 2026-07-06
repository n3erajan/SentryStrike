import ReactDOM from "react-dom/client";
import { IconContext } from "@phosphor-icons/react";
import "./index.css";
import App from "./App.jsx";

ReactDOM.createRoot(document.getElementById("root")).render(
  <IconContext.Provider value={{ size: 18, weight: "regular" }}>
    <App />
  </IconContext.Provider>,
);
