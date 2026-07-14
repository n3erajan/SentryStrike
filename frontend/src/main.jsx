import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { IconContext } from "@phosphor-icons/react";
import "./index.css";
import App from "./App.jsx";
import { AuthProvider } from "./context/AuthContext.jsx";

ReactDOM.createRoot(document.getElementById("root")).render(
  <IconContext.Provider value={{ size: 18, weight: "regular" }}>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </IconContext.Provider>,
);
