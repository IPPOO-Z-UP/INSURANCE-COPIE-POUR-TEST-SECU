import { Component, type ReactNode } from "react";
import { RouterProvider } from "react-router";
import { router } from "./routes";
import { LanguageProvider } from "./lib/LanguageContext";
import { setupPWA } from "./espace-client/pwa";
import { setupErrorReporter, reportError } from "./espace-client/errorReporter";

setupPWA();
setupErrorReporter();

class AppErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: unknown) {
    console.error("App crash:", error, info);
    reportError(error, { boundary: "AppErrorBoundary", info: String(info ?? "") });
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 24, fontFamily: "system-ui, sans-serif", color: "#111" }}>
          <h1 style={{ fontSize: 22, fontWeight: 800, marginBottom: 12 }}>Erreur de l'application</h1>
          <p style={{ marginBottom: 12, color: "#666" }}>
            Un problème est survenu lors de l'affichage (les détails techniques sont consignés dans la console) :
          </p>
          <pre style={{ background: "#0d1117", color: "#fff", padding: 16, borderRadius: 12, overflow: "auto", fontSize: 12 }}>
            {this.state.error.message}
            {import.meta.env.DEV && this.state.error.stack ? `\n\n${this.state.error.stack}` : ""}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <AppErrorBoundary>
      <LanguageProvider>
        <RouterProvider router={router} />
      </LanguageProvider>
    </AppErrorBoundary>
  );
}
