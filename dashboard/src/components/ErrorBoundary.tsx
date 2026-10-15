import React from "react";

type Props = { children: React.ReactNode; label?: string };
type State = { error: Error | null };

/**
 * Page-level error boundary: a malformed API response (or a render bug) shows
 * a readable error card instead of a blank admin panel — critical during an
 * incident. Data is never trusted blindly downstream, but this is the net.
 */
export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel" style={{ margin: 24, padding: 24 }}>
          <div className="eyebrow" style={{ color: "var(--danger)" }}>
            {this.props.label ?? "SECTION"} ERROR
          </div>
          <p className="muted" style={{ marginTop: 8 }}>
            {this.state.error.message || "Unexpected render error."}
          </p>
          <button
            className="btn btn--sm"
            style={{ marginTop: 12 }}
            onClick={() => this.setState({ error: null })}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
