import type { Task, TaskStatus } from "../api/types";
import { TaskStatusTag } from "./badges";

// Browser tasks embed captures in stdout as `step N (action): data:…` lines.
// One line = one capture: screenshots (image) as <img>, PDFs as a download
// link. The base64 may be truncated (stdout is capped at ~1 MiB) — a broken
// data URI only renders a broken image/link, it never crashes the page.
const DATA_IMAGE = "data:image/";
const DATA_PDF = "data:application/pdf;base64,";

// A stdout line's embedded capture, or null for plain lines.
function screenshotUri(line: string): string | null {
  const idx = line.indexOf(DATA_IMAGE);
  if (idx === -1) return null;
  const uri = line.slice(idx);
  return uri.startsWith("data:image/jpeg;base64,") || uri.startsWith("data:image/png;base64,")
    ? uri
    : null;
}

function pdfUri(line: string): string | null {
  const idx = line.indexOf(DATA_PDF);
  return idx === -1 ? null : line.slice(idx);
}

/**
 * Task stdout: plain lines as text, screenshot lines as clickable images
 * (max-width 100%, opens in a new tab), PDF lines as download links — the
 * raw base64 kept in a collapsed `<details>`.
 */
export function TaskOutput({ stdout }: { stdout: string }) {
  let shots = 0;
  let pdfs = 0;
  return (
    <div className="codeblock" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {stdout.split("\n").map((line, i) => {
        const uri = screenshotUri(line);
        const pdf = uri ? null : pdfUri(line);
        if (uri) {
          shots += 1;
          return (
            <div key={i}>
              <a href={uri} target="_blank" rel="noreferrer">
                <img
                  src={uri}
                  alt={`screenshot ${shots}`}
                  style={{ maxWidth: "100%", display: "block", border: "1px solid var(--line)" }}
                />
              </a>
              <details style={{ marginTop: 4 }}>
                <summary className="muted tiny">raw</summary>
                <div className="muted tiny" style={{ wordBreak: "break-all" }}>
                  {line}
                </div>
              </details>
            </div>
          );
        }
        if (pdf) {
          pdfs += 1;
          return (
            <div key={i}>
              <a href={pdf} download={`huginn-export-${pdfs}.pdf`}>
                📄 PDF export {pdfs} (download)
              </a>
              <details style={{ marginTop: 4 }}>
                <summary className="muted tiny">raw</summary>
                <div className="muted tiny" style={{ wordBreak: "break-all" }}>
                  {line}
                </div>
              </details>
            </div>
          );
        }
        // keep blank lines as blank lines inside the flex column
        return (
          <span key={i} style={{ whiteSpace: "pre-wrap" }}>
            {line || "\u00A0"}
          </span>
        );
      })}
    </div>
  );
}

// Statuses a task never leaves — the spinner below shows until then.
const IN_FLIGHT: ReadonlySet<TaskStatus> = new Set(["pending", "dispatched", "running"]);

/**
 * The result block of a dispatched task — status header (spinner while the
 * task is still queued/running), stdout (with screenshots rendered),
 * stderr and error. Shared by the action/command results and the browser
 * step runner on the VM page.
 */
export function TaskResultView({ task }: { task: Task }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row" style={{ gap: 12, marginBottom: 6 }}>
        <TaskStatusTag status={task.status} />
        {task.exit_code !== null && <span className="muted tiny">exit {task.exit_code}</span>}
        {IN_FLIGHT.has(task.status) && <span className="spin" />}
      </div>
      {task.stdout && <TaskOutput stdout={task.stdout} />}
      {task.stderr && (
        <pre className="codeblock" style={{ borderColor: "rgba(255,77,77,0.3)", marginTop: 8 }}>
          {task.stderr}
        </pre>
      )}
      {task.error && <div style={{ color: "var(--blood)", marginTop: 8 }}>{task.error}</div>}
    </div>
  );
}
