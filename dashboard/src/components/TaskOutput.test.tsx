import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Task } from "../api/types";
import { TaskOutput, TaskResultView } from "./TaskOutput";

function taskWith(stdout: string): Task {
  return {
    id: "t1",
    vm_id: "v1",
    type: "browser",
    action_name: null,
    status: "succeeded",
    exit_code: 0,
    stdout,
    stderr: null,
    error: null,
    created_at: "2026-01-01T00:00:00Z",
    finished_at: "2026-01-01T00:00:01Z",
  };
}

const JPEG =
  "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAA" + "EABAAA".repeat(4);

describe("TaskOutput", () => {
  it("renders plain step lines as text", () => {
    render(<TaskOutput stdout={"step 1 (navigate): https://example.com\nstep 2 (get_text): hello"} />);
    expect(screen.getByText(/step 1 \(navigate\)/)).toBeInTheDocument();
    expect(screen.getByText(/step 2 \(get_text\)/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("renders screenshot lines as clickable images with the raw line folded away", () => {
    const line = `step 2 (screenshot): ${JPEG}`;
    const { container } = render(<TaskOutput stdout={`step 1 (navigate): https://example.com\n${line}`} />);
    const img = screen.getByRole("img", { name: "screenshot 1" });
    expect(img).toHaveAttribute("src", JPEG);
    // clickable: wrapped in a link that opens a new tab
    const link = img.closest("a");
    expect(link).not.toBeNull();
    expect(link).toHaveAttribute("href", JPEG);
    expect(link).toHaveAttribute("target", "_blank");
    // the raw base64 line is kept in a collapsed <details>
    const details = container.querySelector("details");
    expect(details).not.toBeNull();
    expect(screen.queryByText(line)).not.toBeVisible();
  });

  it("renders one image per screenshot line, and survives truncated base64", () => {
    // cut mid-payload by the ~1 MiB stdout cap — the prefix survives, the
    // base64 just ends early (a broken <img>, never a crash)
    const truncated = "data:image/jpeg;base64,/9j/4AAQ";
    render(
      <TaskOutput
        stdout={`step 1 (screenshot): ${JPEG}\nstep 2 (screenshot): ${truncated}\n[...output truncated...]`}
      />,
    );
    expect(screen.getByRole("img", { name: "screenshot 1" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "screenshot 2" })).toBeInTheDocument();
    expect(screen.getByText("[...output truncated...]")).toBeInTheDocument();
  });

  it("renders pdf lines as download links, not images", () => {
    const pdf = "data:application/pdf;base64,JVBERi0xLjQK";
    render(<TaskOutput stdout={`step 3 (pdf): ${pdf}`} />);
    const link = screen.getByText("📄 PDF export 1 (download)");
    expect(link).toBeInTheDocument();
    expect(link.closest("a")).toHaveAttribute("download", "huginn-export-1.pdf");
    // No <img> for a PDF.
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});

describe("TaskResultView", () => {
  it("shows the status and the rendered stdout", () => {
    render(<TaskResultView task={taskWith(`step 1 (screenshot): ${JPEG}`)} />);
    expect(screen.getByText("SUCCEEDED")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "screenshot 1" })).toBeInTheDocument();
  });

  it("shows stderr and error when present", () => {
    const task = { ...taskWith("out"), stderr: "boom", error: "step 1 (navigate) failed: timeout" };
    render(<TaskResultView task={task} />);
    expect(screen.getByText("boom")).toBeInTheDocument();
    expect(screen.getByText(/step 1 \(navigate\) failed/)).toBeInTheDocument();
  });
});
