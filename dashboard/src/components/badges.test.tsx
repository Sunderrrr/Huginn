import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ModeBadge, StateBadge, TaskStatusTag } from "./badges";

describe("StateBadge", () => {
  it("renders the state with the matching class", () => {
    const { container } = render(<StateBadge state="active" />);
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(container.querySelector(".badge--active")).toBeTruthy();
  });

  it("renders revoked styling", () => {
    const { container } = render(<StateBadge state="revoked" />);
    expect(container.querySelector(".badge--revoked")).toBeTruthy();
  });
});

describe("ModeBadge", () => {
  it("flags unrestricted mode prominently", () => {
    const { container } = render(<ModeBadge mode="unrestricted" />);
    expect(screen.getByText(/unrestricted/i)).toBeInTheDocument();
    expect(container.querySelector(".badge--unrestricted")).toBeTruthy();
  });

  it("shows whitelist by default", () => {
    render(<ModeBadge mode="whitelist" />);
    expect(screen.getByText("whitelist")).toBeInTheDocument();
  });
});

describe("TaskStatusTag", () => {
  it("uppercases the status", () => {
    render(<TaskStatusTag status="succeeded" />);
    expect(screen.getByText("SUCCEEDED")).toBeInTheDocument();
  });
});
