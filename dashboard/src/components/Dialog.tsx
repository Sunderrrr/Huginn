import { AnimatePresence, motion } from "framer-motion";
import type { ReactNode } from "react";

export function Modal({
  open,
  onClose,
  title,
  children,
  width = 520,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  width?: number;
}) {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 900,
            background: "rgba(4,5,7,0.78)",
            backdropFilter: "blur(3px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 20,
          }}
        >
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 18, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 380, damping: 30 }}
            onClick={(e) => e.stopPropagation()}
            className="panel panel--bracket"
            style={{ width, maxWidth: "100%", boxShadow: "var(--shadow)" }}
          >
            <div
              className="spread"
              style={{ padding: "16px 18px", borderBottom: "1px solid var(--line)" }}
            >
              <h3 className="display" style={{ fontSize: 16, letterSpacing: "0.1em" }}>
                {title}
              </h3>
              <button className="btn btn--ghost btn--sm" onClick={onClose}>
                ✕
              </button>
            </div>
            <div style={{ padding: 18 }}>{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
