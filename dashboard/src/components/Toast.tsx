import { AnimatePresence, motion } from "framer-motion";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

type ToastKind = "ok" | "err" | "info";
interface Toast {
  id: number;
  kind: ToastKind;
  msg: string;
}

const ToastContext = createContext<(kind: ToastKind, msg: string) => void>(() => {});

const COLOR: Record<ToastKind, string> = {
  ok: "var(--signal)",
  err: "var(--blood)",
  info: "var(--steel)",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((kind: ToastKind, msg: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, msg }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div
        style={{
          position: "fixed",
          bottom: 24,
          right: 24,
          zIndex: 1000,
          display: "flex",
          flexDirection: "column",
          gap: 10,
          maxWidth: 380,
        }}
      >
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, x: 40, scale: 0.96 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 40, scale: 0.96 }}
              transition={{ type: "spring", stiffness: 400, damping: 30 }}
              className="panel"
              style={{
                padding: "12px 14px",
                borderLeft: `2px solid ${COLOR[t.kind]}`,
                display: "flex",
                gap: 10,
                alignItems: "center",
                boxShadow: "var(--shadow)",
              }}
            >
              <span style={{ color: COLOR[t.kind], fontFamily: "var(--font-display)" }}>
                {t.kind === "ok" ? "✓" : t.kind === "err" ? "✕" : "›"}
              </span>
              <span style={{ fontSize: 13 }}>{t.msg}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
