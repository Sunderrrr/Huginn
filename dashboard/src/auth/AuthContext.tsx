import { createContext, useContext, useCallback, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, setToken } from "../api/client";
import { useMe } from "../api/hooks";
import type { User } from "../api/types";

interface TokenResponse {
  access_token: string;
  expires_in: number;
}
interface OIDCStart {
  authorization_url: string;
}

interface AuthValue {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  oidcLogin: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { data: user, isLoading } = useMe();

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await api.post<TokenResponse>("/api/auth/login", { username, password });
      setToken(res.access_token);
      await qc.invalidateQueries({ queryKey: ["me"] });
    },
    [qc],
  );

  const logout = useCallback(() => {
    setToken(null);
    qc.clear();
    window.location.href = "/login";
  }, [qc]);

  const oidcLogin = useCallback(async () => {
    const res = await api.get<OIDCStart>("/api/auth/oidc/login");
    window.location.href = res.authorization_url;
  }, []);

  return (
    <AuthContext.Provider value={{ user: user ?? null, loading: isLoading, login, logout, oidcLogin }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
