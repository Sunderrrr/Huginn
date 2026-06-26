import { createContext, useContext, useCallback, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { startAuthentication } from "@simplewebauthn/browser";
import { api, setToken } from "../api/client";
import { useMe } from "../api/hooks";
import type { LoginChallenge, User } from "../api/types";

interface TokenResponse {
  access_token: string;
  expires_in: number;
}
interface OIDCStart {
  authorization_url: string;
}

export type LoginResult =
  | { kind: "ok" }
  | { kind: "mfa"; methods: string[] }
  | { kind: "mfa_setup"; methods: string[] };

interface AuthValue {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<LoginResult>;
  verifyMfa: (payload: { code?: string; backup_code?: string }) => Promise<void>;
  setupToken: string | null;
  finishSetup: (accessToken: string) => Promise<void>;
  passkeyLogin: (username?: string) => Promise<void>;
  logout: () => void;
  oidcLogin: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { data: user, isLoading } = useMe();
  // Held in memory only — never persisted to localStorage.
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [setupToken, setSetupToken] = useState<string | null>(null);

  const adopt = useCallback(
    async (accessToken: string) => {
      setToken(accessToken);
      setChallengeToken(null);
      setSetupToken(null);
      await qc.invalidateQueries({ queryKey: ["me"] });
    },
    [qc],
  );

  const login = useCallback(
    async (username: string, password: string): Promise<LoginResult> => {
      const res = await api.post<TokenResponse & LoginChallenge>("/api/auth/login", {
        username,
        password,
      });
      if (res.mfa_required) {
        setChallengeToken(res.challenge_token);
        return { kind: "mfa", methods: res.methods };
      }
      if (res.mfa_setup_required) {
        setSetupToken(res.challenge_token);
        return { kind: "mfa_setup", methods: res.methods };
      }
      await adopt(res.access_token);
      return { kind: "ok" };
    },
    [adopt],
  );

  const verifyMfa = useCallback(
    async (payload: { code?: string; backup_code?: string }) => {
      if (!challengeToken) throw new Error("no MFA challenge in progress");
      const res = await api.postWithToken<TokenResponse>(
        "/api/auth/mfa/verify",
        payload,
        challengeToken,
      );
      await adopt(res.access_token);
    },
    [challengeToken, adopt],
  );

  // Called by the setup flow once an enroll endpoint returns an access token.
  const finishSetup = useCallback((accessToken: string) => adopt(accessToken), [adopt]);

  const passkeyLogin = useCallback(
    async (username?: string) => {
      const options = await api.post<Record<string, unknown>>(
        "/api/auth/mfa/webauthn/login/begin",
        { username: username || null },
      );
      const assertion = await startAuthentication({ optionsJSON: options as never });
      const res = await api.post<TokenResponse>("/api/auth/mfa/webauthn/login/finish", {
        credential: assertion,
      });
      await adopt(res.access_token);
    },
    [adopt],
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
    <AuthContext.Provider
      value={{
        user: user ?? null,
        loading: isLoading,
        login,
        verifyMfa,
        setupToken,
        finishSetup,
        passkeyLogin,
        logout,
        oidcLogin,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
