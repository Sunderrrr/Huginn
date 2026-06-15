import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useSettings, useUpdateSettings } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import type { Settings } from "../api/types";
import { fmtTime } from "../lib/format";

export function SettingsPage() {
  const { user } = useAuth();
  const { data: settings } = useSettings();
  const update = useUpdateSettings();
  const toast = useToast();
  const isAdmin = user?.role === "admin";

  // Fleet
  const [version, setVersion] = useState("");
  const [repo, setRepo] = useState("");
  const [domains, setDomains] = useState("");

  // SSO / OIDC
  const [oidcEnabled, setOidcEnabled] = useState(false);
  const [oidcIssuer, setOidcIssuer] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [oidcClientSecret, setOidcClientSecret] = useState("");
  const [oidcRedirectUrl, setOidcRedirectUrl] = useState("");
  const [oidcPostLoginRedirect, setOidcPostLoginRedirect] = useState("");

  // LDAP
  const [ldapEnabled, setLdapEnabled] = useState(false);
  const [ldapServerUrl, setLdapServerUrl] = useState("");
  const [ldapBindDn, setLdapBindDn] = useState("");
  const [ldapBindPassword, setLdapBindPassword] = useState("");
  const [ldapUserSearchBase, setLdapUserSearchBase] = useState("");
  const [ldapUserSearchFilter, setLdapUserSearchFilter] = useState("");
  const [ldapStartTls, setLdapStartTls] = useState(false);
  const [ldapUseLdaps, setLdapUseLdaps] = useState(false);

  useEffect(() => {
    if (settings) {
      setVersion(settings.target_worker_version);
      setRepo(settings.target_release_repo);
      setDomains(settings.allowed_release_domains.join(", "));
    }
  }, [settings]);

  // Extended settings from API (includes OIDC/LDAP)
  useEffect(() => {
    fetch("/api/settings", { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } })
      .then((r) => r.json())
      .then((s: Record<string, unknown>) => {
        if (s.oidc_enabled !== undefined) {
          setOidcEnabled(!!s.oidc_enabled);
          setOidcIssuer((s.oidc_issuer as string) || "");
          setOidcClientId((s.oidc_client_id as string) || "");
          setOidcRedirectUrl((s.oidc_redirect_url as string) || "");
          setOidcPostLoginRedirect((s.oidc_post_login_redirect as string) || "");
        }
        if (s.ldap_enabled !== undefined) {
          setLdapEnabled(!!s.ldap_enabled);
          setLdapServerUrl((s.ldap_server_url as string) || "");
          setLdapBindDn((s.ldap_bind_dn as string) || "");
          setLdapUserSearchBase((s.ldap_user_search_base as string) || "");
          setLdapUserSearchFilter((s.ldap_user_search_filter as string) || "");
          setLdapStartTls(!!s.ldap_start_tls);
          setLdapUseLdaps(!!s.ldap_use_ldaps);
        }
      })
      .catch(() => {});
  }, []);

  async function save() {
    try {
      await update.mutateAsync({
        target_worker_version: version,
        target_release_repo: repo,
        allowed_release_domains: domains.split(",").map((d) => d.trim()).filter(Boolean),
        oidc_enabled: oidcEnabled,
        oidc_issuer: oidcIssuer,
        oidc_client_id: oidcClientId,
        oidc_client_secret: oidcClientSecret || undefined,
        oidc_redirect_url: oidcRedirectUrl,
        oidc_post_login_redirect: oidcPostLoginRedirect,
        ldap_enabled: ldapEnabled,
        ldap_server_url: ldapServerUrl,
        ldap_bind_dn: ldapBindDn,
        ldap_bind_password: ldapBindPassword || undefined,
        ldap_user_search_base: ldapUserSearchBase,
        ldap_user_search_filter: ldapUserSearchFilter,
        ldap_start_tls: ldapStartTls,
        ldap_use_ldaps: ldapUseLdaps,
      } as Partial<Settings> & Record<string, unknown>);
      toast("ok", "settings saved");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "save failed";
      toast("err", msg);
    }
  }

  return (
    <div style={{ maxWidth: 680 }}>
      <div className="eyebrow">control plane</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 20 }}>
        Settings
      </h1>

      <div className="stack" style={{ gap: 24 }}>
        {/* Fleet */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 24 }}>
          <SectionTitle>Fleet</SectionTitle>
          <div className="stack" style={{ gap: 18 }}>
            <Field label="Target worker version">
              <input className="field" value={version} onChange={(e) => setVersion(e.target.value)} disabled={!isAdmin} />
              <Hint>Workers below this version show as stale and can be updated.</Hint>
            </Field>
            <Field label="Release repository">
              <input className="field" value={repo} onChange={(e) => setRepo(e.target.value)} disabled={!isAdmin} />
            </Field>
            <Field label="Allowed release domains (SSRF allowlist)">
              <input className="field" value={domains} onChange={(e) => setDomains(e.target.value)} disabled={!isAdmin} />
              <Hint>Comma-separated hostnames or IPs.</Hint>
            </Field>
          </div>
        </motion.div>

        {/* SSO / OIDC */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ padding: 24 }}>
          <div className="spread" style={{ marginBottom: 16 }}>
            <SectionTitle>SSO / OIDC</SectionTitle>
            {isAdmin && (
              <label className="row" style={{ gap: 8, cursor: "pointer" }}>
                <input type="checkbox" checked={oidcEnabled} onChange={(e) => setOidcEnabled(e.target.checked)} />
                <span style={{ fontSize: 13 }}>Enabled</span>
              </label>
            )}
          </div>
          <div className="stack" style={{ gap: 18 }}>
            <Field label="Issuer URL">
              <input className="field" value={oidcIssuer} onChange={(e) => setOidcIssuer(e.target.value)} disabled={!isAdmin} placeholder="https://auth.example.com/application/o/huginn" />
              <Hint>Authentik or any OIDC-compliant provider.</Hint>
            </Field>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <Field label="Client ID">
                <input className="field" value={oidcClientId} onChange={(e) => setOidcClientId(e.target.value)} disabled={!isAdmin} />
              </Field>
              <Field label="Client secret">
                <input className="field" type="password" value={oidcClientSecret} onChange={(e) => setOidcClientSecret(e.target.value)} disabled={!isAdmin} placeholder="••••••••" />
              </Field>
            </div>
            <Field label="Redirect URL">
              <input className="field" value={oidcRedirectUrl} onChange={(e) => setOidcRedirectUrl(e.target.value)} disabled={!isAdmin} placeholder="https://hub.example.com/api/auth/oidc/callback" />
            </Field>
            <Field label="Post-login redirect (dashboard URL)">
              <input className="field" value={oidcPostLoginRedirect} onChange={(e) => setOidcPostLoginRedirect(e.target.value)} disabled={!isAdmin} placeholder="https://hub.example.com/login" />
              <Hint>After OIDC login, redirect browser here with token in fragment.</Hint>
            </Field>
          </div>
        </motion.div>

        {/* LDAP */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} style={{ padding: 24 }}>
          <div className="spread" style={{ marginBottom: 16 }}>
            <SectionTitle>LDAP / LDAPS</SectionTitle>
            {isAdmin && (
              <label className="row" style={{ gap: 8, cursor: "pointer" }}>
                <input type="checkbox" checked={ldapEnabled} onChange={(e) => setLdapEnabled(e.target.checked)} />
                <span style={{ fontSize: 13 }}>Enabled</span>
              </label>
            )}
          </div>
          <div className="stack" style={{ gap: 18 }}>
            <Field label="Server URL">
              <input className="field" value={ldapServerUrl} onChange={(e) => setLdapServerUrl(e.target.value)} disabled={!isAdmin} placeholder="ldap://ldap.example.com:389" />
            </Field>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <Field label="Bind DN">
                <input className="field" value={ldapBindDn} onChange={(e) => setLdapBindDn(e.target.value)} disabled={!isAdmin} placeholder="cn=admin,dc=example,dc=com" />
              </Field>
              <Field label="Bind password">
                <input className="field" type="password" value={ldapBindPassword} onChange={(e) => setLdapBindPassword(e.target.value)} disabled={!isAdmin} placeholder="••••••••" />
              </Field>
            </div>
            <Field label="User search base">
              <input className="field" value={ldapUserSearchBase} onChange={(e) => setLdapUserSearchBase(e.target.value)} disabled={!isAdmin} placeholder="ou=users,dc=example,dc=com" />
            </Field>
            <Field label="User search filter">
              <input className="field" value={ldapUserSearchFilter} onChange={(e) => setLdapUserSearchFilter(e.target.value)} disabled={!isAdmin} placeholder="(uid={username})" />
              <Hint>Use {"{username}"} as placeholder for the login username.</Hint>
            </Field>
            <div className="row" style={{ gap: 24 }}>
              {isAdmin && (
                <>
                  <label className="row" style={{ gap: 8, cursor: "pointer" }}>
                    <input type="checkbox" checked={ldapStartTls} onChange={(e) => setLdapStartTls(e.target.checked)} />
                    <span style={{ fontSize: 13 }}>StartTLS</span>
                  </label>
                  <label className="row" style={{ gap: 8, cursor: "pointer" }}>
                    <input type="checkbox" checked={ldapUseLdaps} onChange={(e) => setLdapUseLdaps(e.target.checked)} />
                    <span style={{ fontSize: 13 }}>LDAPS (SSL)</span>
                  </label>
                </>
              )}
            </div>
            <Hint>LDAPS uses port 636 with SSL. StartTLS upgrades a plain connection on port 389.</Hint>
          </div>
        </motion.div>

        {/* Save button */}
        {isAdmin ? (
          <div className="spread">
            <span className="muted tiny">updated {fmtTime(settings?.updated_at ?? null)}</span>
            <button className="btn btn--primary" onClick={save} disabled={update.isPending}>
              {update.isPending ? <span className="spin" /> : "Save settings"}
            </button>
          </div>
        ) : (
          <div className="muted tiny">Read-only — settings changes require an admin account.</div>
        )}
      </div>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="display" style={{ fontSize: 15, letterSpacing: "0.1em", marginBottom: 4 }}>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="lbl">{label}</label>
      {children}
    </div>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return <div className="muted tiny" style={{ marginTop: 5 }}>{children}</div>;
}
