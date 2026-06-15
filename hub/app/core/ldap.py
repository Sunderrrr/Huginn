"""LDAP / LDAPS authentication against a directory configured at runtime.

Config lives in the DB ``settings`` row (admin-editable from the dashboard), not
in environment variables. The flow is the standard bind-search-bind:

1. Bind with a service account (``ldap_bind_dn`` / ``ldap_bind_password``).
2. Search for the user by ``ldap_user_search_filter`` (``{username}`` substituted
   and escaped to prevent LDAP injection).
3. Re-bind as the found DN with the supplied password to verify it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.models.setting import Setting

logger = logging.getLogger("huginn.hub.ldap")

_CONNECT_TIMEOUT = 10


@dataclass
class LDAPClaims:
    dn: str
    username: str
    email: str | None


class LDAPClient:
    def __init__(self, settings_row: Setting) -> None:
        self._s = settings_row

    @property
    def enabled(self) -> bool:
        s = self._s
        return bool(s.ldap_enabled and s.ldap_server_url and s.ldap_user_search_base)

    def _build_server(self) -> Server:
        use_ssl = bool(self._s.ldap_use_ldaps)
        tls = Tls() if (use_ssl or self._s.ldap_start_tls) else None
        return Server(
            self._s.ldap_server_url,
            use_ssl=use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=_CONNECT_TIMEOUT,
        )

    def authenticate(self, username: str, password: str) -> LDAPClaims | None:
        """Return claims if the username/password bind succeeds, else None.

        Synchronous (ldap3 is blocking) — call from a thread in async contexts.
        """
        if not self.enabled or not password:
            return None
        server = self._build_server()
        safe_username = escape_filter_chars(username)
        search_filter = self._s.ldap_user_search_filter.replace("{username}", safe_username)
        try:
            # 1. Bind as the service account.
            conn = Connection(
                server,
                user=self._s.ldap_bind_dn or None,
                password=self._s.ldap_bind_password or None,
                auto_bind=False,
            )
            if self._s.ldap_start_tls and not self._s.ldap_use_ldaps:
                conn.open()
                conn.start_tls()
            if not conn.bind():
                logger.warning("LDAP service bind failed: %s", conn.last_error)
                return None

            # 2. Search for the user.
            conn.search(
                search_base=self._s.ldap_user_search_base,
                search_filter=search_filter,
                attributes=["mail", "cn", "uid"],
            )
            if not conn.entries:
                return None
            entry = conn.entries[0]
            user_dn = entry.entry_dn
            email = str(entry.mail) if "mail" in entry else None
            conn.unbind()

            # 3. Re-bind as the user to verify the password.
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=False)
            if self._s.ldap_start_tls and not self._s.ldap_use_ldaps:
                user_conn.open()
                user_conn.start_tls()
            if not user_conn.bind():
                return None
            user_conn.unbind()

            return LDAPClaims(dn=user_dn, username=username, email=email)
        except LDAPException as exc:
            logger.warning("LDAP authentication error: %s", exc)
            return None
