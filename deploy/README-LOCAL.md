# Huginn — déploiement production sur cette machine

Stack : PostgreSQL 16 + hub FastAPI + dashboard React + MCP + Caddy (TLS).
Déploiement du 2026-10-13, via `docker-compose.prod.yml` (backend conteneurs : Podman).

## Accès

- **URL principale** : https://huginn.example.com/ (via Cloudflare — voir « Connexion Cloudflare »)
- **Accès direct local** : https://192.0.2.10/ (IP Netbird ; aussi 10.0.0.75, localhost, node-b)
  → recommandé pour les workers : `HUB_URL=https://192.0.2.10`
- **Admin initial** : `admin` / mot de passe dans `.env.prod` (`HUGINN_BOOTSTRAP_ADMIN_PASSWORD`)
- À la première connexion : configuration **TOTP obligatoire** (QR code) — `HUGINN_REQUIRE_ADMIN_MFA=true`.
  Passkeys/WebAuthn configurées pour `huginn.example.com` (fonctionnent une fois l'accès domaine actif).

## Connexion Cloudflare (état au 2026-10-14)

Le domaine `huginn.example.com` est proxifié Cloudflare (zone NS Cloudflare) mais l'origine
actuelle du hostname `huginn` répond `404 page not found` (autre serveur) et le port 443 de
l'IP publique 82.70.249.181 n'est PAS joignable depuis Internet (NAT fermé). Deux options :

1. **Cloudflare Tunnel (recommandé, aucun NAT à ouvrir)** : créer un tunnel dans le dashboard
   Cloudflare Zero Trust, hostname public `huginn.example.com` → service
   `https://localhost:443` (cocher *No TLS Verify* — notre cert est self-signed), installer le
   connector ici : `cloudflared service install <token>`.
2. **Port forwarding** : rediriger 80/443 du routeur vers cette machine, record A `huginn` →
   `82.70.249.181`. ⚠️ Mettre le mode SSL Cloudflare sur **Full** (pas *Full (strict)*, notre
   cert origin est self-signed) — ou fournir un Cloudflare Origin Certificate dans
   `deploy/certs/` (remplacer huginn.crt/huginn.key puis `... restart caddy`).

En attendant, tout fonctionne en accès direct local (IP Netbird / LAN).

## HTTPS (certificat auto-généré)

Certificat serveur émis par la **« Huginn Local CA »** (`certs/huginn-ca.crt`, clé 4096, valable 10 ans),
leaf en `certs/huginn.crt` + `certs/huginn.key` (5 ans). SANs : huginn.example.com,
192.0.2.10, 10.0.0.75, 82.70.249.181, 127.0.0.1, localhost, node-b.
Le Caddyfile route le même site pour tous ces noms (`Caddyfile`, site block).

- Navigateur : warning « non approuvé » au premier accès (Normal). Pour un accès sans warning,
  importer `certs/huginn-ca.crt` dans le magasin de certificats du poste (Autorités de confiance).
- La CA est aussi servie par le hub : `curl -k https://192.0.2.10/caddy-root.crt -o huginn-ca.crt`
- Les workers l'installent automatiquement (trust-on-first-use) via `install.sh`.

## Enrôler une VM

Depuis le dashboard : Fleet → Add VM → token. Puis sur la VM :

```bash
curl -fsSL https://192.0.2.10/install.sh | HUB_URL=https://192.0.2.10 TOKEN=<token> bash
```

(`install.sh` récupère la CA automatiquement ; binaires servis par le hub sur `/dist` —
les reconstruire avec `./build-artifacts.sh` si le worker change.)

## Opérations (depuis /opt/huginn/deploy)

```bash
cd /opt/huginn/deploy
docker compose -f docker-compose.prod.yml --env-file .env.prod ps        # état
docker compose -f docker-compose.prod.yml --env-file .env.prod logs -f hub   # logs d'un service
docker compose -f docker-compose.prod.yml --env-file .env.prod down          # stop (données conservées)
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d         # start
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build # rebuild après MAJ du repo
```

Sauvegarde DB : `docker exec deploy-postgres-1 pg_dump -U huginn huginn > backup.sql`

## Particularités de cette machine

- **MCP Rust en prod** (`mcp-rs/`, image déployée sur ce stack) : auth Bearer
  par utilisateur comme le Python, tests e2e passés. Le hub tourne aussi avec
  le long-poll event-driven (pickup <200 ms, idle DB ~0).
- `postgres` a `security_opt: apparmor=unconfined` dans `docker-compose.prod.yml` :
  le profil AppArmor par défaut de Podman sur Ubuntu bloque les `signal()` de gosu
  (l'entrypoint de l'image postgres boucle alors à 100 % CPU sans jamais démarrer).
  À conserver tant que Podman+AppArmor sont utilisés.
- `mcp/pyproject.toml` épingle `mcp>=1.2,<2` (l'API FastMCP a été retirée en mcp 2.x).
- La stack redémarre au reboot : `podman.socket` + `podman-restart.service` activés,
  tous les services en `restart: unless-stopped`.
- Secrets dans `.env.prod` (chmod 600). Backup recommandé de `certs/` + `.env.prod`.
