@AGENTS.md

> **Database (since 16 Oct 2026): self-hosted MongoDB 7 on the AWS EC2 box (63.185.211.215), db `ctiaze`.
> MongoDB Atlas is GONE — never use or suggest an Atlas URI.** On the box every service connects to
> `127.0.0.1:27017` (engine: `/opt/ctiaze-engine/engine.env`, web: `/opt/skopnix/app.env`). From the Mac,
> open the SSH tunnel (local 27018 → box 27017) and use the URIs in `~/.config/skopnix/app.env` with port
> 27018; the repo's local `.env`/`.env.local` already point there. Nightly dumps: `/var/backups/skopnix`
> on the box (skopnix-dbdump timer). The engine's GitHub workflows no longer run on a schedule (systemd
> timers on the box replaced them); their `MONGO_URI` secret still names Atlas, so a manual run fails.

