# PhantomNet Cloud Console

A web terminal for managing PhantomNet sensors from anywhere. You type commands
(`status`, `incidents`, `alerts test`, `setup`, …) instead of clicking pages.

```
 Browser, anywhere                     Vercel (console/)
 ┌─────────────────────────┐     ┌──────────────────────────────┐
 │ you@phantomnet:~/lab$ _  │ ──► │ FastAPI: commands, auth,     │
 └─────────────────────────┘     │ sensor sync API              │
                                 └──────────────┬───────────────┘
                                                │ Admin SDK
                                  Firebase: Authentication + Firestore
                                                ▲
                          outbound HTTPS only   │
 ┌──────────────────────────────┐               │
 │ Sensor (phantomnet-core)      │ ──────────────┘  every 15 s:
 │  never accepts connections    │   push status + redacted incidents
 └──────────────────────────────┘   pull settings + queued actions
```

## Security model

- **Sensors only connect out.** Nothing on the internet can reach a sensor; a
  compromised console can change decoy settings but cannot open a shell, read
  files, or touch production — the sensor re-validates every setting and the
  controller has no host privileges.
- **Enrollment** uses a single-use code that expires after 24 h. The sensor
  swaps it for a long-lived token; the console stores only SHA-256 hashes of
  both. Removing a sensor in the console revokes its token immediately.
- **Data leaving the sensor is redacted** (no passwords, ever — only lengths).
- **Firestore is server-only.** `console/firestore.rules` denies all client
  access; only the console's service account can read or write.
- **Accounts** are Firebase Authentication (email + password). Each user sees
  only their own sensors and incidents.
- Every state-changing command is written to an audit log (`audit`), with
  webhook URLs and passwords stripped.

## Deploying

### 1. Firebase project
1. Create a project at <https://console.firebase.google.com> (Spark/free plan is enough).
2. **Build → Authentication → Get started → Sign-in method → Email/Password → Enable.**
3. **Build → Firestore Database → Create database** (production mode, any US location).
4. Deploy the deny-all rules: `firebase deploy --only firestore:rules` from `console/`
   (or paste `console/firestore.rules` into Firestore → Rules → Publish).
5. **Project settings → General → Web API key** — copy it.
6. **Project settings → Service accounts → Generate new private key** — downloads a JSON file.
   Treat it like a password: never commit it.

### 2. Vercel
1. Import the GitHub repo in Vercel. Set **Root Directory = `console`**
   (framework preset: FastAPI).
2. **Settings → Environment Variables**:

   | Name | Value |
   |---|---|
   | `FIREBASE_API_KEY` | the Web API key |
   | `FIREBASE_SERVICE_ACCOUNT` | the entire contents of the service-account JSON file |
   | `PN_CONSOLE_URL` | your console URL, e.g. `https://phantomnet-console.vercel.app` |

3. Deploy. Open the URL, type `signup`.

### 3. Connect a sensor
In the console:
```
signup                     # or login
sensor add office          # prints PN_CLOUD_URL and a one-time PN_ENROLL_CODE
```
On the sensor host, add both lines to `/opt/phantomnet/.env` and run
`sudo docker compose up -d`. Within ~30 s, `sensors` shows it **online**.

Port/address changes (`decoys …`, `config set decoys.*`) are applied on the host by
```bash
sudo scripts/apply-managed-config.sh            # or schedule it every few minutes
```
because containers deliberately can't change their own ports.

## Commands

| Area | Commands |
|---|---|
| Account | `signup` · `login` · `logout` · `whoami` · `clear` |
| Sensors | `sensors` · `sensor add <name>` · `sensor code <name>` · `sensor remove <name> --yes` · `use <name>` · `status` |
| Incidents | `incidents [--all] [--high]` · `incident <id>` · `ack <id> [note]` · `close <id> [note]` · `reopen <id>` · `export <id>` |
| Configure | `setup` (wizard) · `config show [prefix]` · `config set <key> <value>` · `config reset <key>` · `config keys` |
| Decoys | `decoys` · `decoys enable\|disable ssh\|mysql\|http` · `persona list` · `persona rotate [name]` |
| Bait & scanners | `honeytokens [add\|remove <user>]` · `scanners [allow\|remove <ip/range>]` |
| Alerts | `alerts` · `alerts webhook <url\|off>` · `alerts level <low\|medium\|high>` · `alerts email <field> <value>` · `alerts test` |
| Operate | `isolation` · `actions` · `audit` · `help [command]` |

Tab completes commands, setting keys, sensor and persona names; ↑/↓ recalls history; Ctrl+C cancels a prompt; Ctrl+L clears.

## Local development

```bash
cd console
PN_CONSOLE_DEV=1 uvicorn app:app --port 18900    # in-memory accounts and data
```
To point a local Docker sensor at a dev console over plain HTTP, set
`PN_CLOUD_ALLOW_INSECURE=1` in the sensor's `.env` — **never in production**.
