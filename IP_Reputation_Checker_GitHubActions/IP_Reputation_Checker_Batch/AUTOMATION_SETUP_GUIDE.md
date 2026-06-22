# Automated Hourly Check + Email Reports - Setup Guide
### (Render.com + GitHub Actions edition - no PC/server needs to stay on)

## What changed from the old design

Earlier, this app used an in-process background scheduler that needed
the app running continuously to fire every hour. That doesn't work
well on free hosting (the process sleeps when idle) and definitely
doesn't work if you have to leave your own PC on 24/7.

**Current design:** the app exposes one URL - `/run-scheduled-check` -
that does the hourly check (and the missed-check watchdog check)
whenever it's *called*. A **GitHub Actions scheduled workflow** - which
runs on GitHub's own infrastructure, not your computer - calls that URL
once an hour. The HTTP request itself wakes up your sleeping free-tier
app and triggers everything. Nothing needs to stay running in between
calls, and nothing needs setting up outside of GitHub and Render -
both of which you're already using to deploy this project.

```
GitHub Actions (free, scheduled workflow, runs every hour)
        |
        v  curl https://your-app.onrender.com/run-scheduled-check?token=...
Render free web service (asleep until called, wakes on request)
        |
        v
Checks uploads/IP.txt -> emails blocked report -> goes back to sleep
```

**A note on timing:** GitHub does not guarantee scheduled workflows run
at the exact minute requested - their own docs warn that runs can be
delayed, especially when GitHub's infrastructure is under heavy load
across all of GitHub. In practice this usually means a few minutes of
slack, occasionally more. This project's `MISSED_CHECK_GRACE_MINUTES`
is set to 30 (not 10) specifically to absorb that without firing false
"missed check" alerts on a perfectly normal GitHub delay.

---

## Part A - One-time email setup

You need a Gmail "App Password" (not your normal Gmail password).

1. Go to https://myaccount.google.com/security and turn on
   **2-Step Verification** if it isn't already on.
2. Go to https://myaccount.google.com/apppasswords
3. App: **Mail**, Device: **Other** (name it `IP Checker`), click
   **Generate**.
4. Copy the 16-character password **without spaces**, e.g.
   `abcd efgh ijkl mnop` -> `abcdefghijklmnop`.

Keep this somewhere safe - you'll paste it into Render's dashboard in
Part C, not into any file you push to GitHub.

---

## Part B - Put the project on GitHub

Both Render (Part C) and the scheduled trigger (Part D) need this
project on GitHub.

1. Create a new repository on https://github.com (can be private).
2. From inside the project folder on your computer:
   ```bash
   git init
   git add .
   git commit -m "IP Reputation Checker with automated hourly check"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
   git push -u origin main
   ```

**Important:** `.gitignore` already excludes your real `.env` file, so
your Gmail password and secret token will NOT be uploaded to GitHub.
Only `.env.example` (placeholders only) gets committed. Real values go
into Render's dashboard (Part C) and GitHub's own secrets storage
(Part D) instead - never into a file in the repo itself.

The workflow file that makes the hourly trigger happen
(`.github/workflows/hourly-check.yml`) is already included in this
project, so once you push, it's already in place - you just need to
add two secrets for it to use (Part D).

---

## Part C - Deploy to Render

1. Go to https://render.com and sign up (free, no credit card needed
   for the free tier).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub account and select the repository you just
   pushed.
4. Render should auto-detect the included `render.yaml` and pre-fill:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Plan:** Free
   If it doesn't auto-detect, enter those two commands manually and
   pick the **Free** instance type.
5. Before clicking "Create Web Service", scroll to **Environment
   Variables** and add these (Render will have stubbed them out from
   `render.yaml` - click each one and fill in the real value):

   | Key | Value |
   |---|---|
   | `MAIL_SENDER` | your Gmail address |
   | `MAIL_APP_PASSWORD` | the 16-character App Password from Part A |
   | `MAIL_RECIPIENT` | where you want reports sent (can be same as above) |
   | `SMTP_SERVER` | `smtp.gmail.com` (pre-filled) |
   | `SMTP_PORT` | `587` (pre-filled) |
   | `CHECK_INTERVAL_MINUTES` | `60` (pre-filled) |
   | `MISSED_CHECK_GRACE_MINUTES` | `30` (pre-filled) |
   | `SCHEDULED_CHECK_TOKEN` | a long random string - generate one with the command below |

   To generate a good random token, run this on your own computer and
   paste the output:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(24))"
   ```
   Keep a copy of this exact value - you'll need to paste it again as
   a GitHub secret in Part D.

6. Click **Create Web Service**. Render will build and deploy - this
   takes a few minutes the first time. When it's done, you'll get a
   URL like:
   ```
   https://ip-reputation-checker-xxxx.onrender.com
   ```
7. Open that URL in your browser to confirm the site loads normally
   (single-IP search, etc. should all work exactly as before).

**About the free tier sleeping:** Render's free web services spin down
after about 15 minutes of no traffic, and take roughly 30-60 seconds to
wake back up on the next request. This is fine here - GitHub Actions'
hourly call wakes it, runs the check, and it goes back to sleep
afterward. (If a person visits your site right as it's asleep, they'll
just see a short delay on that first page load - normal Render free
tier behavior, not a bug in this app.)

---

## Part D - Set up the GitHub Actions schedule

The workflow file is already in the repo at
`.github/workflows/hourly-check.yml`. It needs two secrets to know
where to call and what token to send.

1. In your GitHub repository, go to **Settings** -> **Secrets and
   variables** -> **Actions**.
2. Click **New repository secret** and add:

   | Name | Value |
   |---|---|
   | `APP_URL` | your Render URL, no trailing slash, e.g. `https://ip-reputation-checker-xxxx.onrender.com` |
   | `SCHEDULED_CHECK_TOKEN` | the exact same random token you put in Render's `SCHEDULED_CHECK_TOKEN` environment variable in Part C |

3. That's it. Once both secrets exist and the workflow file is on your
   default branch (`main`), GitHub will start running it automatically
   on the schedule defined in the file (every hour, on the hour, UTC).

**To test immediately rather than waiting for the next hour:**
1. Go to the **Actions** tab of your repository.
2. Click **Hourly IP Reputation Check** in the left sidebar.
3. Click **Run workflow** (this works because the workflow file
   includes a `workflow_dispatch` trigger for manual runs).
4. Click the run that appears to watch its progress and see the
   output (HTTP status code and the JSON response from your app).

**Want a different time zone or interval?** GitHub Actions cron
schedules are always in UTC. Edit the `cron: "0 * * * *"` line in
`.github/workflows/hourly-check.yml` if you want a different cadence -
for example `"0 */2 * * *"` for every 2 hours. If you change the
interval, also update `CHECK_INTERVAL_MINUTES` in Render's environment
variables to match, so the missed-check math stays accurate.

---

## Part E - Confirm it's working

**Check the GitHub Actions run log:** Actions tab -> Hourly IP
Reputation Check -> click any run -> click the "Call
/run-scheduled-check" step to expand it. A successful run looks like:
```
HTTP status: 200
Response body:
{
  "check_ran": true,
  "check_message": "Checked 7 IP(s), 1 blocked. Email: Email sent successfully.",
  "watchdog_message": "OK - last successful run was 0 min ago (threshold 90 min).",
  "timestamp": "2026-06-22T05:00:03"
}
```
If the HTTP status isn't 200, the workflow step itself fails and shows
a red X in the Actions tab - so you'll see a failure at a glance
without needing to read the response body every time.

**Check your inbox** (`MAIL_RECIPIENT`) for the hourly report email -
also check spam the first couple of times.

**Check the homepage status panel** - reload your Render URL and look
for the "Automated Hourly Check" box; "Last successful run" should
update each time the workflow fires.

**Turn on GitHub's own failure notifications (recommended):** by
default, GitHub emails the repository owner automatically when a
scheduled workflow run fails. Make sure email notifications are
enabled for your GitHub account under
https://github.com/settings/notifications - this gives you a second,
independent signal if the workflow itself can't reach your app at all
(as opposed to the app's own missed-check alert, which can only fire
from inside a successful request).

---

## What the emails look like

### Hourly report (always sent, every run)
**Subject:** `IP Reputation Checker - Hourly Report (2026-06-22 14:00)`
```
Automated IP Reputation Check
Run time: 2026-06-22 14:00
IPs checked: 7
IPs with at least one Blocked vendor: 2

2 of 7 IP(s) were flagged as Blocked by at least one vendor this run.

Full per-vendor blocked details are attached as a CSV.
```
(CSV attached, same columns as the "Download Blocked Report" button.)

### Missed-check alert (only if something's wrong)
**Subject:** `ALERT: IP Reputation Checker - Hourly Check Missed`
```
The automated hourly IP check has NOT run successfully on schedule.

Last successful run: 2026-06-22 13:00
Time since last successful run: 95 minute(s)

Please check that the application is still running and that the
network/API keys are working correctly.
```
This fires if no successful run has happened within
`CHECK_INTERVAL_MINUTES + MISSED_CHECK_GRACE_MINUTES` (60 + 30 = 90
minutes by default). It sends **once** per missed gap, not repeatedly.

**Important nuance with this design:** the alert email is sent *by
your app*, which means it can only fire the next time a request
successfully reaches `/run-scheduled-check`. If GitHub Actions itself
stops running the workflow entirely (rather than the call failing) -
say, the workflow got manually disabled, or GitHub automatically
disables scheduled workflows after **60 days with no commits** to the
repository (a real, documented GitHub behavior - and forked
repositories have scheduled workflows disabled by default from the
start) - nothing will trigger the watchdog check from the app's side
at all. This is exactly why turning on GitHub's own failure
notification email (end of Part E) matters as a second, independent
layer - it doesn't depend on your app being reachable to warn you. If
you expect long stretches without touching this repo, push even a
trivial commit (e.g. a comment tweak) every month or two to keep
scheduled runs active.

---

## Troubleshooting

**Render free tier "spun down" / first request after idle is slow:**
Normal - free instances sleep after about 15 minutes idle and take
under a minute to wake. The GitHub Actions call still works, just with
that one-time delay - `curl` in the workflow will simply wait for the
response.

**GitHub Actions run shows a 403 in the response body:**
Your token doesn't match. Double check the `SCHEDULED_CHECK_TOKEN`
secret in GitHub matches exactly (no extra spaces, no quotes) the
`SCHEDULED_CHECK_TOKEN` environment variable in Render.

**Workflow run fails with a curl/connection error rather than a 403:**
Check `APP_URL` in GitHub secrets - it should be your bare Render URL
with no trailing slash and no `/run-scheduled-check` already appended
(the workflow file adds that part itself).

**"SMTP authentication failed" in the response body:**
`MAIL_APP_PASSWORD` in Render must be the 16-character Gmail App
Password, not your normal Gmail login password, and 2-Step
Verification must be enabled on that Google account.

**Scheduled workflow hasn't run in a long time / repo seems inactive:**
GitHub automatically disables scheduled workflows on a repository
after 60 days with no commits pushed at all - GitHub will email you a
warning before this happens. If it does happen, go to the Actions tab,
open the workflow, and click "Enable workflow" - or simply push any
small commit to reset the clock. Note that if you ever fork this repo
into a new one, scheduled workflows start out disabled by default on
the fork and need enabling manually.

**Changed an environment variable in Render but nothing changed:**
Render redeploys automatically when you save environment variable
changes - wait for the deploy to finish (a minute or two), then
manually trigger the GitHub Actions workflow (`workflow_dispatch`) to
test against the new values right away.

**I want to test locally before deploying:**
Fill in your local `.env` file with real values, run `python app.py`,
then visit:
```
http://127.0.0.1:5000/run-scheduled-check?token=YOUR_TOKEN
```
in your browser to trigger it manually and see the JSON response.

---

## Files involved in this feature

| File | Purpose |
|---|---|
| `services/mailer.py` | Sends the two email types via Gmail SMTP. |
| `services/scheduled_check.py` | Runs the hourly check + watchdog logic; called by the route below, not by a background thread. |
| `app.py` -> `/run-scheduled-check` route | The HTTP endpoint GitHub Actions calls. Token-protected. |
| `.github/workflows/hourly-check.yml` | The GitHub Actions scheduled workflow that calls the endpoint every hour. |
| `.env` / `.env.example` | Email credentials, timing settings, and the secret token (local copy only, never pushed to GitHub). |
| `render.yaml` | Tells Render how to build/run the app and what environment variables to expect. |
| `requirements.txt` | Includes `gunicorn` (production server Render uses) and `python-dotenv`. |
| `templates/index.html` | Small "Automated Hourly Check" status box (last run / next expected run). |

Nothing about the existing single-IP search, batch-from-file button,
vendor-details page, or manual CSV downloads was changed in behavior -
they all work exactly as before, just now also deployable to Render
with a GitHub-Actions-driven hourly check.
