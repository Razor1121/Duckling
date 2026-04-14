# Anti-Phish Discord Bot

Discord bot focused on phishing prevention, moderation utilities, in-server tickets, and server lockdown controls.

## Current Features

### 1) Anti-phishing detection
- Detects suspicious links from message text using regex and heuristic scoring.
- Deletes malicious messages when detected.
- Logs incidents to `malicious_links.log`.
- Stores moderation-style case records in `cases.json`.

### 2) Moderation and utility commands
- `=help`
- `=ping`
- `=ban <member> [reason]`
- `=kick <member> [reason]`
- `=timeout <member> <duration> [reason]`
- `=delete [amount]` (alias: `=clear`)
- `=cases [member]`
- `=reply <user_id> <message>`
- `=lastphish`
- `=check <text/link>` (owner-only)
- `=add_link <link>`

### 3) Ticket system
- `=ticketpanel` posts a panel with a **Create Ticket** button.
- User submits title + description in modal.
- Ticket starts locked for user messaging until staff presses **Open Ticket**.
- Staff can close with **Close Ticket**.

### 4) Lockdown system (new)
- `=lockall [message]`
	- Locks all channels to the configured lockdown role.
	- Creates/reuses a temporary `server-status` channel.
	- Posts a status embed message.
- `=editlockmsg <message>` (alias: `=lockmsg`)
	- Edits the lockdown message in the temporary status channel.
- `=unlock [channel_id]`
	- Unlocks a single channel and restores previous permission overwrites.
	- If `channel_id` is omitted, unlocks the current channel.
- `=unlockall`
	- Restores all channels locked by `=lockall`.
	- Deletes the temporary status channel.

## Public-Safe Configuration

Do not hardcode secrets or private IDs in source files. This project now reads runtime config from environment variables.

Required:
- `BOT_TOKEN` = your Discord bot token

Optional:
- `BOT_PREFIX` (default: `=`)
- `LOG_CHANNEL_ID` (default: `0`)
- `TICKET_CHANNEL_ID` (default: `0`)
- `TICKET_STAFF_ROLE_ID` (default: `0`)
- `LOCKDOWN_ROLE_ID` (default: value of `TICKET_STAFF_ROLE_ID`)
- `QUARANTINE_ROLE_ID` (default: `0`)

PowerShell example:

```powershell
$env:BOT_TOKEN="YOUR_TOKEN_HERE"
$env:TICKET_STAFF_ROLE_ID="123456789012345678"
$env:LOCKDOWN_ROLE_ID="123456789012345678"
python bot.py
```

## Setup

1. Install dependencies:

```powershell
pip install -r requirements.txt
```

2. Set environment variables (see above).

3. Run the bot:

```powershell
python bot.py
```

## Files Created At Runtime

- `cases.json`
- `trivia_scores.json`
- `custom_link_patterns.json`
- `lockdown_state.json`
- `malicious_links.log`

These files may contain server/user data and should not be committed to public repos.

## Notes

- The detector is heuristic-based and can produce false positives/false negatives.
- Scanning currently targets text content, not image OCR.