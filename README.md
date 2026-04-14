# Anti-Phish Discord Bot

Anti-Phish Discord Bot helps protect and manage a Discord server by combining automated phishing detection with moderation, tickets, and lockdown controls.

## What The Bot Does

### Anti-phishing and account safety
- Detects suspicious links from message text using regex and heuristic scoring.
- Deletes malicious messages when detected.
- Detects Discord bot token patterns and removes exposed tokens from chat.
- Can auto-quarantine users when high-risk content is detected.
- Logs phishing events and moderation cases for staff review.

### Moderation tools
- Supports moderation actions such as ban, kick, timeout, and bulk message deletion.
- Maintains moderation case history and supports case lookup.
- Includes link checking and custom phishing-link pattern reporting.
- Lets staff send direct follow-up replies to users.

### In-server ticket system
- Posts a ticket panel where users can create support tickets using buttons.
- Collects ticket title and description through a modal form.
- Creates private ticket channels tied to ticket owners.
- Keeps tickets locked until staff opens them.
- Allows staff to open and close tickets from channel buttons.

### Server lockdown controls
- Can lock nearly all channels to a designated lockdown role.
- Creates a temporary status channel to explain active lockdowns.
- Allows staff to edit the lockdown notice message.
- Can unlock one channel at a time or unlock all channels at once.
- Restores original channel permission overwrites when unlocking.
- Skips Discord onboarding-required channels that must remain visible to everyone.

### Utility and engagement commands
- Includes quick utility commands for help and status checks.
- Includes trivia and small fun commands such as 8-ball, coin flip, dice roll, and rock-paper-scissors.

### Important behavior notes
- The phishing detector is heuristic-based and may occasionally produce false positives or false negatives.
- Link and token safety checks focus on message text content.
