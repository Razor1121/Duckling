# Anti-Phishing Discord Bot

## Overview

This Discord bot is designed to help keep servers safe from phishing links and malicious messages while also providing useful moderation and support tools. It automatically scans messages for suspicious links using an advanced phishing detection algorithm and can take action to prevent harmful content from spreading.

In addition to phishing protection, the bot includes basic moderation commands and an in-server button-based ticket system so users can easily contact server staff for help.

---

## Features

### Advanced Phishing Detection

The bot monitors messages for potentially dangerous links. When a suspicious or known phishing link is detected, the bot can automatically:

* Delete the message
* Warn or mute the user
* Alert moderators
* Log the event for review

The detection system analyzes link structure, domain reputation, and common phishing patterns to reduce false positives while maintaining strong protection.

---

### Moderation Commands

The bot includes several basic moderation tools to help staff manage the server:

* `prefix = "="`
* `ban` – Ban a user from the server
* `kick` – Kick a user from the server
* `timeout` – Temporarily mute a user
* `warn` – Issue a warning to a user
* `clear` – Bulk delete messages from a channel
* `help` - Lists every command currently accessible with the bot
* `add_link` - Allow users to submit a phishing link/domain so the bot will auto-detect it in future messages
* `ticketpanel` - Staff command to post the ticket panel with a **Create Ticket** button

These commands help moderators quickly respond to rule violations.

---

### Ticket System

Users can create support tickets in-server using buttons and a modal. The flow is:

1. Staff posts the ticket panel using `=ticketpanel`.
2. A user presses **Create Ticket**.
3. The user submits a **title** and **description** in a modal.
4. The bot creates a temporary private ticket channel.
5. The user is locked from sending messages until staff opens the ticket.
6. A staff member with the configured staff role can press **Open Ticket**.
7. Staff can press **Close Ticket** to delete the temporary ticket channel.

This system allows users to privately report issues, ask questions, or request assistance in a controlled ticket workflow.

---

## How It Works

1. The bot listens to messages sent in the server.
2. Links are analyzed by the phishing detection system.
3. Suspicious messages are flagged or removed automatically.
4. Moderators can use commands to manage users and server activity.
5. Users can open support tickets through the in-server ticket panel.

---

## Purpose

The goal of this bot is to create a safer Discord environment by combining automated phishing protection with essential moderation tools and a simple support system.

---

## Disclaimer

The code is not bulletproof, however it does have a decent list of regexes and other random websites that it will catch.

## Setup Notes

1. Install Python dependencies from `requirements.txt`.

The bot scans message text for links and suspicious patterns. Image attachments are not scanned.