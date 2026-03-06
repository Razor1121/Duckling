# Anti-Phishing Discord Bot

## Overview

This Discord bot is designed to help keep servers safe from phishing links and malicious messages while also providing useful moderation and support tools. It automatically scans messages for suspicious links using an advanced phishing detection algorithm and can take action to prevent harmful content from spreading.

In addition to phishing protection, the bot includes basic moderation commands and a DM-based ticket system so users can easily contact server staff for help.

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

These commands help moderators quickly respond to rule violations.

---

### DM Ticket System

Users can create support tickets by sending a direct message to the bot. When a ticket is created:

1. The bot forwards the message to a staff channel.
2. Staff members can reply through the bot.
3. The user receives the response directly in their DMs.

This system allows users to privately report issues, ask questions, or request assistance without needing a public channel.

---

## How It Works

1. The bot listens to messages sent in the server.
2. Links are analyzed by the phishing detection system.
3. Suspicious messages are flagged or removed automatically.
4. Moderators can use commands to manage users and server activity.
5. Users can open support tickets by messaging the bot directly.

---

## Purpose

The goal of this bot is to create a safer Discord environment by combining automated phishing protection with essential moderation tools and a simple support system.

---

## Disclaimer

The code is not bulletproof, however it does have a decent list of regexes and other random websites that it will catch.

## Advanced OCR and QR Phishing Detection

The bot now scans image attachments with an OCR + QR pipeline:

- Image preprocessing: denoise, contrast enhancement (CLAHE), thresholding, resize, and sharpening.
- OCR extraction: multi-pass text extraction using Tesseract.
- QR detection: OpenCV QR detector with `pyzbar` fallback decoding.
- URL extraction: detects direct and obfuscated links like `hxxps://` and `example[.]com`.
- Domain intelligence: checks extracted domains against known phishing-domain patterns.

If a malicious URL/domain is found in message text, OCR text, or decoded QR payloads, the bot removes the message and applies quarantine according to your existing moderation settings.

## Setup Notes

1. Install Python dependencies from `requirements.txt`.
2. Install Tesseract OCR on the host machine (required by `pytesseract`):
	- Windows: install Tesseract and ensure `tesseract.exe` is available in `PATH`.

Without Tesseract and the OCR dependencies, image scanning is skipped and only text-link scanning remains active.