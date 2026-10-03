# Think Twice 💬

**Spot scam messages before they cost you.**

Think Twice checks suspicious texts, WhatsApp messages and emails for the tricks scammers use most. It underlines every red flag in the message and explains why it matters, in plain language anyone can understand.

🔗 **Live demo:** [ADD YOUR VERCEL LINK HERE]

Built for **WarriorHacks 2.0** — theme: solve an issue in your community.

## The problem

Scam messages are everywhere: fake delivery notices, bank alerts, "your power will be cut off tonight" threats, and "Hi Mom, this is my new number" texts. They're designed to cause panic, and they work best on people who are less familiar with technology, especially older adults. The warning signs are usually right there in the message. People just don't know what to look for.

Think Twice doesn't just say "scam" or "safe." It teaches people to spot the red flags themselves.

## Features

- **Marked-up message:** paste any message and see each red flag underlined and numbered, color-coded by type. Tap one to learn why it's a warning sign.
- **Risk gauge:** a clear verdict: *No red flags found*, *Be careful*, or *Likely a scam*.
- **How a scam is built:** shows which of the three parts of a typical scam the message uses: **Bait → Pressure → Request**.
- **Score breakdown:** shows exactly which flags raised the risk score, so the result is never a black box.
- **What to do now:** next steps that change based on what was found (for example, what to do if you already shared a code).
- **Send to family:** shares the result through your phone's share menu, or copies it to paste into a message.
- **Practice mode:** decide if a message is a scam, tap the words that gave it away, then see which red flags you found and missed.
- **Accessible by design:** three text sizes, keyboard navigation, dark mode, and the Atkinson Hyperlegible font, designed by the Braille Institute for low-vision readers.

## Privacy

Think Twice runs entirely in your browser. **Nothing you paste is sent anywhere.** There's no server, no account and no tracking, and it works offline.

## How it works

Think Twice uses transparent detection rules instead of a black-box model, so every warning comes with a reason. Each rule belongs to one stage of the scam pattern:

| Stage | Examples of what it detects |
|---|---|
| **Bait** | Prizes, "new number" family stories, fake account problems, parcel problems, easy-money jobs |
| **Pressure** | Deadlines, threats of disconnection or arrest, requests for secrecy |
| **Request** | Asking for codes or PINs, money or gift cards, calling a number, installing remote-control apps |
| **Disguise** | Lookalike links (e.g. `usps-redelivery.top` instead of `usps.com`), shortened links, unusual web address endings, generic greetings |

Each flag has a weight. The risk score combines them with diminishing returns:
