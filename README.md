# 💬 Think Twice

### 🛡️ Spot scam messages before they cost you.

Think Twice checks suspicious texts, WhatsApp messages and emails for the tricks scammers use most. It underlines every red flag in the message and explains why it matters, in plain language anyone can understand.

🔗 Live demo:https://think-twice-zeta.vercel.app/

## 📸 Screenshots
<img width="1520" height="877" alt="image" src="https://github.com/user-attachments/assets/b0f54db0-de6a-4529-b20d-54679bd4f031" />

<img width="1522" height="637" alt="Screenshot 2026-10-03 061624" src="https://github.com/user-attachments/assets/f77c3db4-64f0-40ae-af03-f313105cd245" />

<img width="1512" height="851" alt="image" src="https://github.com/user-attachments/assets/7c299901-ce57-4301-b8a9-b26f0fe73ecb" />


## 🚨 The problem

Scam messages are everywhere: 📦 fake delivery notices, 🏦 bank alerts, ⚡ "your power will be cut off tonight" threats, and 📱 "Hi Mom, this is my new number" texts. They're designed to cause panic, and they work best on people who are less familiar with technology, especially older adults 👵👴. The warning signs are usually right there in the message. People just don't know what to look for.

💡 Think Twice doesn't just say "scam" or "safe." It teaches people to spot the red flags themselves.

## ✨ Features

- 🖍️ **Marked-up message:** paste any message and see each red flag underlined and numbered, color-coded by type. Tap one to learn why it's a warning sign.
- 🎯 **Risk gauge:** a clear verdict: ✅ *No red flags found*, ⚠️ *Be careful*, or 🚫 *Likely a scam*.
- 🧩 **How a scam is built:** shows which of the three parts of a typical scam the message uses: 🎣 **Bait → ⏰ Pressure → 💸 Request**.
- 📊 **Score breakdown:** shows exactly which flags raised the risk score, so the result is never a black box.
- 📝 **What to do now:** next steps that change based on what was found (for example, what to do if you already shared a code).
- 👨‍👩‍👧 **Send to family:** shares the result through your phone's share menu, or copies it to paste into a message.
- 🎮 **Practice mode:** decide if a message is a scam, tap the words that gave it away, then see which red flags you found and missed.
- ♿ **Accessible by design:** 🔠 three text sizes, ⌨️ keyboard navigation, 🌙 dark mode, and the Atkinson Hyperlegible font, designed by the Braille Institute for low-vision readers.

## 🔒 Privacy

Think Twice runs entirely in your browser. **Nothing you paste is sent anywhere.** 🚫 No server, 🚫 no account, 🚫 no tracking, and ✈️ it works offline.

## ⚙️ How it works

Think Twice uses transparent detection rules instead of a black-box model, so every warning comes with a reason. Each rule belongs to one stage of the scam pattern:

| Stage | Examples of what it detects |
|---|---|
| 🎣 **Bait** | Prizes, "new number" family stories, fake account problems, parcel problems, easy-money jobs |
| ⏰ **Pressure** | Deadlines, threats of disconnection or arrest, requests for secrecy |
| 💸 **Request** | Asking for codes or PINs, money or gift cards, calling a number, installing remote-control apps |
| 🎭 **Disguise** | Lookalike links (e.g. `usps-redelivery.top` instead of `usps.com`), shortened links, unusual web address endings, generic greetings |

🧮 Each flag has a weight. The risk score combines them with diminishing returns:

```
risk = 1 − (1 − w₁)(1 − w₂)…(1 − wₙ)
```

So several weak signs add up, but no single weak sign decides the result. A message that combines ⏰ **pressure** with a 💸 **request** gets an extra flag, because that pairing is the core of almost every scam. 🛡️ Protective phrases like "never share this code" lower the score.

## 🚀 Run it locally

No installation needed. 📥 Download the repository and open `index.html` in any browser.

<div align="center">

**Built by Shambhavi **

MIT License

</div>

