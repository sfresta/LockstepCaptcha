# 🔐 LockstepCaptcha

**LockstepCaptcha** is a modern, self-hosted CAPTCHA for PHP that verifies human presence through **two independent, coordinated actions** (*lockstep*):  
1. **Cognitive understanding** — recognizing masked characters  
2. **Visual interaction** — clicking the icon that appears the fewest times

By combining reasoning and interaction in a single challenge, LockstepCaptcha significantly increases the cost of automation while keeping the experience simple and accessible for real users.

---

## ✨ Key Features

- 🧠 **Double challenge (lockstep)**  
  Requires both comprehension *and* interaction to succeed.

- 🖼️ **Single self-generated image**  
  The entire challenge is rendered server-side as one image. No external assets.

- 🔒 **Anti-tamper design**  
  Uses HMAC signatures and one-time tokens to prevent client-side manipulation.

- ⏱️ **Built-in bot defenses**  
  Includes TTL, minimum time-to-fill, honeypot fields, and per-challenge invalidation.

- 📉 **Rate limiting**  
  Designed to throttle repeated attempts and slow down brute-force automation.

- 📱 **Mobile-friendly**  
  Supports responsive layouts with correct click coordinate handling.

- 🔐 **Session hardening**  
  Strict session mode, HttpOnly cookies, and SameSite support.

- ⚙️ **Highly configurable**  
  Canvas size, difficulty, icon distribution, timing, and thresholds are adjustable.

---

## 🚫 No JavaScript Required

LockstepCaptcha **does not require JavaScript to function**.

The core challenge works entirely with standard HTML form submission and server-side validation.  
This makes it suitable for:

- environments with restricted or disabled JavaScript  
- privacy-focused applications  
- progressive enhancement strategies  
- email clients, embedded browsers, and legacy setups  

> Optional JavaScript may be used for UX improvements, but it is **not required** for security or correctness.

---

## 🎯 Design Goals

LockstepCaptcha is designed to block:

- commodity bots  
- simple headless automation  
- scripted form abuse  
- low-effort CAPTCHA bypasses  

It intentionally does **not** claim to be “AI-proof”.

Instead, it follows a **pragmatic, risk-based security model**:
> combine multiple weak signals into a strong, cost-effective barrier.

---

## 🧩 Typical Use Cases

- Contact forms  
- User registration and login  
- Comment systems  
- Abuse-prone endpoints  
- Self-hosted or offline environments  

---

## 📦 Technical Requirements

- PHP 8.0 or newer  
- GD extension enabled  
- No database required  
- No third-party services  
- No external APIs  

---

## ⚠️ Security Philosophy

LockstepCaptcha is meant to be part of a **defense-in-depth strategy**.

For high-risk environments, it is recommended to combine it with:
- IP reputation or ASN filtering  
- additional rate limiting  
- behavioral analysis  
- progressive challenge escalation  
