# Project Vision & Scope: Radio Ink

Radio Ink is open-source firmware for the Xteink X3 / X4. It started life as a fork of CrossPoint Reader — a
single-purpose e-reader — and has since grown into a **reader plus a field toolkit**: the reading experience is still
the centre of the device, but the radio, the RTC, the SD card, and the screen are all treated as things worth using.

## 1. Core Mission

To provide a lightweight, high-performance firmware that maximises what an ESP32-C3 with an e-ink panel can do, without
compromising stability. Reading comes first. Everything else earns its place by being genuinely useful in the hand and
cheap in RAM.

## 2. Scope

### In-Scope — Reading

*The original mission, unchanged.*

* **User Experience:** User-friendly interfaces and interactions, both inside the reader and navigating the firmware —
  button mapping, book loading, bookmarks, and navigation.
* **Document Rendering:** Rendering documents (primarily EPUB) and improvements to the rendering engine.
* **Format Optimization:** Efficiently parsing EPUB (CSS/Images) and other documents within the device's capabilities.
* **Typography & Legibility:** Custom font support, hyphenation engines, and adjustable line spacing.
* **E-Ink Driver Refinement:** Reducing full-screen flashes (ghosting management) and improving general rendering.
* **Library Management:** Simple, intuitive ways to organize and navigate a collection of books.
* **Local Transfer:** "Pull" based book loading via a basic web-server or public, widely-used standards (OPDS, WebDAV,
  KOReader sync).
* **Language Support:** Multiple languages in both the reader and the interfaces, via the `tr()` i18n system.
* **Reference Tools:** Local dictionary lookup — quick, offline definitions that enhance comprehension without breaking
  focus.

### In-Scope — Tools

*Small, self-contained utilities that fit a button-driven e-ink device and cost little RAM. These live under
Home → Tools and each one is a single Activity.*

* **Text & Notes:** Notepad (notes and checklists, with Wi-Fi sync).
* **Time:** Clock, stopwatch, timer, and Calendar, backed by the RTC where the device has one.
* **Security & Encoding:** Authenticator (TOTP), Password Generator, Hash Calculator, Encode/Decode.
* **Utility:** Calculator, QR Generator, Badge.
* **Study:** Flashcards with spaced repetition, reading decks from the SD card.

The bar for a new tool: it must work with four buttons and a slow monochrome refresh, hold its state in a bounded
amount of RAM, and be something you would actually reach for while holding this device rather than your phone.

### In-Scope — Reading From the Network

*Pull-based, user-initiated fetches that end in text on the SD card.*

* **Read Later:** Fetch a URL, strip it to readable text, and save it for offline reading.
* **News / RSS:** Subscribe to feeds, pull headlines on demand, and open an item as an article.

The rule that keeps this from becoming a web browser: **no background Wi-Fi, no polling, no rendering the live web.**
The radio comes up when the user asks for it, does one job, writes text to SD, and goes back off. What you end up with
is a file you read in the reader — the same as any other book.

### In-Scope — Radio Audit

*The pentest / RF-audit suite, under its own top-level menu.*

* **Passive by default.** Scanning, enumeration, detection, and reporting ship in release builds.
* **Active features are gated twice:** behind the `RADIO_AUDIT_ENABLE_ACTIVE` build flag (off in `gh_release`) *and* a
  per-session on-device authorization prompt. Transmitting attacks are for authorized testing only.

### Out-of-Scope

*These are rejected because they compromise the device's stability, its battery, or its mission.*

* **Background Connectivity:** No always-on Wi-Fi, no polling daemons, no push notifications. Every network action is
  started by the user and torn down when it finishes.
* **Live Web Browsing:** No HTML rendering engine, no JavaScript, no interactive web pages. Fetching a page and
  reducing it to text is in scope; being a browser is not.
* **Media Playback:** No audio players or audio-books — the hardware has no audio path. (The Movies flipbook player is
  a deliberate novelty, not a media stack.)
* **Games:** Nothing that turns the device into a console. A study tool that happens to be interactive is fine; an
  arcade is not.
* **Anything that destabilises reading:** If a feature adds meaningful RAM pressure, fragments the heap, or risks the
  reader's stability, it does not ship regardless of how interesting it is.

### In-scope — Technically Unsupported

*These features align with Radio Ink's goals but are impractical on the current hardware or produce poor UX.*

* **PDF Rendering:** PDFs are fixed-layout, so rendering them means displaying pages as images rather than reflowable
  text — constant panning and zooming, which is a poor reading experience on e-ink.
* **Sub-GHz / NFC / IR:** The X3 and X4 carry no CC1101, NRF24, or IR hardware, and the X3's NFC controller is
  currently unidentified. These stay stubs until the hardware is confirmed.
* **GPS Wardriving:** WiGLE export exists, but with no GPS receiver the coordinates come from a user-supplied
  `location.txt` rather than a live fix.

## 3. Idea Evaluation

Radio Ink is a lightweight, reliable, performant e-reader that also happens to carry a good toolkit. New ideas are
weighed on three questions:

1. **Does it fit the hardware?** Four buttons, a slow monochrome panel, ~380 KB of RAM, no PSRAM, 2.4 GHz only.
2. **What does it cost?** Every new heap allocation, task, and kilobyte of flash is a real cost on this chip. A feature
   that fragments the heap or pushes flash toward the partition limit needs to justify itself.
3. **Would you use it here?** Not "is it cool" — would you reach for it on *this* device instead of the phone in your
   other pocket?

A feature that fails any of the three doesn't ship, however fun it is to build.

> **Note to Contributors:** If you are unsure whether your idea fits the scope, please open a **Discussion** before you
> start coding!
