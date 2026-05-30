# F1–F7 Quick Reference Card

**Print this. Keep visible during session. No theory knowledge needed.**

---

## F1 — ECOSYSTEM TRAP

**Signal:** "We already use [Skybox/Prisma/Wiz/Ansible]"

**Definition:** ConfigGuard seen as extra tool, not replacement

**Look for:**
- Has incumbent tool
- Zero integration questions
- "Nice to have" language

**Decision:** Don't block GO. Note as constraint.

---

## F2 — WORKFLOW INERTIA

**Signal:** "I'd use it but our process..."

**Definition:** Individual wants it but org structure blocks

**Look for:**
- "We do manual approval"
- "Change window required"
- Mentions process, not product

**Decision:** CONDITIONAL GO. Org change needed.

---

## F3 — SILENT ADOPTER / REJECTION

**Signal:** Zero signals, zero verbatim, no complaints

**Definition:** Cannot classify without follow-up

**Look for:**
- H1 ≥ 3/4
- Zero adoption_signals
- No questions, no complaints

**Decision:** Don't count toward or against GO. Follow up 1 week later.

---

## F4 — METHODOLOGY DOUBT

**Signal:** 3+ questions about how risk is calculated

**Definition:** Skeptic — won't trust without proof

**Look for:**
- "How was this calculated?"
- "What data trained this?"
- "Can I see the evidence chain?"
- TCT = OVERRIDE

**Decision:** CONDITIONAL if user willing to wait for evidence.

---

## F5 — COMPLIANCE MISMATCH

**Signal:** Auditor + "need control mapping"

**Definition:** Output doesn't map to control framework

**Look for:**
- User type: Security Auditor
- "Does this map to CIS-2.4?"
- TCT = ESCALATE or DEFER

**Decision:** Try B-auditor material first. If still failing, CONDITIONAL.

---

## F6 — FEATURE EXTRACTION

**Signal:** One feature interest, ignores rest

**Definition:** Likes single command, will extract and leave

**Look for:**
- Only "explain" command mentioned
- No CI/CD questions
- No other features asked about

**Decision:** Note as fragile adoption. Bundle features later.

---

## F7 — POLITICAL BUY-IN

**Signal:** "Need to check with manager"

**Definition:** Individual wants but manager/policy blocks

**Look for:**
- warning_3_needs_team = true
- Has incumbent
- "Manager wants..."
- "Policy requires..."

**Decision:** CONDITIONAL GO. Target power user, not individual.

---

## DRIFT — When F1–F7 Fails

**Don't force-fit. Use DRIFT to detect taxonomy failure.**

**D0:** Behavior doesn't fit any F → Log verbatim, mark D0
**D1:** Multiple F's apply → Note all, primary = highest confidence
**D2:** User mentions time condition → Mark D2, re-assess at follow-up
**D4:** Skeptic but pipeline interest → Possible false negative
**D5:** Verbal yes, no workflow signal → Possible false positive

**Rule:** DRIFT > 40% of sessions = taxonomy insufficient, STOP

---

## DRIFT Validator Checklist (2 min)

```
□ Does behavior fit F cleanly?
  → Yes: F-type = [F#]
  → No: DRIFT = D0

□ Multiple F-types?
  → No: Proceed
  → Yes: DRIFT = D1, note all

□ User mentions time?
  → No: Proceed
  → Yes: DRIFT = D2

□ Behavior contradicts F?
  → No: Proceed
  → Yes: DRIFT = D4 or D5

□ DRIFT: [YES/NO]
□ Taxonomy trust: [HIGH/MEDIUM/LOW]
```