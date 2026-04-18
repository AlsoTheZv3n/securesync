# SecureSync — Design System
> NEXO AI | UI/UX Design Specification

---

## Brand Identity

### Logo & Name
- Product: **SecureSync**
- By: **NEXO AI**
- Tagline: *Automated Security Intelligence for MSPs*
- Logo: Angular/geometric — cybersecurity meets modern SaaS

### Tone of Voice
- Professional but not sterile
- Technical depth, human clarity
- Data-first: everything backed by numbers
- Reassuring when things are good, urgent when they're not

---

## Colour System

### Base Palette (Dark Theme — Primary)
```
Background:         #0A0E1A    (deep navy black)
Surface:            #111827    (card backgrounds)
Surface Elevated:   #1C2333    (modals, dropdowns)
Border:             #2A3441    (subtle separators)
Text Primary:       #F0F4FF    (almost white, slightly blue-tinted)
Text Secondary:     #8B9CB6    (muted labels)
Text Muted:         #4A5568    (disabled, placeholders)
```

### Brand Accent
```
Primary:            #3B82F6    (electric blue — NEXO AI brand)
Primary Hover:      #2563EB
Primary Glow:       rgba(59,130,246,0.15)
```

### Semantic Colours (Security Rating)
```
Grade A:   #10B981    (emerald green — excellent)
Grade B:   #84CC16    (lime green — good)
Grade C:   #F59E0B    (amber — acceptable)
Grade D:   #F97316    (orange — poor)
Grade E:   #EF4444    (red — critical risk)
Grade F:   #7F1D1D    (dark red — severe / failing)
```

### Severity Colours (CVE/Findings)
```
Critical:  #FF2D55    (bright red)
High:      #FF6B35    (orange-red)
Medium:    #FFB800    (amber)
Low:       #3B82F6    (blue — informational)
Info:      #64748B    (slate — background noise)
```

### Light Theme (Customer Portal / Reports)
```
Background:         #F8FAFC
Surface:            #FFFFFF
Border:             #E2E8F0
Text Primary:       #0F172A
Text Secondary:     #64748B
Primary:            #2563EB
```

---

## Typography

```
Font Family:   'Inter', -apple-system, BlinkMacSystemFont, sans-serif
Code/Mono:     'JetBrains Mono', 'Fira Code', monospace

Scale:
  xs:    0.75rem  / 12px   (labels, badges)
  sm:    0.875rem / 14px   (body small, table cells)
  base:  1rem     / 16px   (body default)
  lg:    1.125rem / 18px   (body large)
  xl:    1.25rem  / 20px   (section headers)
  2xl:   1.5rem   / 24px   (card titles)
  3xl:   1.875rem / 30px   (page headers)
  4xl:   2.25rem  / 36px   (hero / rating display)

Weight:
  Regular:   400
  Medium:    500
  Semibold:  600
  Bold:      700
```

---

## Component Specifications

### Security Rating Badge (A–F)
```
Shape:     Circle with inner ring (gauge-style)
Size:      120px × 120px (dashboard), 48px × 48px (table)
Font:      72px bold, centered (large version)
Animation: Ring fills clockwise based on score (0–100%)
A = 100% fill (green), F = 10% fill (dark red)

States:
  A (90-100): ring #10B981, fill-glow rgba(16,185,129,0.1)
  B (75-89):  ring #84CC16
  C (60-74):  ring #F59E0B
  D (45-59):  ring #F97316
  E (25-44):  ring #EF4444
  F (0-24):   ring #7F1D1D, pulsing red glow
```

### House Analogy Component
```
Visual: SVG of a house illustration
Clickable regions, each mapped to a security category:

  Front Door    → Password & Access Policy
  Roof          → Email Security (SPF/DMARC)
  Windows       → Network Exposure / Open Ports
  Foundation    → Patch Management
  Chimney       → Firewall
  Garden Gate   → External Perimeter / Web App
  Mailbox       → Credential Breach Exposure

State colours:
  Good (A/B):   element tinted green
  Warning (C):  element tinted amber
  Bad (D/E/F):  element tinted red, cracked/broken texture overlay

Tooltip on hover: category name + score + 1-line description
```

### Findings Table
```
Columns:
  [severity badge] | CVE ID | Title | Asset | CVSS | EPSS% | Status | Age

Row hover: subtle #1C2333 background
Click: slide-in panel from right (detail view)

Severity badge:
  Pill shape, 6px border-radius
  Background: 10% opacity of severity colour
  Text: severity colour at full opacity
  Icon: ⬆ critical, ↑ high, → medium, ↓ low

EPSS column: progress bar (0–100%) in red-to-green gradient
```

### Scan Progress Card
```
Layout:     Card with left border (4px, primary blue)
Header:     Scan type icon + target + timestamp
Progress:   Multi-step stepper (Queued → Running → Enriching → Complete)
            Each scanner shown with individual spinner/checkmark
Footer:     ETA countdown or "Completed in Xm Ys"
```

### Trend Graph
```
Library:    Recharts LineChart
X-axis:     Scan dates (last 12 scans)
Y-axis:     Score 0–100 (or A–F converted)
Line:       Smooth curve, gradient fill below
Color:      Dynamically matched to current grade colour
Annotation: Dots at each data point, tooltip on hover
Grid:       Subtle #2A3441 lines
```

---

## Layout

### Sidebar Navigation
```
Width:       240px (expanded) / 64px (collapsed)
Background:  #111827
Logo:        Top, 24px padding

Navigation items:
  Overview          (grid icon)
  Customers         (users icon)
  Scans             (scan icon)
  Findings          (shield-alert icon)
  Reports           (file-text icon)
  ─────────────────
  Integrations      (plug icon)
  Settings          (settings icon)

Active state: left border 3px primary blue, background #1C2333
Hover state:  background #1A2235

Bottom: user avatar + name + role + logout
```

### Dashboard Grid
```
Row 1:  [Total Customers] [Avg. Rating] [Open Critical] [Scans This Month]
        4 KPI cards, equal width

Row 2:  [Customer Rating Overview — Table]    [Rating Distribution — Donut Chart]
        70% / 30% split

Row 3:  [Recent Scan Activity — Timeline]     [Top Vulnerabilities — Bar Chart]
        50% / 50% split
```

### Customer Detail View
```
Header:   Customer name + rating badge + last scan date + "Run Scan" button
Tabs:     Overview | Findings | Scans | Reports | Settings | Agent Status

Overview tab:
  [House Analogy]              [Category Breakdown — horizontal bar chart]
  [Trend Graph — rating history]
  [Top 5 Critical Findings — compact list]
```

---

## PDF Report Design

### Executive Report (Customer-facing)
```
Page 1:  Cover page
         - Customer logo (if uploaded) + NEXO AI branding
         - Report title: "IT Security Assessment — [Month Year]"
         - Customer name, date, generated by

Page 2:  Rating Summary
         - Large A–F badge (centered)
         - Previous rating comparison ("Improved from D to C")
         - 6-category breakdown (horizontal bar chart)

Page 3:  House Analogy (full page, SVG export)

Page 4:  Top Findings (max 10)
         - Each finding: title, severity badge, asset, 2-line description
         - No deep technical details

Page 5:  Recommendations
         - Top 3–5 action items in plain language
         - "What to do next" format

Page 6:  Trend Graph
         - Rating history over last 6 scans

Cover footer: "Confidential — Prepared by [MSP Name] via NEXO AI SecureSync"
```

### Technical Report (MSP internal)
```
Full CVE list with: CVE ID, CVSS vector, EPSS score, evidence, remediation steps
Asset-by-asset breakdown
Appendix: raw scan metadata
```

---

## Responsive Breakpoints

```
Mobile:   < 768px   (customer portal read-only, reports viewing)
Tablet:   768–1024px (condensed sidebar, stacked cards)
Desktop:  > 1024px  (full layout — primary target)
Wide:     > 1440px  (expanded data tables)
```

Primary users (MSP technicians) are on desktop. Mobile is secondary (customer portal only).

---

## Iconography

Library: **Lucide Icons** (consistent with shadcn/ui)

Key icons used:
```
Shield           → Security / Overview
ShieldAlert      → Findings / Vulnerabilities
ShieldCheck      → Resolved / Compliant
ScanLine         → Scan / Network scan
Globe            → External target
Monitor          → Internal endpoint / Agent
FileText         → Reports
Users            → Customers / Tenants
Activity         → Trend / Live status
AlertTriangle    → Warning / D/E rating
XCircle          → Critical / F rating
CheckCircle      → Resolved / A rating
Clock            → Scheduled scan
Plug             → Integrations
Settings         → Configuration
```

---

## Animations & Interactions

```
Page transitions:    Fade + slide (100ms, ease-out)
Card hover:          Subtle elevation shadow increase
Rating gauge:        On load: animates fill from 0 to final value (600ms ease)
Scan progress:       Pulsing dot on active scanner step
House analogy:       Hover regions glow/highlight on hover
New finding alert:   Toast notification (top-right, 4s auto-dismiss)
Sidebar collapse:    Smooth width transition (200ms)
Table row expand:    Accordion slide-down (150ms)
```

---

## White-Label Customisation

Tenants can override:
```css
--color-primary: [hex]          /* replaces #3B82F6 */
--color-primary-hover: [hex]
--logo-url: [uploaded image]
--tenant-name: [string]
```

PDF reports additionally support:
- Custom header/footer text
- Custom cover page colour
- Custom sender email domain (requires DNS verification)
