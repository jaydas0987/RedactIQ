# RedactIQ

Offline PII redaction tool for Indian compliance documents. Supports three redaction modes across six file types. Built for air-gapped environments — no data leaves your machine.

Regex operations form the first and most reliable detection layer. Each PII type has a hand-crafted pattern tuned for Indian data formats — Aadhaar's XXXX XXXX XXXX spacing, PAN's AAAAA9999A structure, Indian mobile numbers with and without the +91 prefix, and so on. Rules fire in a fixed order to prevent one pattern consuming digits that belong to another — credit card numbers are matched before Aadhaar for exactly this reason. When a match is found, its position in the text is recorded as a span and passed to the replacement stage.
spaCy NER runs after regex and catches names and locations that don't follow a predictable pattern. The en_core_web_sm model reads each sentence and labels entities — PERSON, GPE, ORG and so on. Anything labelled PERSON is treated as a name and routed through the PseudonymVault. This catches names that appear without a title prefix like Mr. or Dr. and would otherwise slip past the regex layer entirely.
Indian NER gazetteer complements spaCy since the English model is trained predominantly on Western names and frequently misses South Asian ones like Devika Subramaniam or Priya Nair. RedactIQ maintains a curated list of common Indian first names and surnames. During the context scan pass, any two-word combination where both words appear in the gazetteer is treated as a name candidate and pre-registered in the vault before redaction begins. If Stanza is installed it additionally runs a multilingual model with stronger coverage of Hindi-origin names.

---

## Installation

```bash
pip install flask pypdf python-docx openpyxl reportlab pdfplumber pikepdf spacy
```

Optional (better name detection):
```bash
pip install stanza
python -m spacy download en_core_web_sm
```

---

## Running

```bash
python app.py
```

Open `http://localhost:5000` in your browser.
Default login: `admin` / `admin123`

---

## How It Works

### Redaction Modes

| Mode | Behaviour | Example |
|------|-----------|---------|
| Public | Uniform blocks — zero information leaked | `████████████` |
| Research | Consistent pseudonyms — re-linkable, not re-identifiable | `[NAME-R001]` |
| Audit | Type labels only — identity stripped, structure preserved | `[NAME][EMAIL]` |

### PII Detected

- Names (title-prefixed + context-scanned: customer, agent, officer, etc.)
- Email addresses
- Phone numbers (Indian and international formats)
- Aadhaar numbers, PAN numbers, credit/debit card numbers
- IP addresses
- Dates of birth (keyword-prefixed)
- Physical addresses (number + locality keyword formats)

### Supported File Types

| Format | Notes |
|--------|-------|
| `.txt` | Plain text |
| `.pdf` | Two-layer redaction — visual blocks + content stream blanking |
| `.docx` | Paragraph and table cell aware |
| `.csv` | Per-cell redaction |
| `.xlsx` | Per-cell redaction |
| `.sql` | String literal aware |

### Detection & Redaction Pipeline

When files are uploaded, RedactIQ runs a two-pass detection system before any redaction happens.

**Pass 1 — Context scanning:** The engine scans all uploaded files together looking for names that appear near trigger keywords like `customer`, `agent`, `officer`, `prepared by`, etc. All discovered names are registered in the PseudonymVault upfront, ensuring consistent tokens across the entire batch before redaction begins.

**Pass 2 — Pattern matching + NER:** Each file is processed individually. A ordered stack of regex rules fires against the text — card numbers before Aadhaar (to avoid partial overlaps), structured fields like PAN and email, then phone numbers, then contextual fields like addresses and DOB. In parallel, a spaCy/Stanza NER model catches names and locations that regex alone would miss.

Regex rules are ordered deliberately — a 16-digit card number is matched before a 12-digit Aadhaar to prevent the first 12 digits of a card being consumed as an Aadhaar match.

Once all PII spans are identified, the engine replaces each span according to the active mode. In research mode, the PseudonymVault ensures the same input value always produces the same output token within a job — so `Priya Nair` is always `[NAME-R001]` whether she appears in the CSV, the DOCX, or the SQL dump.

For PDFs, redaction runs an additional layer: after text replacement, pikepdf draws opaque black rectangles directly over the original word coordinates so the PII cannot be recovered by selecting text in a PDF viewer.

### Architecture

```
app.py          Flask web server — routes, job queue, SQLite, admin panel
redactor.py     Core engine — regex rules, PseudonymVault, mode logic
ner_detect.py   NER layer — spaCy/Stanza + Indian name gazetteer
pdf_inplace.py  PDF-specific — pikepdf visual redaction + content stream blanking
```

**Job flow:** upload → `auto_scan` pre-seeds vault with all names found → per-file redaction runs in a background thread → results zipped and stored.

**PseudonymVault:** assigns deterministic tokens (`[NAME-R001]`, `[EMAIL-R001]`) within a job so the same value always maps to the same token, enabling cross-document linkage in research mode.

### Admin Panel (`/admin`)

- **Jobs tab** — full audit trail, who ran each job, per-file breakdown, download original or redacted ZIP
- **Users tab** — add/delete users, assign roles (admin/analyst)

Analyst accounts can use the redaction tool but cannot access the admin panel.

---

## File Structure

```
app.py
redactor.py
ner_detect.py
pdf_inplace.py
redactiq_data/          ← created on first run
  uploads/              ← original files retained per job
  outputs/              ← redacted ZIPs
  jobs.db               ← SQLite audit database
```
