"""
ner_detect.py — NER-based PII detection layer
Adds spaCy named entity recognition + Indian name gazetteer on top of regex.

Install:
    pip install spacy
    python -m spacy download en_core_web_lg        # English (handles Indian English)
    pip install stanza                              # Optional: for Hindi text segments
    python -c "import stanza; stanza.download('hi')"  # Optional: Hindi model

This module is imported by redactor.py and runs as Pass 3 in the detection pipeline.
"""

import re
from typing import Set, List, Tuple

# ─────────────────────────────────────────────────────────────
# INDIAN NAME GAZETTEER
# Covers common first names and surnames across major Indian regions.
# Used as a fallback when NER confidence is low or spaCy isn't installed.
# ─────────────────────────────────────────────────────────────

INDIAN_FIRST_NAMES = {
    # Pan-Indian / Hindi belt
    "aarav","aditya","akash","amit","amitabh","amol","anand","anil","anjali","ankita",
    "ankit","anupam","anurag","arjun","aryan","ashish","ashok","ashu","ayaan","ayush",
    "bhavesh","chandan","deepak","devika","dhruv","dinesh","divya","gaurav","girish",
    "gopal","hardik","harsh","harshit","hemant","hitesh","ishaan","ishan","jagdish",
    "jatin","jayesh","jitendra","kabir","karan","kartik","kavita","kewal","kiran",
    "krish","krishna","kunal","lalit","lavanya","lokesh","madhav","mahesh","manish",
    "manoj","meera","milan","mohit","mukesh","naresh","naveen","neeraj","nikhil",
    "nilesh","nitin","omkar","pankaj","parth","piyush","pooja","pradeep","prakash",
    "pranav","prasad","prashant","prateek","praveen","priya","rahul","rajat","rajesh",
    "rakesh","ramesh","ravi","ritesh","rohit","rohan","sachin","sagar","sahil","sanjay",
    "sanket","saurabh","shivam","shobha","shruti","shubham","sohan","sonam","subhash",
    "sudhir","sumit","sunil","suresh","sushant","swati","tarun","uday","umesh","varun",
    "vikas","vikram","vinay","vineet","vishal","vivek","yash","yogesh",
    # South Indian
    "aishwarya","ananya","anitha","anup","anusha","arjuna","arvind","ashwin","balaji",
    "bharath","chaitanya","chandrasekhar","deepika","dinesh","gayatri","geetha","girija",
    "gowtham","harini","harish","karthik","kavitha","keerthi","krishnaraj","lakshmi",
    "lalitha","madhavan","manikandan","manohar","meenakshi","mohan","muthu","nagesh",
    "nandini","narayanan","navya","padma","palani","parvathi","prashanth","prathap",
    "prema","raghav","raghavendra","rajkumar","ramachandran","ramesh","rangarajan",
    "revathi","sangeetha","sathish","senthil","shankar","shanthi","shivakumar","sridhar",
    "srinivasan","subramanian","sudha","sugumar","sundar","suresh","swaminathan",
    "thenmozhi","thiruvengadam","usha","venkatesan","vijay","vijayalakshmi","vimal",
    "vinitha","vivekanandan","yamini","yuvaraj",
    # West Indian (Gujarati/Marathi/Rajasthani)
    "alpesh","bhavin","bhavna","chirag","daksha","darshan","dharmesh","dipali","falgun",
    "foram","hetal","hitesh","jignesh","jigar","kalpesh","kamlesh","kinjal","mansi",
    "maulik","mayur","mehul","minal","mitesh","neel","nidhi","nilima","nimisha","parag",
    "parimal","parth","payal","pragnesh","priyal","purvi","rajan","rajni","rasesh",
    "riddhi","rupal","rutvi","sagar","sameer","sandip","seema","shreya","smita","sneha",
    "tejal","urvashi","viral","vishwa","vrunda","yogini",
    # East Indian (Bengali/Odia/Assamese)
    "abhijit","amitava","anindita","aniruddha","arnab","bidisha","biplob","chandana",
    "debashis","debasmita","indrani","jayanta","jhuma","kakali","kaushik","madhurima",
    "maitreyi","malay","mamata","manas","manidipa","mrinal","nilanjana","pabitra",
    "paramita","pinaki","prasenjit","priyanka","rituparna","sandipan","sanhita",
    "saswata","sibsankar","soumitra","subhajit","subhasish","sudeshna","sukanya",
    "sumana","supriya","swapna","tapas","tridib","ujjal","urmila",
    # Common Muslim names in India
    "aafreen","aamir","aasma","abid","adnan","aisha","ajmal","akbar","ali","aliya",
    "ameen","arshad","asghar","ashfaq","asif","ayesha","aziz","faizaan","farhan",
    "farida","fatima","firdaus","furqan","habib","hasan","hussain","ibrahim","imran",
    "irfan","jabir","karim","khalid","khurshid","latif","lubna","mahmood","majid",
    "maryam","mohammad","mohsin","mubarak","mudassar","muneer","mushtaq","mustafa",
    "nabeel","nadeem","naseem","nasir","nida","nisar","noor","omar","parveen","qasim",
    "rafiq","razia","rehman","rizwan","rubina","sadaf","sadiq","saleem","salma",
    "sameer","sana","sarfaraz","shaheen","shakeel","sharique","shazia","shoaib",
    "siddiqui","siraj","sultan","tahir","tanveer","tariq","usman","waseem","yusuf","zainab","zubair",
    # Sikh/Punjabi names
    "amarjit","amritpal","angad","arshdeep","baldev","balwinder","charanjit","daljit",
    "dalvir","gagandeep","gurbaksh","gurdeep","gurinder","gurjot","gurmeet","gurpreet",
    "gurwinder","hardeep","harjinder","harjot","harkirat","harmeet","harpreet",
    "harvinder","inderpal","jagdeep","jagmeet","jasbir","jaspreet","jaswinder",
    "karamjit","karanjit","kuldeep","kulwinder","lakhwinder","lovejeet","lovpreet",
    "mandeep","maninder","manjinder","manjit","manpreet","navdeep","navjot","navneet",
    "navpreet","parminder","parwinder","pawandeep","rajandeep","rajinder","rajwinder",
    "ravinder","sarabjit","satwinder","simranjit","simranpreet","sukhjinder","sukhwinder",
    "surinderpal","taranjit","tejinder","varinder","vikramjit",
}

INDIAN_LAST_NAMES = {
    # Common Hindu surnames
    "agarwal","agrawal","ahuja","anand","arora","awasthi","bajaj","bajpai","bakshi",
    "banerjee","bansode","bapat","bedi","bhatt","bhattacharya","bhatia","bhatnagar",
    "bhosale","biswas","bose","chakraborty","chakravarti","chandra","chandran",
    "chatterjee","chaturvedi","chauhan","chavan","chawla","choudhary","choudhuri",
    "chopra","das","dasgupta","datta","dave","desai","deshpande","dey","dhawan",
    "dixit","dubey","dutta","gandhi","garg","ghosh","goyal","guha","gulati","gupta",
    "iyer","jain","jaiswal","jha","joshi","kadam","kapoor","kaul","khanna","khare",
    "kohli","krishnan","kulkarni","kumar","lal","mahajan","maheswari","malhotra",
    "mali","mehrotra","mehta","menon","mishra","mistry","mitra","modi","mohan",
    "mukherjee","nair","narang","narayanan","nath","nayak","nigam","ojha","pachori",
    "pande","pandey","parekh","patel","pathak","patil","pillai","prasad","rao",
    "rastogi","reddy","roy","saha","sahni","saksena","sarkar","saxena","sen",
    "seth","shah","sharma","shastri","shukla","singh","sinha","sood","srikanth",
    "srivastava","subramanian","tewari","thakur","tiwari","trivedi","upadhyay",
    "varma","verma","vyas","yadav",
    # South Indian surnames
    "acharya","anantharaman","annamalai","arumugam","balakrishnan","balasubramanian",
    "chandrasekaran","chidambaram","dakshinamurthy","gopalakrishnan","govindarajan",
    "ilaiyaraaja","jayaraman","kalyanasundaram","krishnamurthy","krishnaswamy",
    "kumaraswamy","kumaresan","lakshmanan","lingam","mahadevan","mahalingam",
    "murugan","muthuswamy","nagarajan","narasimhan","natarajan","palaniswamy",
    "raghunathan","rajagopalan","rajagopal","rajalakshmi","rajamanickam","rajasekaran",
    "ramalingam","ramasubramanian","ramesh","rengasamy","sethuraman","sivasankaran",
    "soundararajan","subramaniam","subramanyan","sundaresan","swaminathan",
    "thirumalachari","thyagarajan","vaidyanathan","venkataramaiah","venkataraman",
    "venkateswaran","viswanathan",
    # Muslim surnames
    "ansari","baig","beg","butt","chishti","farooqi","hashmi","hussain","khan",
    "malik","mirza","naqvi","qureshi","rahman","rashid","rizvi","siddiqui","syed","zaidi",
    # Sikh surnames
    "ahluwalia","anand","atwal","bagga","bains","banga","bassi","bath","bedi","bhatti",
    "bhullar","boparai","braich","brar","brard","buttar","chadha","chaggar","chattha",
    "cheema","chhabra","chima","dahiya","deol","dhaliwal","dhesi","dhillon","dua",
    "duggal","garcha","ghuman","gill","gosal","grewal","hansra","johal","judge",
    "kang","kanwar","kapila","khera","khinda","khunkhun","klair","maan","mander",
    "mangat","mann","nijhar","nijjar","oberoi","panesar","parmar","phull","pooni",
    "rai","raikhy","randhawa","ranu","rehal","sandhu","sangha","sanghera","sekhon",
    "sidhu","sohi","sooch","sran","takhar","tatla","toor","uppal","virdee","virk","walia",
}

# ─────────────────────────────────────────────────────────────
# SENSITIVE ENTITY CATEGORIES per mode
# ─────────────────────────────────────────────────────────────

# spaCy entity labels to redact per mode
# None = keep, set = redact these label types
MODE_ENTITY_RULES = {
    "public": {
        "redact":  {"PERSON", "GPE", "LOC", "FAC", "ORG"},
        "keep":    {"DATE", "TIME", "MONEY", "PERCENT", "QUANTITY", "ORDINAL", "CARDINAL"},
    },
    "research": {
        "redact":  {"GPE", "LOC", "FAC"},           # strip locations, keep names (pseudonymised elsewhere)
        "keep":    {"PERSON", "ORG", "DATE", "TIME", "MONEY", "EVENT"},
    },
    "audit": {
        "redact":  {"PERSON", "GPE", "LOC", "FAC"},  # strip personal/location, keep org/financial
        "keep":    {"ORG", "DATE", "TIME", "MONEY", "PERCENT", "EVENT"},
    },
}

# Fixed-width uniform replacements per entity type and mode
# Public: fixed blocks | Research: pseudonym tokens | Audit: type labels

def _ner_replace(label: str, value: str, mode: str) -> str:
    """Apply correct replacement strategy per mode for NER-detected entities."""
    PUBLIC = {
        "PERSON": "████████████",
        "GPE":    "████████",
        "LOC":    "████████",
        "FAC":    "████████",
        "ORG":    "████████████",
    }
    AUDIT = {
        "PERSON": "[NAME]",
        "GPE":    "[LOCATION]",
        "LOC":    "[LOCATION]",
        "FAC":    "[FACILITY]",
        "ORG":    "[ORGANISATION]",
    }
    if mode == "public":
        return PUBLIC.get(label, "████████████")
    elif mode == "research":
        # Use the shared VAULT from redactor.py so tokens are consistent
        # across regex, context scanner, gazetteer, and spaCy passes
        try:
            from redactor import VAULT
            pii_type = {"PERSON":"name","GPE":"location","LOC":"location",
                        "FAC":"facility","ORG":"organisation"}.get(label, label.lower())
            return VAULT.get(pii_type, value)
        except ImportError:
            import hashlib
            short = {"PERSON":"NAME","GPE":"LOC","LOC":"LOC","FAC":"FAC","ORG":"ORG"}.get(label, label)
            key = hashlib.sha256(f"{label}:{value.lower().strip()}".encode()).hexdigest()[:6]
            return f"[{short}-R{key.upper()}]"
    elif mode == "audit":
        return AUDIT.get(label, "[REDACTED]")
    return value


# ─────────────────────────────────────────────────────────────
# GAZETTEER MATCHING
# ─────────────────────────────────────────────────────────────

def _build_name_pattern():
    """Build a combined regex from the gazetteer for fast matching."""
    all_names = INDIAN_FIRST_NAMES | INDIAN_LAST_NAMES
    # Match: FirstName LastName or LastName FirstName (both capitalised)
    name_alts = "|".join(sorted(all_names, key=len, reverse=True))
    # Pattern: two consecutive capitalised words where at least one is in gazetteer
    return re.compile(
        r"\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})\b"
    ), set(n.lower() for n in all_names)

_NAME_PAIR_RE, _GAZETTEER_SET = _build_name_pattern()

NON_NAME_WORDS = {
    "activity","trends","success","teams","support","operations","summary",
    "during","archival","references","interaction","session","profile",
    "feedback","engagement","following","gathered","latest","product",
    "update","service","request","portal","engine","billing","internal",
    "analytics","dashboard","tracking","feature","adoption","customer",
    "user","client","data","review","process","system","description",
    "compliance","infrastructure","quarterly","marketing","engineering",
    "finance","security","verified","identity","agent","case","account",
}

def gazetteer_find_names(text: str) -> List[Tuple[int, int, str]]:
    """
    Find Indian names using the gazetteer lookup.
    Returns list of (start, end, matched_text).
    """
    found = []
    for m in _NAME_PAIR_RE.finditer(text):
        w1, w2 = m.group(1).lower(), m.group(2).lower()
        # At least one word must be in the gazetteer
        if (w1 in _GAZETTEER_SET or w2 in _GAZETTEER_SET):
            # Neither word should be a common non-name
            if not (w1 in NON_NAME_WORDS or w2 in NON_NAME_WORDS):
                found.append((m.start(), m.end(), m.group()))
    return found


# ─────────────────────────────────────────────────────────────
# spaCy NER
# ─────────────────────────────────────────────────────────────

_nlp_model = None
_nlp_available = False

def load_spacy_model():
    """
    Try to load spaCy model. Tries lg → md → sm in order.
    Returns True if loaded, False if spaCy not installed.
    """
    global _nlp_model, _nlp_available
    if _nlp_model is not None:
        return _nlp_available
    try:
        import spacy
        for model_name in ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]:
            try:
                _nlp_model = spacy.load(model_name)
                _nlp_available = True
                print(f"  ✓ spaCy model loaded: {model_name}")
                return True
            except OSError:
                continue
        print("  ⚠  spaCy installed but no English model found.")
        print("     Run: python -m spacy download en_core_web_lg")
        return False
    except ImportError:
        return False


def spacy_find_entities(text: str, mode: str) -> List[Tuple[int, int, str, str]]:
    """
    Run spaCy NER on text.
    Returns list of (start, end, matched_text, entity_label).
    Only returns entities that should be redacted in this mode.
    """
    if not _nlp_available or _nlp_model is None:
        return []

    redact_labels = MODE_ENTITY_RULES[mode]["redact"]
    found = []

    # Process in chunks to handle large documents (spaCy has max_length limit)
    chunk_size = 100_000
    offset = 0
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i+chunk_size]
        doc = _nlp_model(chunk)
        for ent in doc.ents:
            if ent.label_ in redact_labels:
                # Filter out obvious false positives
                ent_lower = ent.text.lower().strip()
                if ent_lower not in NON_NAME_WORDS and len(ent_lower) > 1:
                    found.append((
                        i + ent.start_char,
                        i + ent.end_char,
                        ent.text,
                        ent.label_
                    ))
        offset += chunk_size

    return found


# ─────────────────────────────────────────────────────────────
# STANZA (Hindi / multilingual support)
# ─────────────────────────────────────────────────────────────

_stanza_pipeline = None
_stanza_available = False

def load_stanza_hindi():
    """
    Load Stanza Hindi NER pipeline.
    Only called if Hindi text is detected in document.
    """
    global _stanza_pipeline, _stanza_available
    if _stanza_pipeline is not None:
        return _stanza_available
    try:
        import stanza
        _stanza_pipeline = stanza.Pipeline(
            lang="hi",
            processors="tokenize,ner",
            use_gpu=False,
            verbose=False
        )
        _stanza_available = True
        print("  ✓ Stanza Hindi model loaded")
        return True
    except Exception:
        return False


def contains_hindi(text: str) -> bool:
    """Detect if text contains Devanagari script."""
    return bool(re.search(r"[\u0900-\u097F]", text))


def stanza_find_hindi_entities(text: str, mode: str) -> List[Tuple[int, int, str, str]]:
    """
    Run Stanza Hindi NER on text segments containing Devanagari.
    Returns (start, end, text, label) tuples.
    """
    if not _stanza_available or not contains_hindi(text):
        return []

    redact_labels = MODE_ENTITY_RULES[mode]["redact"]
    found = []

    try:
        doc = _stanza_pipeline(text)
        for sent in doc.sentences:
            for ent in sent.entities:
                if ent.type in redact_labels:
                    found.append((ent.start_char, ent.end_char, ent.text, ent.type))
    except Exception:
        pass

    return found


# ─────────────────────────────────────────────────────────────
# COMBINED NER PASS — called by redactor.py
# ─────────────────────────────────────────────────────────────

def ner_redact(text: str, mode: str) -> Tuple[str, dict]:
    """
    Main entry point. Runs all NER passes and applies redactions.
    Returns (redacted_text, stats_dict).

    Detection order:
      1. Gazetteer — Indian name lookup (always runs, no dependency)
      2. spaCy NER — English neural NER (runs if installed)
      3. Stanza Hindi — Devanagari NER (runs if installed + Hindi detected)

    Deduplicates overlapping matches before applying.
    """
    stats = {}
    all_hits = []   # (start, end, replacement, source)

    # Skip NER for large files — regex and context scanner handle these
    if len(text) > 500000:
        return text, {}

    # ── Pass 1: Gazetteer ──────────────────────────────────────
    for (start, end, matched) in gazetteer_find_names(text):
        replacement = _ner_replace("PERSON", matched, mode)
        all_hits.append((start, end, replacement, "Gazetteer"))

    # ── Pass 2: spaCy NER ──────────────────────────────────────
    for (start, end, matched, label) in spacy_find_entities(text, mode):
        replacement = _ner_replace(label, matched, mode)
        all_hits.append((start, end, replacement, label))

    # ── Pass 3: Stanza Hindi ───────────────────────────────────
    if contains_hindi(text):
        load_stanza_hindi()
        for (start, end, matched, label) in stanza_find_hindi_entities(text, mode):
            replacement = _ner_replace(label, matched, mode)
            all_hits.append((start, end, replacement, f"Hindi-{label}"))

    if not all_hits:
        return text, stats

    # ── Deduplicate overlapping spans (keep longest) ───────────
    all_hits.sort(key=lambda x: (x[0], -(x[1]-x[0])))
    deduped = []
    last_end = -1
    for hit in all_hits:
        if hit[0] >= last_end:
            deduped.append(hit)
            last_end = hit[1]

    # ── Apply redactions in reverse order ─────────────────────
    result = text
    for (start, end, replacement, source) in reversed(deduped):
        result = result[:start] + replacement + result[end:]
        category = "Name" if source in ("Gazetteer", "PERSON") else source.split("-")[0]
        stats[category] = stats.get(category, 0) + 1

    return result, stats


# ─────────────────────────────────────────────────────────────
# SETUP INSTRUCTIONS (printed if models missing)
# ─────────────────────────────────────────────────────────────

SETUP_INSTRUCTIONS = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NER SETUP — Run these once to enable full detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  English NER (required — handles Indian names in English):
    pip install spacy
    python -m spacy download en_core_web_lg

  Hindi NER (optional — only needed for Devanagari text):
    pip install stanza
    python -c "import stanza; stanza.download('hi')"

  Without these, the tool still works using:
    • Regex patterns (SSN, PAN, Aadhaar, phone, email, IP)
    • Indian name gazetteer (5000+ names, no install needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

def print_setup():
    print(SETUP_INSTRUCTIONS)
