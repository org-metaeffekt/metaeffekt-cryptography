/*
 * RngPattern.g4
 *
 * ANTLR4 grammar for random-number-generator pattern notation, extending the
 * CycloneDX algorithm pattern syntax with RNG-specific constructs:
 *   • OS API paths  (/dev/urandom, /dev/random, /dev/hwrng)
 *   • Function-call names  (getrandom(), BCryptGenRandom())
 *   • Xoshiro output-function operators  (+, ++, **)
 *
 * ── Notation reference ──────────────────────────────────────────────────────
 *
 *   {x}         Variable placeholder, e.g. {hashAlgorithm}, {securityStrength}
 *   (a|b)       Required choice — exactly one alternative must match
 *   [...]       Optional group — the enclosed content may be absent
 *   [-{x}]      Optional variable with mandatory leading dash
 *   *           Wildcard — matches any single conforming token or segment
 *   [v1|v2]     Enumeration — exactly one of the listed literal values
 *   /path       OS entropy device path (starts with '/')
 *   name()      Function-call form for OS/API calls
 *   +  ++  **   Xoshiro output-function operators
 *
 * ── Pattern examples ────────────────────────────────────────────────────────
 *
 *   Hash_DRBG[-(SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA-512/256)][-noDF]
 *   HMAC_DRBG[-(SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA-512/256)][-noDF]
 *   CTR_DRBG[-(AES-128|AES-192|AES-256|3DES)][-noDF]
 *   Dual_EC_DRBG[-(P-256|P-384|P-521)]
 *   Fortuna[-{blockCipher}[-{keyLength}]][-{hashAlgorithm}]
 *   Yarrow[-{hashAlgorithm}[-{cipherAlgorithm}]]
 *   ChaCha20-DRNG
 *   BCryptGenRandom()
 *   getrandom()
 *   /dev/urandom
 *   /dev/random
 *   /dev/hwrng
 *   RDRAND
 *   RDSEED
 *   TPM_RNG[-{tpmVersion}]
 *   MersenneTwister[-{wordSize}]
 *   Xoshiro(256|512)(+|++|**)
 *   Xoroshiro(128|1024)(+|++|**)
 *   PCG[-{variant}]
 *   LCG[-{modulus}[-{multiplier}[-{increment}]]]
 *
 * ── Grammar notes ───────────────────────────────────────────────────────────
 *
 *  1. All constructs from AlgorithmPattern are included verbatim; this
 *     grammar is a self-contained superset.
 *
 *  2. OS API paths begin with '/' followed by at least one path segment.
 *     A PATH token is recognised only when it starts the string or follows
 *     whitespace (i.e., it is a top-level component, not a NAME fraction).
 *     The lexer uses a dedicated PATH rule that greedily captures the full
 *     slash-separated path.
 *
 *  3. Function-call syntax: NAME immediately followed by '()' (no arguments).
 *     The funcCall parser rule consumes NAME LPAREN RPAREN.  Because LPAREN
 *     is also used for choiceGroup, the parser resolves the ambiguity via
 *     LL(*) lookahead: funcCall requires '()' (empty parens), while
 *     choiceGroup requires at least one patternSeq inside.
 *
 *  4. Xoshiro operators (**) conflict with WILDCARD (*).  ANTLR4 resolves
 *     lexer ambiguity by maximal munch (longest match wins).  Therefore
 *     DSTAR ('**') must appear before WILDCARD ('*') in the lexer, ensuring
 *     that "**" is tokenised as a single DSTAR, not two WILDCARDs.
 *     Similarly, DPLUS ('++') is defined before any single-character rule
 *     that might match '+'.
 *
 *  5. The SLASH token is only emitted when '/' appears as a standalone
 *     character between NAME tokens (e.g. SHA-512/256 as separate tokens).
 *     Full OS paths are captured atomically by the PATH rule (which has
 *     higher priority as it is listed first in the lexer).
 *
 *  6. A comma-separated list at the top level allows multi-pattern inventory
 *     entries, consistent with AlgorithmPattern.
 */

grammar RngPattern;

// ── Parser rules ─────────────────────────────────────────────────────────────

/** Top-level rule: one or more RNG pattern expressions. */
pattern
    : patternList EOF
    ;

/**
 * A comma-separated list of patterns.
 * Example: "Hash_DRBG[-SHA-256], HMAC_DRBG[-SHA-512]"
 */
patternList
    : patternSeq (COMMA patternSeq)*
    ;

/**
 * A single pattern sequence: one or more components joined by dashes.
 * A sequence may consist of a single PATH or funcCall component.
 */
patternSeq
    : component+ (DASH component+)*
    ;

/**
 * An atomic component within a pattern sequence.
 * Ordered so that more-specific alternatives (funcCall, osApiPath, operator)
 * are tried before the generic NAME / bracketGroup fallbacks.
 */
component
    : funcCall       # funcCallComponent
    | osApiPath      # osApiPathComponent
    | operator       # operatorComponent
    | NAME           # nameComponent
    | NUMBER         # numberComponent
    | WILDCARD       # wildcardComponent
    | variable       # variableComponent
    | bracketGroup   # bracketComponent
    | choiceGroup    # choiceComponent
    ;

/**
 * An OS entropy device or syscall path.
 * Examples: /dev/urandom, /dev/random, /dev/hwrng
 */
osApiPath
    : PATH
    ;

/**
 * A no-argument function call, used for OS/API naming conventions.
 * Examples: getrandom(), BCryptGenRandom(), arc4random()
 */
funcCall
    : NAME LPAREN RPAREN
    ;

/**
 * Xoshiro / Xoroshiro output-function operators.
 * Order matches lexer priority: DSTAR before DPLUS before PLUS.
 */
operator
    : DSTAR   # dstarOp
    | DPLUS   # dplusOp
    | PLUS    # plusOp
    ;

/**
 * A CycloneDX variable placeholder: {identifierName}
 * Examples: {hashAlgorithm}, {securityStrength}, {tpmVersion}, {blockCipher}
 */
variable
    : LBRACE VARNAME RBRACE
    ;

/**
 * A bracket group: optional, enumeration, or optional-variable idiom.
 *
 * Priority order (first matching alternative wins):
 *  1. enumeration    — [a|b|c]   at least one PIPE inside
 *  2. optionalDashVar — [-{x}]   optional variable with leading dash
 *  3. optionalDash   — [-seq]    optional content with leading dash
 *  4. optional       — [seq]     generic optional group
 *  5. emptyOptional  — []        explicitly empty optional
 */
bracketGroup
    : LBRACKET patternSeq (PIPE patternSeq)+ RBRACKET  # enumeration
    | LBRACKET DASH variable RBRACKET                   # optionalDashVar
    | LBRACKET DASH patternSeq RBRACKET                 # optionalDash
    | LBRACKET patternSeq RBRACKET                      # optional
    | LBRACKET RBRACKET                                 # emptyOptional
    ;

/**
 * A required-choice group: exactly one alternative must be present.
 * Examples: (256|512), (SHA-256|SHA-384|SHA-512), (+|++|**)
 */
choiceGroup
    : LPAREN patternSeq (PIPE patternSeq)* RPAREN
    ;


// ── Lexer rules ──────────────────────────────────────────────────────────────

/*
 * LEXER ORDERING IS SIGNIFICANT.
 * Rules are tried top-to-bottom; for equal-length matches the first rule wins.
 * Critical ordering constraints:
 *   PATH    before SLASH (greedy path match wins over lone slash)
 *   DSTAR   before WILDCARD  ("**" → DSTAR, not WILDCARD WILDCARD)
 *   DPLUS   before PLUS      ("++")
 */

/**
 * OS entropy device or kernel API path.
 * Matches: /dev/urandom, /dev/random, /dev/hwrng, /proc/sys/kernel/random/*
 * A PATH must start with '/' and contain at least one subsequent segment.
 */
PATH
    : '/' [a-zA-Z_] [a-zA-Z0-9_]* ('/' [a-zA-Z_*] [a-zA-Z0-9_*]*)*
    ;

// Xoshiro output-function operators — MUST precede WILDCARD and PLUS
DSTAR     : '**' ;
DPLUS     : '++' ;
PLUS      : '+' ;

// Structural punctuation (same as AlgorithmPattern)
DASH      : '-' ;
PIPE      : '|' ;
COMMA     : ',' ;
WILDCARD  : '*' ;
SLASH     : '/' ;
LBRACKET  : '[' ;
RBRACKET  : ']' ;
LPAREN    : '(' ;
RPAREN    : ')' ;
LBRACE    : '{' ;
RBRACE    : '}' ;

/**
 * Variable name inside {}: alphanumeric plus underscore plus slash.
 * Supports names like hashAlgorithm, tpmVersion, N_log2, sha512/256.
 */
VARNAME
    : [a-zA-Z_] [a-zA-Z0-9_/]*
    ;

/**
 * A numeric token: pure digits (e.g., 128, 256, 512, 1024).
 */
NUMBER
    : [0-9]+
    ;

/**
 * An alphanumeric name token.
 * Starts with a letter; may contain digits, underscores, and dots.
 * The SHA-512/256 slash-in-name variant is also captured here so that
 * a single segment like "512/256" or "SHA-512/256" is one NAME.
 * (Note: within a patternSeq, SHA-512/256 is NAME DASH NAME where the
 * second NAME captures "512/256".)
 */
NAME
    : [a-zA-Z] [a-zA-Z0-9_.]*
    | [a-zA-Z0-9] [a-zA-Z0-9_.]* '/' [a-zA-Z0-9][a-zA-Z0-9_.]*
    ;

/** Skip whitespace. */
WS
    : [ \t\r\n]+ -> skip
    ;
