/*
 * AlgorithmPattern.g4
 *
 * ANTLR4 grammar for CycloneDX cryptographic algorithm pattern notation,
 * extended with wildcard (*) and enumeration ([v1|v2]) support.
 *
 * ── Notation reference ──────────────────────────────────────────────────────
 *
 *   {x}         Variable placeholder, e.g. {keyLength}, {hashAlgorithm}
 *   (a|b)       Required choice — exactly one alternative must match
 *   [...]       Optional group — the enclosed content may be absent
 *   [-{x}]      Optional variable with mandatory leading dash (common idiom)
 *   *           Wildcard — matches any single conforming token or segment
 *   [v1|v2]     Enumeration — exactly one of the listed literal values
 *               (distinguished from plain optional by the presence of '|')
 *
 * ── Pattern examples ────────────────────────────────────────────────────────
 *
 *   AES-[128|192|256]-[GCM|CCM|CBC|CTR|OFB|CFB128|XTS|KW]
 *   AES-[128|192|256]-*
 *   HMAC-[SHA-256|SHA-384|SHA-512]
 *   HMAC-SHA-{hashAlgorithm}
 *   ChaCha20-Poly1305
 *   ML-KEM-[512|768|1024]
 *   ML-DSA-[44|65|87]-*
 *   ML-DSA-[44|65|87]-(hedged)
 *   SLH-DSA-*
 *   FN-DSA-[512|1024]
 *   RSAES-OAEP-[2048|3072|4096]-*
 *   ECDH-[P-256|P-384|P-521]
 *   ECDH-[Curve25519|X25519]
 *   ECDSA-[P-256|P-384|P-521]-[SHA-256|SHA-384|SHA-512]
 *   EdDSA-[Ed25519|Ed448]
 *   RSASSA-PSS-[2048|3072|4096]-*
 *   HKDF-[SHA-256|SHA-384|SHA-512]
 *   PBKDF2-HMAC-[SHA-256|SHA-384|SHA-512]-*
 *   SP800-108-*
 *   CTR_DRBG-AES-256
 *   HMAC_DRBG-[SHA-256|SHA-384|SHA-512]
 *   Argon2id-*
 *   scrypt-*
 *   SHAKE[128|256]
 *   SHA3-[256|384|512]
 *   AES-[128|192|256]-CMAC
 *   KMAC[128|256]
 *   FFDH-*
 *   ECDH-[Curve448|X448]
 *   SP800-108-[KDF-CTR|KDF-Feedback|KDF-DPIpeline]-*
 *   HQC-[128|192|256]
 *   MAYO-*
 *   CROSS-*
 *   UOV-*
 *   SNOVA-*
 *
 * ── Grammar notes ───────────────────────────────────────────────────────────
 *
 *  1. The dash (-) is treated as a structural separator between components,
 *     not as part of a NAME token. This means "AES-256-GCM" parses as three
 *     NAME tokens joined by DASH separators: AES, 256, GCM.
 *
 *  2. Enumeration [v1|v2] vs optional [x] disambiguation: the presence of
 *     PIPE inside the brackets triggers the #enumeration alternative, which
 *     has priority via ANTLR4's ordered-choice LL(*) resolution.
 *
 *  3. Enumerations may themselves contain dashes: [P-256|P-384|P-521].
 *     Inside an enumeration alternative, patternSeq recurses normally, so
 *     P-256 parses as NAME DASH NAME within a single alternative.
 *
 *  4. Required-choice groups (a|b) use parentheses. They are mandatory;
 *     if only one option is listed the parens still force explicit grouping.
 *
 *  5. The WILDCARD token (*) matches at the component level — it represents
 *     "any single dash-separated segment or any trailing continuation".
 *     Semantics are defined by the consuming application; the grammar only
 *     enforces syntactic well-formedness.
 *
 *  6. Variables {x} contain identifiers that name CycloneDX placeholders.
 *     Variable names may include alphanumerics plus underscore.
 */

grammar AlgorithmPattern;

// ── Parser rules ─────────────────────────────────────────────────────────────

/** Top-level rule: a single algorithm pattern expression. */
pattern
    : patternList EOF
    ;

/**
 * A comma-separated list of patterns (for multi-pattern inventory entries).
 * Example: "ML-KEM-[512|768|1024], ML-DSA-[44|65|87]-*"
 */
patternList
    : patternSeq (COMMA patternSeq)*
    ;

/**
 * A single pattern sequence: one or more components joined by dashes.
 * Examples: "AES-256-GCM", "ML-DSA-[44|65|87]-*", "ChaCha20-Poly1305"
 */
patternSeq
    : component+ (DASH component+)*
    ;

/**
 * An atomic component within a pattern sequence.
 */
component
    : NAME           # nameComponent
    | NUMBER         # numberComponent
    | WILDCARD       # wildcardComponent
    | variable       # variableComponent
    | bracketGroup   # bracketComponent
    | choiceGroup    # choiceComponent
    ;

/**
 * A CycloneDX variable placeholder: {identifierName}
 * Examples: {keyLength}, {hashAlgorithm}, {parameterSetIdentifier}
 */
variable
    : LBRACE VARNAME RBRACE
    ;

/**
 * A bracket group: optional, enumeration, or optional-variable idiom.
 *
 * Priority order (ANTLR4 uses first matching alternative):
 *  1. enumeration    — [a|b|c]  contains at least one PIPE
 *  2. optionalDash   — [-{x}]   optional variable with leading dash
 *  3. optional       — [x]      generic optional group
 *  4. emptyOptional  — []       explicitly empty optional (rare)
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
 * Examples: (hedged), (SHA-256|SHA-384|SHA-512)
 */
choiceGroup
    : LPAREN patternSeq (PIPE patternSeq)* RPAREN
    ;


// ── Lexer rules ──────────────────────────────────────────────────────────────

// Structural punctuation
DASH      : '-' ;
PIPE      : '|' ;
COMMA     : ',' ;
WILDCARD  : '*' ;
LBRACKET  : '[' ;
RBRACKET  : ']' ;
LPAREN    : '(' ;
RPAREN    : ')' ;
LBRACE    : '{' ;
RBRACE    : '}' ;

/**
 * Variable name inside {}: alphanumeric plus underscore plus slash
 * to support names like parameterSetIdentifier, N_log2, sha512/256.
 */
VARNAME
    : [a-zA-Z_] [a-zA-Z0-9_/]*
    ;

/**
 * A numeric token: pure digits (e.g., 128, 256, 44, 65, 87).
 * Kept separate from NAME so consumers can distinguish numeric parameters
 * (key lengths, security levels) from algorithm name segments.
 */
NUMBER
    : [0-9]+
    ;

/**
 * An alphanumeric name token. Starts with a letter; may contain digits,
 * underscores, dots, and forward slashes (for algo families like SHA-512/256).
 * Note: the slash variant is only needed when the slash appears within a
 * segment rather than as a NAME-NAME junction; SHA-512/256 is a single NAME.
 */
NAME
    : [a-zA-Z] [a-zA-Z0-9_.]*
    | [a-zA-Z0-9] [a-zA-Z0-9_.]* '/' [a-zA-Z0-9][a-zA-Z0-9_.]*
    ;

/** Skip whitespace between comma-separated patterns. */
WS
    : [ \t\r\n]+ -> skip
    ;
