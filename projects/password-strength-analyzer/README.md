# Password Strength Analyzer

Entropy-based password strength estimator with pattern heuristics (common words, sequences, repetition).

## Files

- `analyze.py`

## Usage

```bash
python analyze.py "correct horse battery staple"
# entropy: 51.2 bits — STRONG
python analyze.py "p@ssw0rd"
# entropy: 12.4 bits — WEAK (common word + substitutions)
```