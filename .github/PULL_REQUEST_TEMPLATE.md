## What this changes

<!-- One or two sentences. -->

## Effect on output

<!-- Does this change the Dockerfile dtrim emits, or the report it prints? If so, paste a
     before and after. If not, say "none". -->

## Checklist

- [ ] `make lint`
- [ ] `make test`
- [ ] `make integration`, if the synthesizer or the base mapping changed
- [ ] Golden changes reviewed line by line, not blindly accepted
- [ ] New rules are idempotent and clear `Raw` on instructions they rewrite
- [ ] Anything not built is in the changelog under "Planned", and anything missed is under
      "Known limitations"
