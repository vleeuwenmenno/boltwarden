// Firefox (and Chrome) show their own typed-history suggestions on login fields. While a field
// is focused Boltwarden can set autocomplete="off" on it to hide them. Field detection must keep
// seeing the page's own value, so every autocomplete read goes through `autocompleteOf`.
type Field = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
const originals = new WeakMap<Field, { value: string; attribute: string | null }>();

// Read the attribute, not the `autocomplete` property: Firefox returns "" from the property for
// tokens it does not autofill itself, such as one-time-code.
const attributeValue = (input: Field) => (input.getAttribute('autocomplete') ?? '').trim().toLowerCase();

/** The page's own autocomplete value (lowercase), even while Boltwarden has it suppressed. */
export function autocompleteOf(input: Field): string {
  return originals.get(input)?.value ?? attributeValue(input);
}

/** Hide browser form history on this field; the returned function puts the page's value back. */
export function suppressFormHistory(input: HTMLInputElement): () => void {
  if (originals.has(input)) return () => {};
  originals.set(input, { value: attributeValue(input), attribute: input.getAttribute('autocomplete') });
  input.setAttribute('autocomplete', 'off');
  return () => {
    const original = originals.get(input);
    originals.delete(input);
    // The page replaced the value itself in the meantime: keep the page's choice.
    if (!original || input.getAttribute('autocomplete') !== 'off') return;
    if (original.attribute === null) input.removeAttribute('autocomplete'); else input.setAttribute('autocomplete', original.attribute);
  };
}
