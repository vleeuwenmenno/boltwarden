import { visibleInput } from './forms';
import type { CardDetails } from './protocol';

export type CardField = 'cc-name' | 'cc-given-name' | 'cc-family-name' | 'cc-number' | 'cc-exp' | 'cc-exp-month' | 'cc-exp-year' | 'cc-csc' | 'cc-type';
export type CardControl = HTMLInputElement | HTMLSelectElement;
export type CardForm = Partial<Record<CardField, CardControl>>;
const purposes: CardField[] = ['cc-name', 'cc-given-name', 'cc-family-name', 'cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'cc-type'];
export function cardPurpose(field: CardControl): CardField | undefined {
  // Payment fields require an explicit standard autocomplete purpose. Guessing
  // from generic "number" or "security code" labels can fill unrelated forms.
  return purposes.find(value => (field.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/).includes(value));
}
function controls(root: Document | ShadowRoot): CardControl[] {
  const found = Array.from(root.querySelectorAll<CardControl>('input,select'));
  for (const element of root.querySelectorAll('*')) if (element.shadowRoot) found.push(...controls(element.shadowRoot));
  return found;
}
export function cardForms(document: Document, visible = visibleInput): CardForm[] {
  const groups = new Map<Node, CardControl[]>();
  for (const field of controls(document).filter(field => visible(field) && cardPurpose(field)
    && (field.type === 'select-one' || ['text', 'tel', 'number', 'password', 'month'].includes(field.type)))) {
    const group = field.form ?? field.closest('[role="form"]') ?? field.getRootNode();
    groups.set(group, [...(groups.get(group) ?? []), field]);
  }
  return [...groups.values()].flatMap(fields => {
    const form: CardForm = {};
    for (const field of fields) {
      const purpose = cardPurpose(field)!;
      if (form[purpose]) return []; // Ambiguous payment forms require a focused, distinct form.
      form[purpose] = field;
    }
    return [form];
  });
}
export function sameCard(left: CardForm | undefined, right: CardForm | undefined): boolean {
  return left === undefined ? right === undefined : !!right && purposes.every(key => left[key] === right[key]);
}
export function fillCard(form: CardForm, card: CardDetails, visible = visibleInput, stillCurrent = () => true): void {
  const month = card.exp_month.padStart(2, '0');
  const year = /^\d{2}$/.test(card.exp_year) ? `20${card.exp_year}` : card.exp_year;
  const names = card.cardholder.trim().split(/\s+/);
  const values: Record<CardField, string> = {
    'cc-name': card.cardholder, 'cc-given-name': names[0] ?? '', 'cc-family-name': names.slice(1).join(' '),
    'cc-number': card.number.replace(/[ -]/g, ''), 'cc-csc': card.code, 'cc-type': card.brand,
    'cc-exp-month': /^\d{1,2}$/.test(card.exp_month) && +month >= 1 && +month <= 12 ? month : '',
    'cc-exp-year': /^\d{4}$/.test(year) ? year : '', 'cc-exp': '',
  };
  values['cc-exp'] = values['cc-exp-month'] && values['cc-exp-year'] ? `${month}/${year.slice(-2)}` : '';
  const fields = purposes.flatMap(purpose => {
    const field = form[purpose];
    if (!field || !values[purpose]) return [];
    let value = values[purpose];
    if (purpose === 'cc-exp' && field.type === 'month') value = `${year}-${month}`;
    if (purpose === 'cc-exp' && field.tagName === 'INPUT' && ((field as HTMLInputElement).maxLength === 7
      || /yyyy/i.test((field as HTMLInputElement).placeholder))) value = `${month}/${year}`;
    if (purpose === 'cc-exp-year' && field.tagName === 'INPUT' && (field as HTMLInputElement).maxLength === 2) value = year.slice(-2);
    if (field.tagName === 'SELECT') {
      const options = Array.from((field as HTMLSelectElement).options).filter(option => !option.disabled && option.value !== '');
      const matching = options.filter(option => {
        const candidates = [option.value.trim(), option.text.trim()];
        return candidates.some(candidate => candidate.toLowerCase() === value.toLowerCase()
          || purpose === 'cc-exp-month' && /^\d{1,2}$/.test(candidate) && +candidate === +month
          || purpose === 'cc-exp-year' && candidate === year.slice(-2));
      });
      if (matching.length !== 1) throw new Error('Select the payment date or card type manually; its options are ambiguous.');
      value = matching[0]!.value;
    } else if ((field as HTMLInputElement).maxLength > 0 && value.length > (field as HTMLInputElement).maxLength) {
      throw new Error('Card details do not fit the selected payment fields.');
    }
    return [{ field, purpose, value, type: field.type, autocomplete: field.getAttribute('autocomplete') }];
  });
  if (!fields.length) throw new Error('No matching card details for these payment fields.');
  const validate = () => {
    if (!stillCurrent() || fields.some(({field, purpose, type, autocomplete}) => !visible(field)
      || field.type !== type || field.getAttribute('autocomplete') !== autocomplete || cardPurpose(field) !== purpose)) {
      throw new Error('The payment form changed. Select a payment field and try again.');
    }
  };
  validate();
  try {
    for (const entry of fields) {
      validate();
      const view = entry.field.ownerDocument.defaultView!;
      const prototype = entry.field.tagName === 'SELECT' ? view.HTMLSelectElement.prototype : view.HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
      if (!setter) throw new Error('This page does not support filling.');
      setter.call(entry.field, entry.value);
      entry.field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      entry.field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
    }
  } finally { for (const entry of fields) entry.value = ''; for (const key of purposes) values[key] = ''; }
}
