import { visibleInput } from './forms';
import type { CardDetails } from './protocol';

export type CardField = 'cc-name' | 'cc-given-name' | 'cc-family-name' | 'cc-number' | 'cc-exp' | 'cc-exp-month' | 'cc-exp-year' | 'cc-csc' | 'cc-type';
export type CardControl = HTMLInputElement | HTMLSelectElement;
export type CardForm = Partial<Record<CardField, CardControl>>;
const purposes: CardField[] = ['cc-name', 'cc-given-name', 'cc-family-name', 'cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'cc-type'];
function explicitPurpose(field: CardControl): CardField | undefined {
  return purposes.find(value => (field.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/).includes(value));
}
/** Recognize specific payment names and associated labels, never generic numbers/codes. */
export function cardPurpose(field: CardControl): CardField | undefined {
  const explicit = explicitPurpose(field);
  if (explicit) return explicit;
  const tokens = (field.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.some(token => token !== 'off' && token !== 'on')) return undefined;
  const labels = Array.from(field.labels ?? []).map(label => label.textContent ?? '');
  const labelled = (field.getAttribute('aria-labelledby') ?? '').split(/\s+/).filter(Boolean).map(id => (field.getRootNode() as Document | ShadowRoot).getElementById?.(id)?.textContent ?? '');
  const hints = [field.name, field.id, field.getAttribute('aria-label') ?? '', ...labels, ...labelled]
    .map(value => value.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim());
  const matches = (expression: RegExp) => hints.some(value => expression.test(value));
  if (matches(/\b(?:card ?number|credit ?card ?number|debit ?card ?number|cc ?number)\b/)) return 'cc-number';
  if (matches(/\b(?:cvv2?|cvc2?|cid|card ?security ?code|card ?verification ?(?:code|value))\b/)) return 'cc-csc';
  if (matches(/\b(?:card ?holder(?: ?name)?|name ?on ?card)\b/)) return 'cc-name';
  if (matches(/\b(?:exp(?:iry|iration)?|card ?exp(?:iry|iration)?) ?month\b/)) return 'cc-exp-month';
  if (matches(/\b(?:exp(?:iry|iration)?|card ?exp(?:iry|iration)?) ?year\b/)) return 'cc-exp-year';
  if (matches(/\b(?:exp(?:iry|iration)(?: ?date)?|card ?exp)\b/)) {
    if (field.tagName !== 'SELECT') return 'cc-exp';
    const values = Array.from((field as HTMLSelectElement).options).map(option => option.value.trim()).filter(value => /^\d+$/.test(value));
    if (values.length >= 2 && values.every(value => /^\d{4}$/.test(value) && +value >= 2000 && +value <= 2200)) return 'cc-exp-year';
    if (values.length === 12 && new Set(values.map(Number)).size === 12 && values.every(value => +value >= 1 && +value <= 12)) return 'cc-exp-month';
  }
  return undefined;
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
    const inferred = fields.some(field => !explicitPurpose(field));
    if (inferred && (!form['cc-number'] || !(form['cc-exp'] || form['cc-exp-month'] || form['cc-exp-year'] || form['cc-csc']))) {
      for (const field of fields) if (!explicitPurpose(field)) delete form[cardPurpose(field)!];
    }
    return Object.keys(form).length ? [form] : [];
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
