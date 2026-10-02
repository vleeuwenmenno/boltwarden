// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cardForms, fillCard, type CardControl } from '../lib/cards';
import { loginForms } from '../lib/forms';
import { submittedLogin } from '../lib/password-capture';
import { parseWire } from '../lib/protocol';
const card = { cardholder: 'Alice Example', number: '4111 1111 1111 1111', code: '123', exp_month: '3', exp_year: '2030', brand: 'Visa' };
const visible = (field: CardControl) => field.isConnected && !field.disabled && field.type !== 'hidden' && !('readOnly' in field && field.readOnly);
beforeEach(() => { document.body.innerHTML = ''; });
describe('credit card fields', () => {
  it('fills explicit payment fields and dropdowns without submitting or touching login fields', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-name"><input autocomplete="cc-number"><input type="password" name="security-code" autocomplete="cc-csc"><select autocomplete="cc-exp-month"><option value="">Month</option><option value="3">03</option></select><select autocomplete="cc-exp-year"><option value="2030">2030</option></select><input autocomplete="username"></form>';
    const submit = vi.fn(); document.querySelector('form')!.addEventListener('submit', submit);
    const forms = cardForms(document, visible);
    expect(forms).toHaveLength(1); fillCard(forms[0]!, card, visible);
    expect(forms[0]!['cc-number']!.value).toBe('4111111111111111');
    expect(forms[0]!['cc-csc']!.value).toBe('123');
    expect(forms[0]!['cc-exp-month']!.value).toBe('3');
    expect(document.querySelector<HTMLInputElement>('[autocomplete=username]')!.value).toBe('');
    expect(loginForms(document, visible)[0]?.password).toBeUndefined();
    expect(loginForms(document, visible).some(form => form.otp)).toBe(false);
    expect(submit).not.toHaveBeenCalled();
  });
  it('recognizes labeled payment fields without autocomplete and never captures CVV as a password', () => {
    document.body.innerHTML = '<form><label>Card Number *<input id="pan"></label><label>Expiration month<select><option value="">Select One</option><option value="3">03</option></select></label><label>Expiration year<select><option value="2030">2030</option></select></label><label>CVV *<input type="password"></label></form>';
    const form = cardForms(document, visible)[0]!;
    fillCard(form, card, visible);
    expect(form['cc-number']!.value).toBe('4111111111111111');
    expect(form['cc-csc']!.value).toBe('123');
    expect(form['cc-exp-month']!.value).toBe('3');
    expect(submittedLogin(document.querySelector('form')!, visible)).toBeUndefined();
    expect(loginForms(document, visible)).toHaveLength(0);
  });
  it('requires payment context for guesses and preserves explicit nonpayment autocomplete', () => {
    document.body.innerHTML = '<form><label>Card number<input></label></form><form><input name="number"><input name="code"><input name="expiryMonth"></form><form><input name="cardNumber" autocomplete="one-time-code"><input name="cvv"></form>';
    expect(cardForms(document, visible)).toEqual([]);
  });
  it('rechecks heuristic labels after a page event handler changes their meaning', () => {
    document.body.innerHTML = '<form><label>Cardholder<input></label><label>Card number<input></label><label id="csc">CVV<input type="password"></label></form>';
    const form = cardForms(document, visible)[0]!;
    form['cc-name']!.addEventListener('input', () => { document.getElementById('csc')!.firstChild!.textContent = 'Account password'; });
    expect(() => fillCard(form, card, visible)).toThrow('payment form changed');
    expect(form['cc-number']!.value).toBe(''); expect(form['cc-csc']!.value).toBe('');
  });
  it('does not guess generic number or security-code fields or fill hidden fields', () => {
    document.body.innerHTML = '<form><input name="number"><input name="security-code"><input autocomplete="cc-number" type="hidden"><input autocomplete="cc-csc" readonly></form>';
    expect(cardForms(document, visible)).toEqual([]);
  });
  it('rejects duplicate card fields in one group and preserves separate forms and open shadow roots', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-number"></form><form><input autocomplete="cc-exp"></form><div id="shadow"></div>';
    document.getElementById('shadow')!.attachShadow({mode:'open'}).innerHTML = '<input autocomplete="cc-csc">';
    expect(cardForms(document, visible)).toHaveLength(2);
  });
  it.each([['text', 5, '', '03/30'], ['text', 7, '', '03/2030'], ['month', -1, '', '2030-03'], ['text', -1, 'MM/YYYY', '03/2030']])('formats expiry %s %s %s', (type, length, placeholder, expected) => {
    document.body.innerHTML = `<input autocomplete="cc-exp" type="${type}" maxlength="${length}" placeholder="${placeholder}">`;
    const form = cardForms(document, visible)[0]!; fillCard(form, card, visible);
    expect(form['cc-exp']!.value).toBe(expected);
  });
  it('validates every field again after page event handlers run', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const form = cardForms(document, visible)[0]!;
    form['cc-name']!.addEventListener('input', () => { form['cc-number']!.autocomplete = 'username'; });
    expect(() => fillCard(form, card, visible)).toThrow('payment form changed');
    expect(form['cc-number']!.value).toBe(''); expect(form['cc-csc']!.value).toBe('');
  });
  it('refuses stale targets and checks ambiguous dropdowns before releasing any values', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><select autocomplete="cc-exp-month"><option value="3">March</option><option value="03">03</option></select></form>';
    const form = cardForms(document, visible)[0]!;
    expect(() => fillCard(form, card, visible)).toThrow('ambiguous');
    expect(form['cc-number']!.value).toBe('');
    document.body.innerHTML = '<input autocomplete="cc-number">';
    expect(() => fillCard(cardForms(document, visible)[0]!, card, visible, () => false)).toThrow('payment form changed');
  });
  it('rejects malformed native card messages', () => {
    expect(() => parseWire({version:1, type:'Card', card:{...card,number:42},document_id:'doc',epoch:1})).toThrow();
    expect(parseWire({version:1, type:'Card', card,document_id:'doc',epoch:1}).type).toBe('Card');
  });
});
