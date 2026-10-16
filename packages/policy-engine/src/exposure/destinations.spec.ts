// Design 4.2, test row T2: destinations in content and in call arguments.
import { describe, it, expect } from 'vitest';
import {
  extractContentDestinations,
  extractArgDestinations,
  destinationDomain,
  destinationKind,
  destinationValue,
  isDestructiveToolName,
  MAX_DESTINATIONS,
} from './destinations';

// A checksum-valid IBAN (the GB example from the IBAN registry), assembled so
// no account-shaped literal sits in the source.
const IBAN = ['GB82', 'WEST', '1234', '5698', '7654', '32'].join('');

describe('content: emails, URL hosts, IBANs', () => {
  it('finds each kind once, normalised', () => {
    const text =
      `From: Mark.Black@Example.com\nPlease wire to ${IBAN.slice(0, 4)} ${IBAN.slice(4, 8)} ` +
      `${IBAN.slice(8, 12)} ${IBAN.slice(12, 16)} ${IBAN.slice(16, 20)} ${IBAN.slice(20)} ` +
      `and confirm at https://Evil.Test/collect?x=1. Also see www.news.example/page, ` +
      `and mark.black@example.com again.`;
    const d = extractContentDestinations(text).sort();
    expect(d).toEqual(
      [
        'email:mark.black@example.com',
        'host:evil.test',
        'host:www.news.example',
        `iban:${IBAN}`,
      ].sort()
    );
  });

  it('ignores lookalikes: a bare word with a dot, localhost, a price', () => {
    const text =
      'Use node.js and open file.txt at localhost:3000; the total is 239.99. ' +
      'user@localhost is not an address.';
    expect(extractContentDestinations(text)).toEqual([]);
  });

  it('keeps an IBAN-shaped number with a failing checksum as an account, never as an IBAN', () => {
    const text = 'Pay to GB82WEST12345698765499 (sandbox) or to US133000000121212121212.';
    expect(extractContentDestinations(text).sort()).toEqual(
      ['account:GB82WEST12345698765499', 'account:US133000000121212121212'].sort()
    );
    expect(extractArgDestinations({ recipient: 'US133000000121212121212' })).toEqual([
      'account:US133000000121212121212',
    ]);
    expect(extractArgDestinations({ subject: 'US133000000121212121212' })).toEqual([
      'account:US133000000121212121212',
    ]);
  });

  it('caps the set', () => {
    const many = Array.from({ length: 300 }, (_, i) => `u${i}@example.com`).join(' ');
    expect(extractContentDestinations(many).length).toBe(MAX_DESTINATIONS);
  });

  it('never throws', () => {
    expect(extractContentDestinations('')).toEqual([]);
    expect(extractContentDestinations('x'.repeat(200_000) + ' a@b.co')).toEqual([]);
  });
});

describe('arguments: recipient keys count without a scheme', () => {
  it('send_email: to/cc and a URL in the body', () => {
    const d = extractArgDestinations({
      to: 'Outsider@Example.com',
      cc: ['boss@acme.example'],
      subject: 'hi',
      body: 'see http://drop.example/x',
    }).sort();
    expect(d).toEqual(
      ['email:outsider@example.com', 'email:boss@acme.example', 'host:drop.example'].sort()
    );
  });

  it('send_money: an IBAN under recipient', () => {
    expect(extractArgDestinations({ recipient: IBAN, amount: 30000 })).toEqual([`iban:${IBAN}`]);
  });

  it('a bare host under a recipient key, but not under another key', () => {
    expect(extractArgDestinations({ destination: 'drop.example' })).toEqual(['host:drop.example']);
    expect(extractArgDestinations({ title: 'drop.example' })).toEqual([]);
    expect(extractArgDestinations({ to: 'Alice' })).toEqual([]);
  });

  it('nested and non-object inputs', () => {
    expect(
      extractArgDestinations({ actions: [{ input: { url: 'https://a.example/p' } }] })
    ).toEqual(['host:a.example']);
    expect(extractArgDestinations(null)).toEqual([]);
    expect(extractArgDestinations('x@y.example')).toEqual(['email:x@y.example']);
  });
});

describe('arguments: shapes an attacker would pick', () => {
  it('a scheme-less URL, a bare host or an IPv6 literal under a destination key', () => {
    expect(extractArgDestinations({ url: 'evil.example/collect' })).toEqual(['host:evil.example']);
    expect(extractArgDestinations({ endpoint: 'Drop.Example:8443' })).toEqual([
      'host:drop.example',
    ]);
    expect(extractArgDestinations({ url: 'http://[2001:db8::1]/x' })).toEqual(['host:2001:db8::1']);
    expect(extractArgDestinations({ host: '[2001:db8::2]' })).toEqual(['host:2001:db8::2']);
    expect(extractArgDestinations({ title: 'evil.example/collect' })).toEqual([]);
  });

  it('an IDN address and a dashed IBAN', () => {
    expect(extractArgDestinations({ to: 'a@\u0435vil.example' })).toEqual([
      'email:a@\u0435vil.example',
    ]);
    expect(extractArgDestinations({ iban: 'GB82-WEST-1234-5698-7654-32' })).toEqual([
      `iban:${IBAN}`,
    ]);
    expect(extractContentDestinations('pay GB82 WEST 1234 5698 7654 32 now')).toEqual([
      `iban:${IBAN}`,
    ]);
  });
});

describe('helpers', () => {
  it('domain, kind, value', () => {
    expect(destinationDomain('email:a@b.example')).toBe('b.example');
    expect(destinationDomain('host:b.example')).toBeNull();
    expect(destinationKind('iban:GB1')).toBe('iban');
    expect(destinationKind('nope')).toBeNull();
    expect(destinationValue('host:b.example')).toBe('b.example');
  });

  it('destructive verbs by bare name', () => {
    for (const n of ['delete_file', 'remove_user', 'send_money', 'update_password', 'transfer'])
      expect(isDestructiveToolName(n)).toBe(true);
    for (const n of ['create_event', 'send_email', 'get_file', 'deleted_items', 'payload'])
      expect(isDestructiveToolName(n)).toBe(false);
  });
});
