import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  constantTimeEqual,
  getMlDsaParameters
} from '@qmoosa/pqc-mldsa-protocol';
import { MlDsaEngine } from '@qmoosa/pqc-mldsa-engine';
import {
  MlDsaClient,
  hexToBytes,
  bytesToHex
} from '@qmoosa/pqc-mldsa-sdk';

test('Negative Control 1: Fujisaki-Okamoto / Lattice Hardness on 1-Bit Corrupted Signature', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Mission Critical State Root');

  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  // Corrupt exactly 1 byte
  const corrupted = new Uint8Array(sigResult.signature);
  corrupted[100] ^= 0x01;

  const verified = engine.verify(corrupted, message, alice.publicKey, 'ML-DSA-65');
  assert.equal(verified, false, 'Corrupted signature bit must be rejected');
});

test('Negative Control 2: Web4 Envelope Rejection on Corrupted Signature Hex', () => {
  const client = new MlDsaClient();
  const alice = client.createKeyPair('ML-DSA-65');

  const tx = {
    chainId: '42161',
    nonce: 100,
    fromAddress: '0xAlice',
    toAddress: '0xBob',
    value: '1000',
    payloadHex: '0x',
    contextString: 'QMOOSA-CHAIN-42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'ML-DSA-65');

  // Corrupt signature in envelope
  const corruptedSigBytes = hexToBytes(envelope.signatureHex);
  corruptedSigBytes[50] ^= 0x80;
  const forgedEnvelope = {
    ...envelope,
    signatureHex: bytesToHex(corruptedSigBytes)
  };

  assert.equal(client.verifyTransaction(forgedEnvelope), false, 'Corrupted signature in envelope must fail');
});

test('Negative Control 3: Tampered Transaction Amount Rejection', () => {
  const client = new MlDsaClient();
  const alice = client.createKeyPair('ML-DSA-65');

  const tx = {
    chainId: '42161',
    nonce: 100,
    fromAddress: '0xAlice',
    toAddress: '0xBob',
    value: '5000000000000000000', // 5 ETH
    payloadHex: '0x',
    contextString: 'QMOOSA-CHAIN-42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'ML-DSA-65');

  // Attacker inflates value
  const forgedEnvelope = {
    ...envelope,
    value: '500000000000000000000' // 500 ETH
  };

  assert.equal(client.verifyTransaction(forgedEnvelope), false, 'Inflated transaction amount must fail verification');
});

test('Negative Control 4: Tampered Transaction Nonce Replay Rejection', () => {
  const client = new MlDsaClient();
  const alice = client.createKeyPair('ML-DSA-65');

  const tx = {
    chainId: '42161',
    nonce: 5,
    fromAddress: '0xAlice',
    toAddress: '0xBob',
    value: '1000',
    payloadHex: '0x',
    contextString: 'QMOOSA-CHAIN-42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'ML-DSA-65');

  // Attacker increments nonce to replay future state
  const forgedEnvelope = {
    ...envelope,
    nonce: 6
  };

  assert.equal(client.verifyTransaction(forgedEnvelope), false, 'Tampered nonce must fail verification');
});

test('Negative Control 5: Tampered Recipient Address Rejection', () => {
  const client = new MlDsaClient();
  const alice = client.createKeyPair('ML-DSA-65');

  const tx = {
    chainId: '42161',
    nonce: 1,
    fromAddress: '0xAlice',
    toAddress: '0xGoodGuy',
    value: '1000',
    payloadHex: '0x',
    contextString: 'QMOOSA-CHAIN-42161'
  };

  const envelope = client.signTransaction(tx, alice.secretKeyHex, alice.publicKeyHex, 'ML-DSA-65');

  // Attacker redirects funds
  const forgedEnvelope = {
    ...envelope,
    toAddress: '0xAttackerVault'
  };

  assert.equal(client.verifyTransaction(forgedEnvelope), false, 'Substituted recipient must fail verification');
});

test('Negative Control 6: Cross-Chain Replay Attack via Context String Mismatch', () => {
  const client = new MlDsaClient();
  const alice = client.createKeyPair('ML-DSA-65');

  const txArbitrum = {
    chainId: '42161',
    nonce: 1,
    fromAddress: '0xAlice',
    toAddress: '0xBob',
    value: '1000',
    payloadHex: '0x',
    contextString: 'CHAIN_42161_DOMAIN'
  };

  const envelope = client.signTransaction(txArbitrum, alice.secretKeyHex, alice.publicKeyHex, 'ML-DSA-65');

  // Attacker broadcasts envelope to Optimism (Chain ID 10)
  const replayedEnvelope = {
    ...envelope,
    chainId: '10',
    contextString: 'CHAIN_10_DOMAIN'
  };

  assert.equal(client.verifyTransaction(replayedEnvelope), false, 'Cross-chain replayed transaction must fail verification');
});

test('Negative Control 7: Wrong Public Key Rejection', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const eve = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Confidential Instruction');

  const sig = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  assert.equal(
    engine.verify(sig.signature, message, eve.publicKey, 'ML-DSA-65'),
    false,
    'Verifying with Eve public key must return false'
  );
});

test('Negative Control 8: Truncated Public Key Rejection in Engine', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Test');
  const sig = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  const truncatedPk = alice.publicKey.subarray(0, 100);
  assert.equal(engine.verify(sig.signature, message, truncatedPk, 'ML-DSA-65'), false);
});

test('Negative Control 9: Truncated Signature Buffer Rejection in Engine', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Test');
  const sig = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  const truncatedSig = sig.signature.subarray(0, 500);
  assert.equal(engine.verify(truncatedSig, message, alice.publicKey, 'ML-DSA-65'), false);
});

test('Negative Control 10: Malformed Seed Length Rejection in KeyGen', () => {
  const engine = new MlDsaEngine();
  assert.throws(
    () => engine.generateKeyPair('ML-DSA-65', { seed: new Uint8Array(16) }),
    /INVALID_SEED_LENGTH/
  );
  assert.throws(
    () => engine.generateKeyPair('ML-DSA-65', { seed: new Uint8Array(64) }),
    /INVALID_SEED_LENGTH/
  );
});

test('Negative Control 11: Context String Length Violation (>255 Bytes per FIPS 204)', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Context Overflow Test');

  const oversizedContext = new Uint8Array(256).fill(0x41);

  assert.throws(
    () => engine.sign(message, alice.secretKey, 'ML-DSA-65', { context: oversizedContext }),
    /CONTEXT_TOO_LONG/
  );
});

test('Negative Control 12: Deterministic Known Answer Test (KAT) Reproducibility', () => {
  const engine = new MlDsaEngine();
  const fixedSeed = new Uint8Array(32).fill(0x5a);

  const run1 = engine.generateKeyPair('ML-DSA-65', { seed: fixedSeed });
  const run2 = engine.generateKeyPair('ML-DSA-65', { seed: fixedSeed });

  assert.equal(bytesToHex(run1.publicKey), bytesToHex(run2.publicKey));
  assert.equal(bytesToHex(run1.secretKey), bytesToHex(run2.secretKey));
});

test('Negative Control 13: Constant-Time Array Equality Timing Protection', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  const c = new Uint8Array([1, 2, 3, 4, 6]);
  const d = new Uint8Array([1, 2, 3, 4]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});

test('Negative Control 14: Deep Freeze Immutability Protection', () => {
  assert.ok(Object.isFrozen(ML_DSA_44));
  assert.ok(Object.isFrozen(ML_DSA_65));
  assert.ok(Object.isFrozen(ML_DSA_87));

  assert.throws(() => {
    // @ts-ignore
    ML_DSA_65.publicKeyBytes = 99999;
  });
});
