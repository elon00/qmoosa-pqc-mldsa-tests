import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  constantTimeEqual
} from '@qmoosa/pqc-mldsa-protocol';
import { MlDsaEngine } from '@qmoosa/pqc-mldsa-engine';
import {
  MlDsaClient,
  canonicalTransactionHash
} from '@qmoosa/pqc-mldsa-sdk';

test('Integration Reality: Cross-Subsystem End-to-End Web4 Transaction Lifecycle', () => {
  const client = new MlDsaClient();

  // 1. Participant generates post-quantum signature keypair
  const alice = client.createKeyPair('ML-DSA-65');
  assert.equal(alice.parameterSet, 'ML-DSA-65');
  assert.equal(alice.publicKeyHex.length, ML_DSA_65.publicKeyBytes * 2);
  assert.equal(alice.secretKeyHex.length, ML_DSA_65.secretKeyBytes * 2);

  // 2. Construct Web4 transaction
  const tx = {
    chainId: '42161',
    nonce: 1042,
    fromAddress: '0xAlicePqcAccount',
    toAddress: '0xSovereignVault',
    value: '25000000000000000000',
    payloadHex: '0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111',
    contextString: 'QMOOSA-ARBITRUM-ONE-TX:42161'
  };

  // 3. Client signs transaction envelope
  const signedEnvelope = client.signTransaction(
    tx,
    alice.secretKeyHex,
    alice.publicKeyHex,
    'ML-DSA-65'
  );

  assert.equal(signedEnvelope.chainId, '42161');
  assert.equal(signedEnvelope.signatureHex.length, ML_DSA_65.signatureBytes * 2);

  // 4. Verifier / Smart Contract validates envelope
  const isAuthentic = client.verifyTransaction(signedEnvelope);
  assert.equal(isAuthentic, true, 'Genuine transaction envelope must verify successfully in integration');
});

test('Integration Reality: Multi-Tier Parameter Set Signature Pipeline (44, 65, 87)', () => {
  const engine = new MlDsaEngine();
  const client = new MlDsaClient(engine);

  // Tier 1: ML-DSA-44 (Edge Device)
  const edge = client.createKeyPair('ML-DSA-44');
  const edgePayload = new TextEncoder().encode('IoT Sensor Reading #1');
  const edgeSig = client.signMessage(edgePayload, edge.secretKeyHex, 'ML-DSA-44', {
    context: 'EDGE-IOT-SENSOR'
  });
  assert.equal(
    client.verifySignature(edgeSig.signatureHex, edgePayload, edge.publicKeyHex, 'ML-DSA-44', {
      context: 'EDGE-IOT-SENSOR'
    }),
    true
  );

  // Tier 2: ML-DSA-65 (Consensus Block Proposal)
  const validator = client.createKeyPair('ML-DSA-65');
  const blockHeader = new TextEncoder().encode('Block Header #1042000');
  const blockSig = client.signMessage(blockHeader, validator.secretKeyHex, 'ML-DSA-65', {
    context: 'WEB4-CONSENSUS-BLOCK'
  });
  assert.equal(
    client.verifySignature(blockSig.signatureHex, blockHeader, validator.publicKeyHex, 'ML-DSA-65', {
      context: 'WEB4-CONSENSUS-BLOCK'
    }),
    true
  );

  // Tier 3: ML-DSA-87 (Governance Anchor)
  const govAnchor = client.createKeyPair('ML-DSA-87');
  const govAction = new TextEncoder().encode('Execute Governance Emergency Halt Override');
  const govSig = client.signMessage(govAction, govAnchor.secretKeyHex, 'ML-DSA-87', {
    context: 'GOVERNANCE-EMERGENCY-OVERRIDE'
  });
  assert.equal(
    client.verifySignature(govSig.signatureHex, govAction, govAnchor.publicKeyHex, 'ML-DSA-87', {
      context: 'GOVERNANCE-EMERGENCY-OVERRIDE'
    }),
    true
  );
});
