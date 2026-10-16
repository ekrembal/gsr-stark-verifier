//! The settlement transaction as the batch guest sees it, and the exact byte strings the covenant
//! reads with `OP_TX` and hashes into the journal.
//!
//! * inputs preimage: selector `00 07 00 20 3f 00` = collate, version, locktime, then for every input
//!   `txid[32] || vout u32 || amount u64 || cs(spk) || cs(scriptSig) || sequence u32`;
//! * outputs preimage: selector `00 01 00 02 00 03` = collate, every output `amount u64 || cs(spk)`,
//!   the BIP 341 `sha_outputs` preimage;
//! * annex: the raw annex of input zero, starting with `0x50`.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use pr_protocol_types::hash::sha256;
use pr_protocol_types::{DecodeError, Outpoint, Reader, TxOut, Writer};
use serde::{Deserialize, Serialize};

pub const INPUTS_SELECTOR: [u8; 6] = [0x00, 0x07, 0x00, 0x20, 0x3f, 0x00];
pub const OUTPUTS_SELECTOR: [u8; 6] = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
pub const ANNEX_SELECTOR: [u8; 6] = [0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
pub const INPUT_INDEX_SELECTOR: [u8; 6] = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00];

/// A settlement input with the output it spends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub prevout: Outpoint,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// The witness-free part of a settlement transaction plus its spent outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTx {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOut>,
}

impl SettlementTx {
    pub fn inputs_preimage(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.version).u32(self.lock_time);
        for i in &self.inputs {
            w.bytes(&i.prevout.txid)
                .u32(i.prevout.vout)
                .u64(i.amount)
                .var_bytes(&i.script_pubkey)
                .var_bytes(&i.script_sig)
                .u32(i.sequence);
        }
        w.finish()
    }

    pub fn outputs_preimage(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for o in &self.outputs {
            w.u64(o.value).var_bytes(&o.script_pubkey);
        }
        w.finish()
    }

    pub fn inputs_digest(&self) -> [u8; 32] {
        sha256(&self.inputs_preimage())
    }

    pub fn outputs_digest(&self) -> [u8; 32] {
        sha256(&self.outputs_preimage())
    }

    /// The settlement as Bitcoin serializes it without witnesses.
    pub fn plain(&self) -> PlainTx {
        PlainTx {
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(|i| PlainInput { prevout: i.prevout, script_sig: i.script_sig.clone(), sequence: i.sequence })
                .collect(),
            outputs: self.outputs.clone(),
        }
    }

    /// Legacy (non-witness) serialization; its double SHA-256 is the txid.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        self.plain().serialize_legacy()
    }

    pub fn txid(&self) -> [u8; 32] {
        self.plain().txid()
    }
}

/// An input as it appears in a transaction's legacy serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainInput {
    pub prevout: Outpoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// Any Bitcoin transaction without its witnesses: exactly what its txid commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainTx {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<PlainInput>,
    pub outputs: Vec<TxOut>,
}

/// Bound on a decoded transaction (consensus caps a block at 4 MB of weight).
pub const MAX_TX_BYTES: usize = 4_000_000;

impl PlainTx {
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.version).compact_size(self.inputs.len() as u64);
        for i in &self.inputs {
            w.bytes(&i.prevout.txid).u32(i.prevout.vout).var_bytes(&i.script_sig).u32(i.sequence);
        }
        w.compact_size(self.outputs.len() as u64);
        for o in &self.outputs {
            w.u64(o.value).var_bytes(&o.script_pubkey);
        }
        w.u32(self.lock_time);
        w.finish()
    }

    pub fn txid(&self) -> [u8; 32] {
        sha256(&sha256(&self.serialize_legacy()))
    }

    /// Parses a legacy or BIP 144 (witness) serialization; witnesses are checked for shape and dropped.
    pub fn decode(bytes: &[u8]) -> Result<PlainTx, DecodeError> {
        if bytes.len() > MAX_TX_BYTES {
            return Err(DecodeError::LengthOutOfRange);
        }
        let mut r = Reader::new(bytes);
        let version = r.u32()?;
        let mut n_in = r.compact_size()?;
        let segwit = n_in == 0;
        if segwit {
            if r.u8()? != 1 {
                return Err(DecodeError::BadMagic);
            }
            n_in = r.compact_size()?;
            if n_in == 0 {
                return Err(DecodeError::LengthOutOfRange);
            }
        }
        let mut inputs = Vec::new();
        for _ in 0..n_in {
            let prevout = Outpoint { txid: r.array()?, vout: r.u32()? };
            let script_sig = r.var_bytes(MAX_TX_BYTES)?.to_vec();
            inputs.push(PlainInput { prevout, script_sig, sequence: r.u32()? });
        }
        let mut outputs = Vec::new();
        for _ in 0..r.compact_size()? {
            let value = r.amount()?;
            outputs.push(TxOut { value, script_pubkey: r.var_bytes(MAX_TX_BYTES)?.to_vec() });
        }
        if segwit {
            for _ in 0..n_in {
                for _ in 0..r.compact_size()? {
                    r.var_bytes(MAX_TX_BYTES)?;
                }
            }
        }
        let lock_time = r.u32()?;
        r.finish()?;
        Ok(PlainTx { version, lock_time, inputs, outputs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn preimages_have_op_tx_layout() {
        let tx = SettlementTx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxInput {
                prevout: Outpoint { txid: [7; 32], vout: 3 },
                amount: 1000,
                script_pubkey: vec![0x51, 0x20],
                script_sig: vec![],
                sequence: 1,
            }],
            outputs: vec![TxOut { value: 900, script_pubkey: vec![0x6a] }],
        };
        let p = tx.inputs_preimage();
        assert_eq!(p.len(), 4 + 4 + 32 + 4 + 8 + 3 + 1 + 4);
        assert_eq!(&p[..8], &[2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tx.outputs_preimage(), [&900u64.to_le_bytes()[..], &[1, 0x6a]].concat());
    }

    #[test]
    fn plain_tx_decodes_legacy_and_witness_forms_to_the_same_txid() {
        let tx = PlainTx {
            version: 2,
            lock_time: 7,
            inputs: vec![
                PlainInput { prevout: Outpoint { txid: [3; 32], vout: 1 }, script_sig: vec![], sequence: 1 },
                PlainInput { prevout: Outpoint { txid: [4; 32], vout: 0 }, script_sig: vec![0x51], sequence: 2 },
            ],
            outputs: vec![TxOut { value: 5000, script_pubkey: vec![0x00, 0x14] }],
        };
        let legacy = tx.serialize_legacy();
        assert_eq!(PlainTx::decode(&legacy), Ok(tx.clone()));
        let tail = legacy.len() - 4;
        let mut witness = [&legacy[..4], &[0x00, 0x01], &legacy[4..tail]].concat();
        witness.extend_from_slice(&[2, 1, 0xaa, 0, 1, 2, 0xbb, 0xcc]);
        witness.extend_from_slice(&legacy[tail..]);
        let decoded = PlainTx::decode(&witness).unwrap();
        assert_eq!(decoded.txid(), tx.txid());
        assert_eq!(PlainTx::decode(&[&witness[..], &[0]].concat()), Err(DecodeError::TrailingBytes));
        assert!(PlainTx::decode(&witness[..witness.len() - 1]).is_err());
    }
}
