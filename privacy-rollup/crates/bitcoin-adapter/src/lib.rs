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
use pr_protocol_types::{Outpoint, TxOut, Writer};
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

    /// Legacy (non-witness) serialization; its double SHA-256 is the txid.
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
}
