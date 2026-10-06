//! Segwit serialization of a settlement: the operator's witness-free `SettlementTx` plus one
//! witness stack per input.
use pr_bitcoin_adapter::SettlementTx;
use pr_protocol_types::Writer;

pub fn serialize_segwit(tx: &SettlementTx, witnesses: &[Vec<Vec<u8>>]) -> Vec<u8> {
    assert_eq!(witnesses.len(), tx.inputs.len(), "one witness per input");
    let mut w = Writer::new();
    w.u32(tx.version).bytes(&[0x00, 0x01]).compact_size(tx.inputs.len() as u64);
    for i in &tx.inputs {
        w.bytes(&i.prevout.txid).u32(i.prevout.vout).var_bytes(&i.script_sig).u32(i.sequence);
    }
    w.compact_size(tx.outputs.len() as u64);
    for o in &tx.outputs {
        w.u64(o.value).var_bytes(&o.script_pubkey);
    }
    for stack in witnesses {
        w.compact_size(stack.len() as u64);
        for item in stack {
            w.var_bytes(item);
        }
    }
    w.u32(tx.lock_time);
    w.finish()
}

/// Txid in display (RPC) byte order.
pub fn display_txid(tx: &SettlementTx) -> String {
    let mut id = tx.txid();
    id.reverse();
    hex::encode(id)
}

/// BIP-141 weight: 3 × base size + total size.
pub fn weight(tx: &SettlementTx, raw: &[u8]) -> u64 {
    3 * tx.serialize_legacy().len() as u64 + raw.len() as u64
}

#[cfg(test)]
mod tests {
    use pr_bitcoin_adapter::TxInput;
    use pr_protocol_types::{Outpoint, TxOut};

    use super::*;

    #[test]
    fn segwit_layout_and_txid() {
        let tx = SettlementTx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxInput {
                prevout: Outpoint { txid: [0x11; 32], vout: 1 },
                amount: 5,
                script_pubkey: vec![0x51],
                script_sig: Vec::new(),
                sequence: 1,
            }],
            outputs: vec![TxOut { value: 4, script_pubkey: vec![0x51] }],
        };
        let raw = serialize_segwit(&tx, &[vec![vec![0x51], vec![]]]);
        let legacy = tx.serialize_legacy();
        assert_eq!(&raw[..4], &legacy[..4]);
        assert_eq!(&raw[4..6], &[0, 1]);
        assert_eq!(&raw[6..6 + legacy.len() - 8], &legacy[4..legacy.len() - 4]);
        assert_eq!(&raw[raw.len() - 8..], &[2, 1, 0x51, 0, 0, 0, 0, 0]);
        assert_eq!(weight(&tx, &raw), 3 * legacy.len() as u64 + raw.len() as u64);
        let mut id = tx.txid();
        id.reverse();
        assert_eq!(display_txid(&tx), hex::encode(id));
    }
}
