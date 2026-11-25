//! Shared Solana wire codecs used by Blockzilla and source adapters.
//!
//! These codecs preserve the existing signed transaction, execution metadata
//! and source metadata encodings. CAR transport and reconstruction are owned
//! by the separate source adapter.

pub mod blockmarker;
mod convert_metadata;
pub mod metadata_decoder;
pub mod short_vec;
pub mod slot_meta;
pub mod stored_transaction;
pub mod versioned_transaction;

pub mod confirmed_block {
    include!(concat!(
        env!("OUT_DIR"),
        "/solana.storage.confirmed_block.rs"
    ));
}

#[doc(hidden)]
pub mod confirmed_block_borrowed {
    #![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/quick-protobuf/mod.rs"));
}
