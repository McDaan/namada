//! Primitives that facilitate keeping track of the number
//! of bytes utilized by some Tendermint consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block, rejecting blocks whose size exceeds
//! the limit stated in [`RequestPrepareProposal`].
//!
//! The code in this module doesn't perform any deserializing to
//! verify if we are, in fact, allocating space for the correct
//! kind of tx for the current [`BlockSpaceAllocator`] state. It
//! is up to the user to dispatch the correct kind of tx into the
//! current state of the allocator.
//!
//! # How space is allocated
//!
//! In the current implementation, we allocate space for transactions
//! in the following order of preference:
//!
//! - First, we allocate space for DKG decrypted txs.
//! - Next, we allocate space for protocol txs. Protocol txs get 1/3 of the
//!   block space allotted to them.
//! - Finally, we allocate space for DKG encrypted txs.
//! - If any space remains, we try to fit other smaller txs in the block.
//!
//! Since decrypted txs will utilize at most as much space as
//! encrypted txs will utilize, and we allocate 1/3 of space
//! that has already been taken up by decrypted txs to protocol
//! txs, we roughly divide the block space in 3 for each kind
//! of major tx type.

pub mod states;

// TODO: what if a tx has a size greater than the threshold for
// its bin? how do we handle this? if we keep it in the mempool
// forever, it'll be a DoS vec, as we can make nodes run out of
// memory! maybe we should allow block decisions for txs that are
// too big to fit in their respective bin? in these special block
// decisions, we would only decide proposals with "large" txs??
//
// MAYBE: in the state machine impl, reset to beginning state, and
// and alloc space for large tx right at the start. the problem with
// this is that then we may not have enough space for decrypted txs

// TODO: panic if we don't have enough space reserved for a
// decrypted tx; in theory, we should always have enough space
// reserved for decrypted txs, given the invariants of the state
// machine

// TODO: refactor our measure of space to also reflect gas costs.
// the total gas of all chosen txs cannot exceed the configured max
// gas per block, otherwise a proposal will be rejected!

use std::marker::PhantomData;

use num_rational::Ratio;

use crate::facade::tendermint_proto::abci::RequestPrepareProposal;

/// All status responses from trying to allocate block space for a tx.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AllocStatus<'tx> {
    /// The transaction is able to be included in the current block.
    Accepted,
    /// The transaction can only be included in an upcoming block.
    Rejected { tx: &'tx [u8], space_left: u64 },
    /// The transaction would overflow the allotted bin space,
    /// therefore it needs to be handled separately.
    OverflowsBin { tx: &'tx [u8], bin_size: u64 },
}

/// Allotted space for a batch of transactions in some proposed block,
/// measured in bytes.
///
/// We keep track of the current space utilized by:
///
///   - Protocol transactions.
///   - DKG decrypted transactions.
///   - DKG encrypted transactions.
#[derive(Debug, Default)]
pub struct BlockSpaceAllocator<State> {
    /// The current state of the [`BlockSpaceAllocator`] state machine.
    _state: PhantomData<*const State>,
    /// The total space Tendermint has allotted to the
    /// application for the current block height.
    block: TxBin,
    /// The current space utilized by protocol transactions.
    protocol_txs: TxBin,
    /// The current space utilized by DKG encrypted transactions.
    encrypted_txs: TxBin,
    /// The current space utilized by DKG decrypted transactions.
    decrypted_txs: TxBin,
}

impl From<&RequestPrepareProposal>
    for BlockSpaceAllocator<states::BuildingDecryptedTxBatch>
{
    #[inline]
    fn from(req: &RequestPrepareProposal) -> Self {
        let tendermint_max_block_space_in_bytes = req.max_tx_bytes as u64;
        Self::init(tendermint_max_block_space_in_bytes)
    }
}

impl BlockSpaceAllocator<states::BuildingDecryptedTxBatch> {
    /// Construct a new [`BlockSpaceAllocator`], with an upper bound
    /// on the max size of all txs in a block defined by Tendermint.
    #[inline]
    pub fn init(tendermint_max_block_space_in_bytes: u64) -> Self {
        let max = tendermint_max_block_space_in_bytes;
        Self {
            _state: PhantomData,
            block: TxBin::init(max),
            protocol_txs: TxBin::default(),
            encrypted_txs: TxBin::default(),
            // decrypted txs can use as much space as needed; in practice,
            // we'll only need, at most, the amount of space reserved for
            // encrypted txs at the prev block height
            decrypted_txs: TxBin::init(max),
        }
    }
}

impl<State> BlockSpaceAllocator<State> {
    /// Return the amount of space left to initialize in all
    /// [`TxBin`] instances.
    ///
    /// This is calculated based on the difference between the Tendermint
    /// block space for a given round and the sum of the allotted space
    /// to each [`TxBin`] instance in a [`BlockSpaceAllocator`].
    #[inline]
    fn uninitialized_space_in_bytes(&self) -> u64 {
        let total_bin_space = self.protocol_txs.allotted_space_in_bytes
            + self.encrypted_txs.allotted_space_in_bytes
            + self.decrypted_txs.allotted_space_in_bytes;
        self.block.allotted_space_in_bytes - total_bin_space
    }

    /// Claim all the space used by the [`TxBin`] instances
    /// as block space.
    #[inline]
    fn claim_block_space(&mut self) {
        let used_space = self.protocol_txs.occupied_space_in_bytes
            + self.encrypted_txs.occupied_space_in_bytes
            + self.decrypted_txs.occupied_space_in_bytes;

        self.block.occupied_space_in_bytes = used_space;

        self.decrypted_txs = TxBin::default();
        self.protocol_txs = TxBin::default();
        self.encrypted_txs = TxBin::default();
    }
}

/// Allotted space for a batch of transactions of the same kind in some
/// proposed block, measured in bytes.
#[derive(Debug, Copy, Clone, Default)]
struct TxBin {
    /// The current space utilized by the batch of transactions.
    occupied_space_in_bytes: u64,
    /// The maximum space the batch of transactions may occupy.
    allotted_space_in_bytes: u64,
}

impl TxBin {
    /// Construct a new [`TxBin`], with an upper bound on the max number
    /// of storable txs defined by a ratio over `max_bytes`.
    #[inline]
    fn init_over_ratio(max_bytes: u64, frac: Ratio<u64>) -> Self {
        let allotted_space_in_bytes = (frac * max_bytes).to_integer();
        Self {
            allotted_space_in_bytes,
            occupied_space_in_bytes: 0,
        }
    }

    /// Return the amount of space left in this [`TxBin`].
    #[inline]
    fn space_left_in_bytes(&self) -> u64 {
        self.allotted_space_in_bytes - self.occupied_space_in_bytes
    }

    /// Construct a new [`TxBin`], with a capacity of `max_bytes`.
    #[inline]
    fn init(max_bytes: u64) -> Self {
        Self {
            allotted_space_in_bytes: max_bytes,
            occupied_space_in_bytes: 0,
        }
    }

    /// Shrink the allotted space of this [`TxBin`] to whatever
    /// space is currently being utilized.
    #[inline]
    fn shrink_to_fit(&mut self) {
        self.allotted_space_in_bytes = self.occupied_space_in_bytes;
    }

    /// Try to dump a new transaction into this [`TxBin`].
    ///
    /// Signal the caller if the tx is larger than its max
    /// allotted bin space.
    fn try_dump<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        let tx_len = tx.len() as u64;
        if tx_len > self.allotted_space_in_bytes {
            let bin_size = self.allotted_space_in_bytes;
            return AllocStatus::OverflowsBin { tx, bin_size };
        }
        let occupied = self.occupied_space_in_bytes + tx_len;
        if occupied <= self.allotted_space_in_bytes {
            self.occupied_space_in_bytes = occupied;
            AllocStatus::Accepted
        } else {
            let space_left = self.space_left_in_bytes();
            AllocStatus::Rejected { tx, space_left }
        }
    }

    /// Try to dump a new batch of transactions into this [`TxBin`].
    ///
    /// If an allocation fails, rollback the state of the [`TxBin`],
    /// and return the respective status of the failure.
    fn try_dump_all<'tx, T>(&mut self, txs: T) -> AllocStatus<'tx>
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        let mut space_diff = 0;
        for tx in txs {
            match self.try_dump(tx) {
                AllocStatus::Accepted => space_diff += tx.len() as u64,
                status @ (AllocStatus::Rejected { .. }
                | AllocStatus::OverflowsBin { .. }) => {
                    self.occupied_space_in_bytes -= space_diff;
                    return status;
                }
            }
        }
        AllocStatus::Accepted
    }
}

mod threshold {
    //! Transaction allotment thresholds.

    use num_rational::Ratio;

    /// The threshold over Tendermint's allotted space for all three
    /// (major) kinds of Namada transactions.
    pub const ONE_THIRD: Ratio<u64> = Ratio::new_raw(1, 3);
}
