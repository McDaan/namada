//! Implementation of chain initialization for the Shell
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::parameters::Parameters;
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::storage_api::{token, StorageWrite};
use namada::types::key::*;
use sha2::{Digest, Sha256};

use super::*;
use crate::config::genesis::chain::{
    FinalizedEstablishedAccountTx, FinalizedTokenConfig, FinalizedTransactions,
    FinalizedValidatorAccountTx,
};
use crate::config::genesis::templates::{TokenBalances, TokenConfig};
use crate::config::genesis::transactions::{
    BondTx, EstablishedAccountTx, SignedBondTx, SignedTransferTx, TransferTx,
    ValidatorAccountTx,
};
use crate::facade::tendermint_proto::abci;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
use crate::facade::tendermint_proto::google::protobuf;
use crate::wasm_loader;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new genesis for the chain with specified id. This includes
    /// 1. A set of initial users and tokens
    /// 2. Setting up the validity predicates for both users and tokens
    pub fn init_chain(
        &mut self,
        init: request::InitChain,
    ) -> Result<response::InitChain> {
        let mut response = response::InitChain::default();
        let chain_id = self.wl_storage.storage.chain_id.as_str();
        if chain_id != init.chain_id.as_str() {
            return Err(Error::ChainId(format!(
                "Current chain ID: {}, Tendermint chain ID: {}",
                chain_id, init.chain_id
            )));
        }

        // Read the genesis files
        let chain_dir = self.base_dir.join(chain_id);
        let genesis = genesis::chain::Finalized::read_toml_files(&chain_dir)
            .expect("Missing genesis files");

        let ts: protobuf::Timestamp = init.time.expect("Missing genesis time");
        let initial_height = init
            .initial_height
            .try_into()
            .expect("Unexpected block height");
        // TODO hacky conversion, depends on https://github.com/informalsystems/tendermint-rs/issues/870
        let genesis_time: DateTimeUtc = (Utc
            .timestamp_opt(ts.seconds, ts.nanos as u32))
        .single()
        .expect("genesis time should be a valid timestamp")
        .into();

        // Initialize protocol parameters
        let parameters = genesis.get_chain_parameters(&self.wasm_dir);
        parameters.init_storage(&mut self.wl_storage);

        // Initialize governance parameters
        let gov_params = genesis.get_gov_params();
        gov_params.init_storage(&mut self.wl_storage);

        // Depends on parameters being initialized
        self.wl_storage
            .storage
            .init_genesis_epoch(initial_height, genesis_time, &parameters)
            .expect("Initializing genesis epoch must not fail");

        // Loaded VP code cache to avoid loading the same files multiple times
        let mut vp_code_cache: HashMap<String, Vec<u8>> = HashMap::default();

        // A helper to look-up path to a VP filename
        let mut lookup_vp = |name| {
            let config = genesis.vps.wasm.get(name).unwrap_or_else(|| {
                panic!("Missing validity predicate for {name}")
            });
            let vp_filename = &config.filename;
            vp_code_cache.get_or_insert_with(vp_filename.clone(), || {
                wasm_loader::read_wasm(&self.wasm_dir, &vp_filename).unwrap()
            })
        };

        // TODO refacotr these into fns

        // Init token accounts
        for (alias, token) in &genesis.tokens.token {
            tracing::debug!("Initializing token {alias}");

            let FinalizedTokenConfig {
                address,
                config: TokenConfig { vp },
            } = token;
            let vp_code = lookup_vp(vp);

            self.wl_storage
                .write(&Key::validity_predicate(address), vp_code)
                .unwrap();
        }

        // Init token balances
        for (token_alias, TokenBalances(balances)) in &genesis.balances.token {
            tracing::debug!("Initializing token balances {token_alias}");

            let token_address = &genesis
                .tokens
                .token
                .get(&token_alias)
                .expect("Token with configured balance not found in genesis.")
                .address;
            for (owner_pk, balance) in balances {
                let owner = Address::from(&owner_pk.raw);

                let pk_storage_key = pk_key(&owner);
                self.wl_storage
                    .write(&pk_storage_key, owner_pk.try_to_vec().unwrap())
                    .unwrap();

                token::credit_tokens(
                    &mut self.wl_storage,
                    token_address,
                    &owner,
                    *balance,
                )
                .expect("Couldn't credit initial balance");
            }
        }

        let FinalizedTransactions {
            established_account,
            validator_account,
            transfer,
            bond,
        } = &genesis.transactions;

        if let Some(txs) = established_account {
            for FinalizedEstablishedAccountTx {
                address,
                tx:
                    EstablishedAccountTx {
                        alias,
                        vp,
                        public_key,
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init an established account \
                     {alias}"
                );

                let vp_code = lookup_vp(&vp);
                self.wl_storage
                    .write_bytes(&Key::validity_predicate(&address), vp_code)
                    .unwrap();

                if let Some(pk) = public_key {
                    let pk_storage_key = pk_key(&address);
                    self.wl_storage
                        .write_bytes(&pk_storage_key, pk.try_to_vec().unwrap())
                        .unwrap();
                }

                // When using a faucet WASM, initialize its PoW challenge
                // storage
                #[cfg(not(feature = "mainnet"))]
                if vp.as_str() == "vp_testnet_faucet" {
                    let difficulty = genesis
                        .parameters
                        .parameters
                        .faucet_pow_difficulty
                        .unwrap_or_default();
                    // withdrawal limit defaults to 1000 NAM when not set
                    let withdrawal_limit = genesis
                        .parameters
                        .parameters
                        .faucet_withdrawal_limit
                        .unwrap_or_else(|| token::Amount::whole(1_000));
                    testnet_pow::init_faucet_storage(
                        &mut self.wl_storage,
                        &address,
                        difficulty,
                        withdrawal_limit,
                    )
                    .expect("Couldn't init faucet storage")
                }
            }
        }

        if let Some(txs) = validator_account.as_ref() {
            for FinalizedValidatorAccountTx {
                address,
                tx:
                    ValidatorAccountTx {
                        alias,
                        vp,
                        dkg_key,
                        commission_rate,
                        max_commission_rate_change,
                        net_address,
                        account_key,
                        consensus_key,
                        protocol_key,
                        tendermint_node_key,
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init a validator account {alias}"
                );

                let vp_code = lookup_vp(&vp);

                self.wl_storage
                    .write_bytes(&Key::validity_predicate(&address), vp_code)
                    .expect("Unable to write user VP");
                // Validator account key
                let pk_key = pk_key(&address);
                self.wl_storage
                    .write(&pk_key, &account_key)
                    .expect("Unable to set genesis user public key");
                self.wl_storage
                    .write(&protocol_pk_key(&address), &protocol_key.pk.raw)
                    .expect("Unable to set genesis user protocol public key");

                self.wl_storage
                    .write(
                        &dkg_session_keys::dkg_pk_key(&address),
                        &dkg_key.raw,
                    )
                    .expect(
                        "Unable to set genesis user public DKG session key",
                    );

                // TODO: replace pos::init_genesis validators arg with
                // init_genesis_validator from here
            }
        }

        if let Some(txs) = transfer {
            for SignedTransferTx {
                data:
                    TransferTx {
                        token,
                        source,
                        target,
                        amount,
                    },
                signature,
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to transfer token {token} from \
                     {source} to {target}"
                );

                let token = match genesis.get_token_address(&token) {
                    Some(token) => token,
                    None => {
                        tracing::warn!(
                            "Genesis token transfer tx uses an unknown token \
                             alias {token}. Skipping."
                        );
                        continue;
                    }
                };
                let target = match genesis.get_user_address(&target) {
                    Some(target) => target,
                    None => {
                        tracing::warn!(
                            "Genesis token transfer tx uses an unknown target \
                             alias {target}. Skipping."
                        );
                        continue;
                    }
                };
                let source: Address = (&source.raw).into();

                if let Err(err) = token::transfer(
                    &mut self.wl_storage,
                    &token,
                    &source,
                    &target,
                    *amount,
                ) {
                    tracing::warn!(
                        "Genesis token transfer tx failed with: {err}. \
                         Skipping."
                    );
                    continue;
                };
            }
        }

        if let Some(txs) = bond {
            for SignedBondTx {
                data:
                    BondTx {
                        source,
                        validator,
                        amount,
                    },
                signature,
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to bond {amount} native tokens from \
                     {source} to {validator}"
                );

                // TODO: apply bonds
            }
        }

        // PoS system depends on epoch being initialized
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let pos_params = genesis.get_pos_params();
        pos::init_genesis_storage(
            &mut self.wl_storage,
            &pos_params,
            [].into_iter(),
            // genesis
            //     .validators
            //     .clone()
            //     .into_iter()
            //     .map(|validator| validator.pos_data),
            current_epoch,
        );
        ibc::init_genesis_storage(&mut self.wl_storage.storage);

        // Set the initial validator set
        if let Some(txs) = validator_account.as_ref() {
            for FinalizedValidatorAccountTx {
                address,
                tx:
                    ValidatorAccountTx {
                        alias,
                        vp,
                        dkg_key,
                        commission_rate,
                        max_commission_rate_change,
                        net_address,
                        account_key,
                        consensus_key,
                        protocol_key,
                        tendermint_node_key,
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init a validator account {alias}"
                );

                let mut abci_validator = abci::ValidatorUpdate::default();
                let pub_key = TendermintPublicKey {
                    sum: Some(
                        key_to_tendermint(&consensus_key.pk.raw).unwrap(),
                    ),
                };
                abci_validator.pub_key = Some(pub_key);
                // TODO Read from PoS - must be after bonds txs
                let stake = token::Amount::default();
                abci_validator.power =
                    into_tm_voting_power(pos_params.tm_votes_per_token, stake);
                response.validators.push(abci_validator);
            }
        }

        self.wl_storage
            .commit_genesis()
            .expect("Must be able to commit genesis state");

        Ok(response)
    }
}

trait HashMapExt<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    /// Inserts a value computed from `f` into the map if the given `key` is not
    /// present, then returns a clone of the value from the map.
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V;
}

impl<K, V> HashMapExt<K, V> for HashMap<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V {
        use std::collections::hash_map::Entry;
        match self.entry(key) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => v.insert(f()).clone(),
        }
    }
}
