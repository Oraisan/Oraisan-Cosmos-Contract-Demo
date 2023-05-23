use thiserror::Error;
use cosmwasm_std::{StdError, Addr};

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Name has been taken (name {contract})")]
    TokenLock { contract: Addr },

    #[error("Unauthorized")]
    Unauthorized {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}
