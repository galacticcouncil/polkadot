// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Error handling related code and Error/Result definitions.

use thiserror::Error;

use parity_scale_codec::{Decode, Encode, Error as DecodingError};

use polkadot_node_subsystem_util::{runtime, unwrap_non_fatal, Fault};

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(pub Fault<NonFatal, Fatal>);

impl From<NonFatal> for Error {
	fn from(e: NonFatal) -> Self {
		Self(Fault::from_non_fatal(e))
	}
}

impl From<Fatal> for Error {
	fn from(f: Fatal) -> Self {
		Self(Fault::from_fatal(f))
	}
}

impl From<runtime::Error> for Error {
	fn from(o: runtime::Error) -> Self {
		Self(Fault::from_other(o))
	}
}

/// Fatal errors when receiving incoming requests.
#[derive(Debug, Error)]
pub enum Fatal {
	/// Incoming request stream exhausted. Should only happen on shutdown.
	#[error("Incoming request channel got closed.")]
	RequestChannelExhausted,
}

/// Non-fatal errors when receiving incoming requests.
#[derive(Debug, Error)]
pub enum NonFatal {
	/// Decoding failed, we were able to change the peer's reputation accordingly.
	#[error("Decoding request failed for peer {0}.")]
	DecodingError(PeerId, #[source] DecodingError),

	/// Decoding failed, but sending reputation change failed.
	#[error("Decoding request failed for peer {0}, and changing reputation failed.")]
	DecodingErrorNoReputationChange(PeerId, #[source] DecodingError),
}

pub type Result<T> = std::result::Result<T, Error>;
