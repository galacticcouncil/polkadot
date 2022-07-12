// Copyright 2020 Parity Technologies (UK) Ltd.
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

mod mock;

use mock::{
	kusama_like_with_balances, AccountId, Balance, Balances, BaseXcmWeight, XcmConfig, CENTS,
};
use polkadot_parachain::primitives::Id as ParaId;
use pretty_assertions::assert_eq;
use sp_runtime::traits::AccountIdConversion;
use xcm::latest::prelude::*;
use xcm_executor::XcmExecutor;

pub const ALICE: AccountId = AccountId::new([0u8; 32]);
pub const PARA_ID: u32 = 2000;
pub const INITIAL_BALANCE: u128 = 100_000_000_000;
pub const REGISTER_AMOUNT: Balance = 10 * CENTS;

// Construct a `BuyExecution` order.
fn buy_execution<C>() -> Instruction<C> {
	BuyExecution { fees: (Here, REGISTER_AMOUNT).into(), weight_limit: Unlimited }
}

/// Scenario:
/// A parachain transfers funds on the relaychain to another parachain's account.
///
/// Asserts that the parachain accounts are updated as expected.
#[test]
fn withdraw_and_deposit_works() {
	let para_acc: AccountId = ParaId::from(PARA_ID).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let other_para_id = 3000;
		let amount = REGISTER_AMOUNT;
		let weight = 3 * BaseXcmWeight::get();
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				DepositAsset {
					assets: All.into(),
					max_assets: 1,
					beneficiary: Parachain(other_para_id).into(),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Complete(weight));
		let other_para_acc: AccountId = ParaId::from(other_para_id).into_account();
		assert_eq!(Balances::free_balance(para_acc), INITIAL_BALANCE - amount);
		let fees = 3;
		let amount_minus_fees = amount - fees;
		assert_eq!(Balances::free_balance(other_para_acc), amount_minus_fees);
	});
}

/// Scenario:
/// A parachain wants to be notified that a transfer worked correctly.
/// It includes a `QueryHolding` order after the deposit to get notified on success.
/// This somewhat abuses `QueryHolding` as an indication of execution success. It works because
/// order execution halts on error (so no `QueryResponse` will be sent if the previous order failed).
/// The inner response sent due to the query is not used.
///
/// Asserts that the balances are updated correctly and the expected XCM is sent.
#[test]
fn query_holding_works() {
	let para_acc: AccountId = ParaId::from(PARA_ID).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let other_para_id = 3000;
		let amount = REGISTER_AMOUNT;
		let query_id = 1234;
		let weight = 4 * BaseXcmWeight::get();
		let max_response_weight = 1_000_000_000;
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				DepositAsset {
					assets: All.into(),
					max_assets: 1,
					beneficiary: OnlyChild.into(), // invalid destination
				},
				// is not triggered becasue the deposit fails
				QueryHolding {
					query_id,
					dest: Parachain(PARA_ID).into(),
					assets: All.into(),
					max_response_weight,
				},
			]),
			weight,
		);
		assert_eq!(
			r,
			Outcome::Incomplete(
				weight - BaseXcmWeight::get(),
				XcmError::FailedToTransactAsset("AccountIdConversionFailed")
			)
		);
		// there should be no query response sent for the failed deposit
		assert_eq!(mock::sent_xcm(), vec![]);
		assert_eq!(Balances::free_balance(para_acc.clone()), INITIAL_BALANCE - amount);

		// now do a successful transfer
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				DepositAsset {
					assets: All.into(),
					max_assets: 1,
					beneficiary: Parachain(other_para_id).into(),
				},
				// used to get a notification in case of success
				QueryHolding {
					query_id,
					dest: Parachain(PARA_ID).into(),
					assets: All.into(),
					max_response_weight: 1_000_000_000,
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Complete(weight));
		let other_para_acc: AccountId = ParaId::from(other_para_id).into_account();
		let fees = 4;
		let amount_minus_fees = amount - fees;
		assert_eq!(Balances::free_balance(other_para_acc), amount_minus_fees);
		assert_eq!(Balances::free_balance(para_acc), INITIAL_BALANCE - 2 * amount);
		assert_eq!(
			mock::sent_xcm(),
			vec![(
				Parachain(PARA_ID).into(),
				Xcm(vec![QueryResponse {
					query_id,
					response: Response::Assets(vec![].into()),
					max_weight: 1_000_000_000,
				}]),
			)]
		);
	});
}

/// Scenario:
/// A parachain wants to move KSM from Kusama to Statemine.
/// The parachain sends an XCM to withdraw funds combined with a teleport to the destination.
///
/// This way of moving funds from a relay to a parachain will only work for trusted chains.
/// Reserve based transfer should be used to move KSM to a community parachain.
///
/// Asserts that the balances are updated accordingly and the correct XCM is sent.
#[test]
fn teleport_to_statemine_works() {
	let para_acc: AccountId = ParaId::from(PARA_ID).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let statemine_id = 1000;
		let other_para_id = 3000;
		let amount = REGISTER_AMOUNT;
		let teleport_effects = vec![
			buy_execution(), // unchecked mock value
			DepositAsset {
				assets: All.into(),
				max_assets: 1,
				beneficiary: (1, Parachain(PARA_ID)).into(),
			},
		];
		let weight = 3 * BaseXcmWeight::get();

		// teleports are allowed to community chains, even in the absence of trust from their side.
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				InitiateTeleport {
					assets: All.into(),
					dest: Parachain(other_para_id).into(),
					xcm: Xcm(teleport_effects.clone()),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Complete(weight));
		let fees = 3;
		let amount_minus_fees = amount - fees;
		assert_eq!(
			mock::sent_xcm(),
			vec![(
				Parachain(other_para_id).into(),
				Xcm(vec![ReceiveTeleportedAsset((Parent, amount_minus_fees).into()), ClearOrigin,]
					.into_iter()
					.chain(teleport_effects.clone().into_iter())
					.collect())
			)]
		);

		// teleports are allowed from statemine to kusama.
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				InitiateTeleport {
					assets: All.into(),
					dest: Parachain(statemine_id).into(),
					xcm: Xcm(teleport_effects.clone()),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Complete(weight));
		// 2 * amount because of the other teleport above
		assert_eq!(Balances::free_balance(para_acc), INITIAL_BALANCE - 2 * amount);
		assert_eq!(
			mock::sent_xcm(),
			vec![
				(
					Parachain(other_para_id).into(),
					Xcm(vec![ReceiveTeleportedAsset((Parent, amount_minus_fees).into()), ClearOrigin,]
						.into_iter()
						.chain(teleport_effects.clone().into_iter())
						.collect()),
				),
				(
					Parachain(statemine_id).into(),
					Xcm(vec![ReceiveTeleportedAsset((Parent, amount_minus_fees).into()), ClearOrigin,]
						.into_iter()
						.chain(teleport_effects.clone().into_iter())
						.collect()),
				)
			]
		);
	});
}

/// Scenario:
/// A parachain wants to move KSM from Kusama to the parachain.
/// It withdraws funds and then deposits them into the reserve account of the destination chain.
/// to the destination.
///
/// Asserts that the balances are updated accordingly and the correct XCM is sent.
#[test]
fn reserve_based_transfer_works() {
	let para_acc: AccountId = ParaId::from(PARA_ID).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let other_para_id = 3000;
		let amount = REGISTER_AMOUNT;
		let transfer_effects = vec![
			buy_execution(), // unchecked mock value
			DepositAsset {
				assets: All.into(),
				max_assets: 1,
				beneficiary: (1, Parachain(PARA_ID)).into(),
			},
		];
		let weight = 3 * BaseXcmWeight::get();
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			Parachain(PARA_ID).into(),
			Xcm(vec![
				WithdrawAsset((Here, amount).into()),
				buy_execution(),
				DepositReserveAsset {
					assets: All.into(),
					max_assets: 1,
					dest: Parachain(other_para_id).into(),
					xcm: Xcm(transfer_effects.clone()),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Complete(weight));
		assert_eq!(Balances::free_balance(para_acc), INITIAL_BALANCE - amount);
		let fees = 3;
		let amount_minus_fees = amount - fees;
		assert_eq!(
			mock::sent_xcm(),
			vec![(
				Parachain(other_para_id).into(),
				Xcm(vec![ReserveAssetDeposited((Parent, amount_minus_fees).into()), ClearOrigin,]
					.into_iter()
					.chain(transfer_effects.into_iter())
					.collect())
			)]
		);
	});
}

/// Scenario:
/// A parachain sends an XCM with an unknown asset to Kusama.
/// Asserts that those funds end up in the asset trap.
#[test]
fn unknown_tokens_are_trapped_on_failed_buy_execution() {
	use xcm::VersionedMultiAssets;
	use sp_runtime::traits::{BlakeTwo256, Hash};
	use crate::mock::XcmPallet;

	env_logger::init();

	let para_acc: AccountId = ParaId::from(PARA_ID).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let amount = REGISTER_AMOUNT;
		let weight = 4 * BaseXcmWeight::get();
		let asset: MultiAsset = (Parachain(PARA_ID), amount).into();
		let assets: MultiAssets = vec![asset.clone()].into();
		let origin = Parachain(PARA_ID).into();
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			origin.clone(),
			Xcm(vec![
				ReserveAssetDeposited(assets.clone()),
				ClearOrigin,
				BuyExecution {
					fees: asset, weight_limit: Limited(weight),
				},
				DepositAsset {
					assets: All.into(),
					max_assets: 1,
					beneficiary: Here.into(),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Incomplete(3 * BaseXcmWeight::get(), XcmError::TooExpensive));
		let versioned = VersionedMultiAssets::from(assets);
		let hash = BlakeTwo256::hash_of(&(&origin, &versioned));
		assert_eq!(XcmPallet::asset_trap(hash), 1);
	});
}

/// Scenario:
/// Statemine sends an XCM with KSM and an unknown asset to Kusama.
/// Asserts that those funds end up in the asset trap.
#[test]
fn unknown_tokens_are_trapped_on_failed_deposit() {
	use xcm::VersionedMultiAssets;
	use sp_runtime::traits::{BlakeTwo256, Hash};
	use crate::mock::XcmPallet;

	env_logger::init();

	let statemine_id = 1000;
	let para_acc: AccountId = ParaId::from(statemine_id).into_account();
	let balances = vec![(ALICE, INITIAL_BALANCE), (para_acc.clone(), INITIAL_BALANCE)];
	kusama_like_with_balances(balances).execute_with(|| {
		let amount = REGISTER_AMOUNT;
		let weight = 4 * BaseXcmWeight::get();
		let para_asset: MultiAsset = (X2(Parachain(statemine_id), GeneralIndex(1)), amount).into();
		let other_para_asset: MultiAsset = (X2(Parachain(statemine_id), GeneralIndex(2)), amount).into();
		let ksm: MultiAsset = (Here, amount).into();
		let assets: MultiAssets = vec![ksm.clone(), para_asset.clone(), other_para_asset.clone()].into();
		let origin = Parachain(statemine_id).into();
		let r = XcmExecutor::<XcmConfig>::execute_xcm(
			origin.clone(),
			Xcm(vec![
				ReserveAssetDeposited(assets.clone()),
				ClearOrigin,
				BuyExecution {
					fees: ksm, weight_limit: Limited(weight),
				},
				DepositAsset {
					assets: All.into(),
					max_assets: 3,
					beneficiary: Parachain(statemine_id).into(),
				},
			]),
			weight,
		);
		assert_eq!(r, Outcome::Incomplete(4 * BaseXcmWeight::get(), XcmError::AssetNotFound));
		let expected_assets: MultiAssets = vec![para_asset.clone(), other_para_asset.clone()].into();
		let versioned = VersionedMultiAssets::from(expected_assets);
		let hash = BlakeTwo256::hash_of(&(&origin, &versioned));
		assert_eq!(XcmPallet::asset_trap(hash), 1);
	});
}
