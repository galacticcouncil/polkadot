#!/usr/bin/env bash
set -e

generate_account_id() {
	../substrate/target/release/subkey inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Account ID" | awk '{ print $3 }'
}

generate_address() {
	../substrate/target/release/subkey inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "SS58 Address" | awk '{ print $3 }'
}

generate_public_key() {
	../substrate/target/release/subkey inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Public" | awk '{ print $4 }'
}

generate_secret_seed() {
	../substrate/target/release/subkey inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Secret seed" | awk '{ print $3 }'
}

generate_address_and_public_key() {
	ADDRESS=$(generate_address $1 $2 $3)
	PUBLIC_KEY=$(generate_public_key $1 $2 $3)

	printf "//$ADDRESS\nhex![\"${PUBLIC_KEY#'0x'}\"].unchecked_into(),"
}

generate_address_and_account_id() {
	ACCOUNT=$(generate_account_id $1 $2 $3)
	ADDRESS=$(generate_address $1 $2 $3)
	if ${4:-false}; then
		INTO="unchecked_into"
	else
		INTO="into"
	fi

	printf "//$ADDRESS\nhex![\"${ACCOUNT#'0x'}\"].$INTO(),"
}

generate_secret_seed_for() {
 	SEED=$(generate_secret_seed $1 $2 $3)
  
	printf "$2: $SEED"
}

S_NUM=$1
E_NUM=$(($1+$2 - 1))

AUTHORITIES=""

for i in $(seq $S_NUM $E_NUM); do
	AUTHORITIES+="(\n"
	AUTHORITIES+="$(generate_address_and_account_id $i stash)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i controller)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i babe '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i grandpa '--scheme ed25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i im_online '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i para_validator '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i para_assignment '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i authority_discovery '--scheme sr25519' true)\n"
	AUTHORITIES+="),\n"
done

printf "$AUTHORITIES"

SECRETS=""
for j in $(seq $S_NUM $E_NUM); do
	SECRETS+="(\n"
	SECRETS+="$(generate_secret_seed_for $j babe '--scheme sr25519' true)\n"
	SECRETS+="$(generate_secret_seed_for $j grandpa '--scheme ed25519' true)\n"
	SECRETS+="$(generate_secret_seed_for $j im_online '--scheme sr25519' true)\n"
	SECRETS+="$(generate_secret_seed_for $j para_validator '--scheme sr25519' true)\n"
	SECRETS+="$(generate_secret_seed_for $j para_assignment '--scheme sr25519' true)\n"
	SECRETS+="$(generate_secret_seed_for $j authority_discovery '--scheme sr25519' true)\n"
	SECRETS+="),\n"
done

printf "$SECRETS"
