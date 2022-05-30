#!/usr/bin/env bash
set -e

SUBKEY=subkey

if [ "$#" -ne 1 ]; then
	echo "Please provide the number of initial validators!"
	exit 1
fi

generate_account_id() {
	$SUBKEY inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Account ID" | awk '{ print $3 }'
}

generate_address() {
	$SUBKEY inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "SS58 Address" | awk '{ print $3 }'
}

generate_public_key() {
  $SUBKEY inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Public key (hex)" | awk '{ print $4 }'
}

generate_secret_seed() {
	$SUBKEY inspect ${3:-} ${4:-} "$SECRET//$1//$2" | grep "Secret seed" | awk '{ print $3 }'
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

get_json() {
  JSON="{"
  JSON+='  "jsonrpc":"2.0",\n'
  JSON+='  "id":1,\n'
  JSON+='  "method":"author_insertKey",\n'
  JSON+='  "params": [\n'
  JSON+="    \"$1\",\n"
  JSON+="    \"$2\",\n"
  JSON+="    \"$3\"\n"
  JSON+="  ]\n"
  JSON+="}\n\n"

  printf "$JSON"
}

V_NUM=$1

AUTHORITIES=""

SECRETS=""

for i in $(seq 1 $V_NUM); do
	AUTHORITIES+="(\n"
	AUTHORITIES+="$(generate_address_and_account_id $i stash)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i controller)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i babe '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i grandpa '--scheme ed25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i im_online '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i para_validator '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i para_assignment '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_account_id $i authority_discovery '--scheme sr25519' true)\n"
	AUTHORITIES+="$(generate_address_and_public_key $i beefy '--scheme ecdsa' true)\n"
	AUTHORITIES+="),\n"

  mkdir -p ../keys/relaychain/v$i
  echo "$(get_json "babe" "$(generate_secret_seed $i babe '--scheme sr25519')" "$(generate_public_key $i babe '--scheme sr25519')")" > ../keys/relaychain/v$i/babe.json
  echo "$(get_json "gran" "$(generate_secret_seed $i grandpa '--scheme ed25519')" "$(generate_public_key $i grandpa '--scheme ed25519')")" > ../keys/relaychain/v$i/grandpa.json
  echo "$(get_json "imon" "$(generate_secret_seed $i im_online '--scheme sr25519')" "$(generate_public_key $i im_online '--scheme sr25519')")" > ../keys/relaychain/v$i/im_online.json
  echo "$(get_json "para" "$(generate_secret_seed $i para_validator '--scheme sr25519')" "$(generate_public_key $i para_validator '--scheme sr25519')")" > ../keys/relaychain/v$i/para_validator.json
  echo "$(get_json "asgn" "$(generate_secret_seed $i para_assignment '--scheme sr25519')" "$(generate_public_key $i para_assignment '--scheme sr25519')")" > ../keys/relaychain/v$i/para_assignment.json
  echo "$(get_json "audi" "$(generate_secret_seed $i authority_discovery '--scheme sr25519')" "$(generate_public_key $i authority_discovery '--scheme sr25519')")" > ../keys/relaychain/v$i/authority_discovery.json
  echo "$(get_json "beef" "$(generate_secret_seed $i beefy '--scheme ecdsa')" "$(generate_public_key $i beefy '--scheme ecdsa')")" > ../keys/relaychain/v$i/beefy.json
done

printf "$AUTHORITIES"

