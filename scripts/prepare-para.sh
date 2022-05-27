#!/usr/bin/env bash
set -e

SUBKEY=../substrate/target/release/subkey

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
	AUTHORITIES+="$(generate_address_and_account_id $i babe '--scheme sr25519' true)\n"
	AUTHORITIES+="),\n"

  echo "$(get_json "aura" "$(generate_secret_seed $i babe '--scheme sr25519')" "$(generate_public_key $i babe '--scheme sr25519')")"
done

printf "$AUTHORITIES"

