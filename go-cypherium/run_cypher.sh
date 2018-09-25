#!/usr/bin/env bash
set -e

# Find out which package this copy of run_cypher.sh is checked into.
dir=$(dirname $(realpath $0))
pkg=`cd $dir`
all_args="$*"

echo $dir
echo $pkg
# increment version in onet if there's something that changes that needs
# migration.
CYPHER_PATH="$(go env GOPATH)/src/github.com/cyphertestnet/go-cypherium/build/bin"

main(){
	if [ ! "$1" ]; then
		showHelp
		exit 1
	fi

	if ! go env GOPATH > /dev/null; then
		echo "Could not find GOPATH."
		echo "Please install go: https://golang.org/doc/install"
		exit 1
	fi
	gopath="$(go env GOPATH)"

	if ! echo $PATH | grep -q $gopath/bin; then
		echo "Please add '$gopath/bin' to your '$PATH'"
		PATH=$PATH:$gopath/bin
		export PATH
	fi
	case $( uname ) in
	Darwin)
		PATH_CO=~/Library
		;;
	*)
		PATH_CO=~/.config
		;;
	esac

	ACTION=$1
	shift
	case $ACTION in
	local)
		runLocal $@
		;;
	*)
		showHelp
		;;
	esac
}

showHelp(){
		cat - <<EOF
Syntax is $0: (public|local)

public				# runs a public cypher - supposes it's already configured
	-debug 3		# Set the debug-level for the conode-run
	-memory 500		# Restarts the process if it exceeds 500MBytes

local nbr [dbg_lvl]	# runs nbr local cyphers - you can give a debug-level as second
					# argument: 1-sparse..5-flood.
EOF
}

runLocal(){
	if [ ! "$1" ]; then
		echo "Please give the number of nodes to start"
		exit 1
	fi
	NBR=$1
	shift
	WAIT=""
	DEBUG=1
	GEN=$dir
	while [ "$1" ]; do
		case $1 in
		--onetdebug)
			DEBUG=$2
			shift
			;;
		-wait_for_apocalypse|-wait)
			WAIT=true
			;;
		*)
			DEBUG=$1
			;;
		esac
		shift
	done

	killall -9 cypher || true
    # make clean
    make cypher
	# rm ./cypher

	rm -f public.toml
	for n in $( seq $NBR ); do
		co=co$n
		if [ -f $co/public.toml ]; then
			if ! grep -q Description $co/public.toml; then
				echo "Detected old files - deleting"
				rm -rf $co
			fi
			if grep 'Public =' $co/public.toml|grep -q =\"; then
				echo "Detected base64 public key for $co: converting"
				mv $co/public.toml $co/public.toml.bak
				$CYPHER_PATH/cypher convert64 < $co/public.toml.bak > $co/public.toml
			fi
		fi

		if [ ! -d $co ]; then
			echo -e "localhost:$((7000 + 2 * $n))\nConode_$n\n$co" | $CYPHER_PATH/cypher setup
		fi
        rm -rf $co/cypher
        $CYPHER_PATH/cypher --datadir $co init $GEN/genesis.json
		cat $co/public.toml >> public.toml
		chmod -R 777 $co
	done

	for n in $( seq $NBR ); do
		co=co$n
		$CYPHER_PATH/cypher --onetdebug $DEBUG --onetdir $co/private.toml --publickeydir public.toml --datadir $co --networkid 123666 --port $((5000 + 2 * $n)) --rpcport $((8000 + 2 * $n)) --verbosity 4 --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi eth,web3,personal --nodiscover 2>$co/output.log &
	done

	sleep 1

	cat - <<EOF

*********

Now you can use public.toml as the group-toml file to interact with your
local cothority.
EOF

	if [ "$WAIT" ]; then
		echo -e "\nWaiting for <ctrl-c>"
		while sleep 3600; do
			date
		done
	fi
}

main $@
