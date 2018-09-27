cd /home/ubuntu
./cypher --onetdebug 1 --onetdir ./ipaddr/private.toml --publickeydir group.toml --datadir cypher_db --networkid 123666 --port 7000 --rpcport 8000 --verbosity 4 --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal > /dev/null 2>&1 &
