## What is run_cypher.sh

run_cypher.sh is used for runs n local cypher quickly.

## Which version of the source code is available

```
$ git clone https://github.com/cypherium/cypherium_private.git -b committee
$ git checkout 5fa8b9b474c17903b2121c74b58c58c3fde8b759
```

## Running cypher locally
```
$ cd go-cypherium
$ ./run_cypher.sh local n
```
run_cypher.sh do the following things:
1.Kill all cypher processes if they exist in the background.
2.Build cypher, the executable file will store in ./build/bin
3.Created n folders to save the data for each cypher,include blockchain db, output log info, private key,public key etc..
4.Bootstrap and initialize a new genesis txblock for each cypher.
5.Generate public.toml which include all cypher's public key and IP address.
6.Runs n local cypher background.

## How to attach cypher
Open another console,enter the following command to attach one process,it will enter co1 javaScript interactive console. 

```
$ ./build/bin/cypher attach ./co1/cypher.ipc
```
Now you can first use personal.newAccount('password') to create an account for recive rewards,then use bftcosi.start() which will run PBFT-COSI protocol as leader,while other processes as follower, all processes work together to generate txblock,finally, you can use bftcosi.stop() to terminated.

All processes log info saved in ./cox/output.log.

For more details,check out our YouTube channel:
https://www.youtube.com/watch?v=U11XDl3QjAc&t=71s

## What is the purpose of public.toml
Currently,the cyphers communicate with each other directly through IP addresses to run PBFT-COSI protocol. When We setup a cypher,we input public.toml which include all cyphers' IP addresses and public key,to let any cypher know each other.

