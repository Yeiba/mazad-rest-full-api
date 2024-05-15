docker exec -it mongos mongosh

sh.addShard("shard1rs/shard1svr1:50001,shard1svr2:50002,shard1svr3:50003")
sh.addShard("shard2rs/shard2svr1:50004,shard2svr2:50005,shard2svr3:50006")
sh.status()


