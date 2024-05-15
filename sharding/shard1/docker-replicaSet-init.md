docker exec -it shard1svr1 mongosh

rs.initiate({
    _id: "shard1rs",
    members: [
        { _id: 0, host: "shard1svr1:50001" },
        { _id: 1, host: "shard1svr2:50002" },
        { _id: 2, host: "shard1svr3:50003" }
    ]
})

rs.status()