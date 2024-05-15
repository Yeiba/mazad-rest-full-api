docker exec -it shard1svr1 mongosh

rs.initiate({
    _id: "shard2rs",
    members: [
        { _id: 0, host: "shard2svr1:50004" },
        { _id: 1, host: "shard2svr2:50005" },
        { _id: 2, host: "shard2svr3:50006" }
    ]
})

rs.status()