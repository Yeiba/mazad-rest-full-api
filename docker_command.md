 docker build -t {image_name} .
 docker build -t {image_name}:{tag_version} .

  docker run --name myapp2_c myapp
  docker run --name {container_name} -p 8000:8000 -d {image_name}:{tag_version}
#   nodemon run container
  docker run --name {container_name} -p 8000:8000 --rm {image_name}:{tag_version}
#   add valuem flag
  docker run --name {container_name} -p 8000:8000 --rm -v {project_path}:/{WORKDIR_path} {image_name}:{tag_version}
#   add valuem flag
  docker run --name {container_name} -p 8000:8000 --rm -v {project_path}:/{WORKDIR_path} -v {WORKDIR_path/node_modules} {image_name}:{tag_version}

#   to see all images
  docker images
#   to see the container in progress
  docker ps 
#   to see all container
  docker ps -a

# stop the container
  docker stop {container_name}
# start the container
  docker start {container_name}
# remove the container
  docker container rm {container_name}

#   to remove image
  docker image rm {image_name} 
#   to remove image forced
  docker image rm {image_name} -f

# remove all containers and images
  docker system prune -a
# run docker composer detach mode
docker-compose up -d --build
# stop docker composer and delete all volumes
docker-compose down -v 

# run docker dev env composer file
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down -v 
<!-- to not remove mongo-db volume -->
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build -v
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down 
<!-- start just specific service without depen-on -->
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --no-deps {serviceName}

# run docker prod env composer file
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale {image name}=2
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down -v 
<!-- to not remove mongo-db volume -->
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down 

# to delete unused volumes 
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker volume prune
docker system prune

# enter docker container
docker exec -it {container_name} bash
exit
# enter mongo db in docker container
<!-- to enter mongo db -->
docker exec -it {container_name} mongo -u "username" -p "password"
db 
<!-- to create db  -->
use mydb
show dbs 
db.books.insert({"name": "jacob", })
db.books.find()
exit

docker inspect {container_name}
# to see logs in detach mode
docker logs {container_name} -f
<!-- backend-node-app-1 -->

docker exec -it mongo1 mongosh

config = {
    _id: "my-mongo-set",
    members: [
        { _id: 0, host: "mongo1:27017" },
        { _id: 1, host: "mongo2:27017" },
        { _id: 2, host: "mongo3:27017" }
    ]
}

rs.initiate(config);

rs.conf()

docker exec replset-mongo_rs0_1-1 bash -c 'mongosh --eval "rs.status();"'