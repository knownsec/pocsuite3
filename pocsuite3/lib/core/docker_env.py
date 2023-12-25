from io import BytesIO
from docker import client
from docker import errors


from pocsuite3.lib.core.data import logger


class DockerEnv:

    def __init__(self):
        self.client = client.from_env()

    def build(self, name, docker_file):
        file_obj = BytesIO(docker_file.encode())
        try:
            logger.info("Building image...")
            build_info = self.client.images.build(fileobj=file_obj, tag=name)
            return build_info
        except errors.BuildError as e:
            logger.error(e)

    def run(self, tag_name, docker_file, ports, envs, volumes):
        try:
            # if image exists run
            self.client.images.get(tag_name)
            logger.info("Image {} exists".format(tag_name))
            run_info = self.client.containers.run(
                tag_name,
                detach=True,
                ports=ports,
                environment=envs,
                volumes=volumes
            )
            return run_info
        except errors.ImageNotFound:
            # if image not exists, build image first
            logger.info("Image {} does not exist".format(tag_name))
            build_info = self.build(tag_name, docker_file)
            if build_info[0].tags:
                run_info = self.client.containers.run(
                    tag_name,
                    detach=True,
                    ports=ports,
                    environment=envs,
                    volumes=volumes
                )
                return run_info


if __name__ == "__main__":
    docker_env = DockerEnv()
    ports = {"8080/tcp": '8899', '8090/tcp': ("127.0.0.1", 8890)}
    env = ["PORT=8899", "PORT=8890"]
    volumes = ["/tmp:/home"]
    dockerfile = "FROM ubuntu:latest"
    image_tag = "ubuntu:pocsuite"
    docker_env.run(
        image_tag,
        docker_file=dockerfile,
        ports=ports,
        envs=env,
        volumes=volumes
    )
