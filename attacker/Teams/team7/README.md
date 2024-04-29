# Defender Challenge

Before you proceed, you must [install Docker Engine](https://docs.docker.com/engine/install/) for your operating system.

From the `defender` folder that contains the `Dockerfile`, build the solution:
```
docker build -t some_name .
```

Run the docker container:
```
docker run -itp 8080:8080 some_name
```
(The flag `-p 8080:8080` maps the container's port 8080 to the host's port 8080.)

Test the solution on malicious and benign samples of your choosing via opening up another cmd and typing below comment after replacing "somePEfile" with actual directory to a pe file without "".
```
curl -XPOST --data-binary @"somePEfile" http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
```