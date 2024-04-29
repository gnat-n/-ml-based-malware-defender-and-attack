## How to Query the Model

---
### Clone the repository
```
git clone "HTTPS URL"
```

### Navigate to the 'defense' directory
```
cd defense
```

### Build the image:
```
docker build -t defender .
```

### Run the container:
```
docker run -it -p 8080:8080 defender
```

### Query the running application:
```
curl -XPOST --data-binary @"path_to_your_pe_file" http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
```
