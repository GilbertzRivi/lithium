currently in development

to start the API, run ``docker compose up`` in the main directory, then run
```
docker exec -it <container-name> /bin/sh
cd app && python3 -m database.rebuild
````
