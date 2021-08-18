import os
try:
    from decouple import RepositoryEnv
    file_path = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
    for k,v in RepositoryEnv("{}/.env".format(file_path)).data.items():
        os.environ[k] = v
        #print(k,v)
except Exception as e:
    pass

