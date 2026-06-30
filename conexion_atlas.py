from pymongo import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://dorj090613hmcmdra0_db_user:ecorutamc405@cluster0.dcoib4a.mongodb.net/?appName=Cluster0"

client = MongoClient(uri, server_api=ServerApi("1"))

try:
    client.admin.command("ping")
    print("Conexión exitosa a MongoDB Atlas")
except Exception as e:
    print("Error al conectar con MongoDB Atlas:")
    print(e)