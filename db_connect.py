import psycopg2  
# The psycopg2 module is PostgreSQL database adaptor.

def connection_db():  # Defining a connection_db function to connect to the PostgreSQL database
     
    connection = psycopg2.connect("dbname=postgres user=postgres password=docker") 
    # Psycopg2.connect() function establishes a connection to a PostgreSQL database. 
    # The connection string includes the database name, the username, and the password.    

    return connection