

def insert_db_row():
# Defining a function insert_db_row() that returns an SQL query string for inserting a new row.

    insert_query = """INSERT INTO Vault (URL, USRNAME, PASSWD) VALUES (%s, %s,%s)"""
    return insert_query 
    
    # The %s acts as a placeholder for values that will be substituted later later. 
    # This prevents SQL injection attacks which is a common vulnerability when dealing with databases.

def delete_db_row(): 
    sql_delete_query = """Delete from Vault where URL = %s"""
    return sql_delete_query

def update_db_url():
    update_query_url = """UPDATE Vault SET url = %s WHERE url = %s"""
    return update_query_url

def update_db_usrname():
    update_query_usrname = """UPDATE Vault SET usrname = %s WHERE url = %s"""
    return update_query_usrname 

def update_db_passwd():
    update_query_passwd = """UPDATE Vault SET passwd = %s WHERE url = %s"""
    return update_query_passwd

def select_db_entry():
    select_query = """SELECT * from vault where url = %s"""
    return select_query

def update_db():
    update_db = """UPDATE Vault SET passwd = %s"""
    return update_db

