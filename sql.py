# Import the psycopg2 library to interact with PostgreSQL
import psycopg2
import os
import csv
import datetime
# Connect to the PostgreSQL database
conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
)
username = 'Arjun'
cps = 0
# Create a cursor object using the cursor() method
cursor = conn.cursor()
cursor.execute("""
SELECT * FROM users
""")
print(datetime.datetime.utcnow())
# Commit the changes to the database
conn.commit()

# Close the cursor and connection
cursor.close()
conn.close()
