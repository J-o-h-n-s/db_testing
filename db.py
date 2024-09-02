import mysql.connector
from mysql.connector import Error
import bcrypt
import getpass
import os
from dotenv import load_dotenv


def get_env():
    load_dotenv()
    ip = os.environ.get("MYSQL_IP")
    username_db = os.environ.get("MYSQL_USER")
    password_db = os.environ.get("MYSQL_PASSWORD")
    db_name = os.environ.get("MYSQL_DB")
    return ip, username_db, password_db, db_name


def create_connection(host_name, user_name, user_password, db_name):
    try:
        connection = mysql.connector.connect(
            host=host_name, user=user_name, passwd=user_password, database=db_name
        )
        print("Connection to MySQL DB successful")
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        return None


def execute_query(connection, query, fetch=False):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        if fetch:
            result = cursor.fetchall()
            return result
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")
    finally:
        cursor.close()


def create_users_table(connection):
    create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT,
            name VARCHAR(255) NOT NULL,
            user_name VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            PRIMARY KEY (id)
        ) ENGINE = InnoDB;
    """
    execute_query(connection, create_table_query)


def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(
        provided_password.encode("utf-8"), stored_password.encode("utf-8")
    )


def register_user(connection, user_name):
    name_inp = input("Enter your name: ")
    email_inp = input("Enter your email: ")
    password_inp = getpass.getpass("Enter your password: ")
    hashed_password = bcrypt.hashpw(password_inp.encode("utf-8"), bcrypt.gensalt())

    get_email_query = f"SELECT email FROM users WHERE email = '{email_inp}';"
    email_exists = execute_query(connection, get_email_query, fetch=True)
    if email_exists:
        print("Email already exists.")
        email_inp = input("Enter your email: ")
        pass
    insert_user_query = f"""
        INSERT INTO users (name, user_name, email, password)
        VALUES ('{name_inp}', '{user_name}', '{email_inp}', '{hashed_password.decode("utf-8")}')
    """
    execute_query(connection, insert_user_query)
    print("User registered successfully. Please log in.")
    do_login(connection, user_name)


def user_exists(connection, user_name):
    find_user_query = f"SELECT * FROM users WHERE user_name = '{user_name}';"
    result = execute_query(connection, find_user_query, fetch=True)
    return len(result) > 0


def do_login(connection, user_name=None):
    if not user_name:
        user_name = input("Enter your username: ")

    if not user_exists(connection, user_name):
        print("User does not exist.")
        register_y_n = input("Register?: (Y/n)")
        if register_y_n.lower() == "n":
            exit()
        else:
            register_user(connection, user_name)
            return

    login_password = getpass.getpass("Enter your password: ")
    select_password_query = (
        f"SELECT password FROM users WHERE user_name = '{user_name}';"
    )
    stored_password = execute_query(connection, select_password_query, fetch=True)[0][0]

    if verify_password(stored_password, login_password):
        print("Login successful!")
    else:
        print("Invalid username or password.")
        do_login(connection)


def main():
    connection = create_connection(*get_env())
    if connection:
        create_users_table(connection)
        do_login(connection)
        connection.close()
        print("MySQL connection is closed")


if __name__ == "__main__":
    main()
