from helper.querybilder import QueryBuilder, DataBase
import bcrypt

qb = QueryBuilder(DataBase(), 'database.db')


class DB:
    def __init__(self):
        self.add_tables()

    def add_tables(self):
        # create table users
        qb.reset()  # reset query builder
        qb.query(
            """CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)"""
        )

    def check_username_exist(self, username: str):
        # Check username from db
        result = qb.select('users').where([['username', '=', username]]).one()
        return result is not None

    def add_user(self, username, password):
        # hash password
        hash_pwd = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt())

        return qb.insert('groups', {'users': username, 'password': hash_pwd}).go()

    def get_user(self, username):
        return qb.select('users').where([['username', '=', username]]).one()
