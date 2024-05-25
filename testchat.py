import ast
import sys
import socket
import sqlite3
import datetime
import json
import time
from random import randint
import threading
import hashlib
import string
import random


class chatDB:
    """Database for chat

    Support multiple-thread accesses
    """

    def __init__(self, path, createNew=False):
        """Init chatdb
        Connect to database (at PATH) or create new one if CREATENEW = True
        """
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        if createNew:
            self.create_tables()
        self.cleanup_thread = None

    def create_tables(self):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS Users (
                                user TEXT PRIMARY KEY,
                                passwd TEXT,
                                status TEXT)''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS Msgs (
                                sender TEXT,
                                receiver TEXT,
                                timestamp TEXT,
                                read TEXT,
                                content TEXT,
                                PRIMARY KEY (sender, receiver, timestamp))''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS Cookies (
                                cookie TEXT PRIMARY KEY,
                                user TEXT,
                                last_acc TIMESTAMP)''')
            self.conn.commit()

    def start(self):
        """Start background tasks of chat db.

        Background tasks: cookie cleaner
        """
        self.cleanup_thread = threading.Thread(target=self.autoClear)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def stop(self):
        """Stop background tasks of chat db.

        Background tasks: cookie cleaner
        """
        if self.cleanup_thread:
            self.cleanup_thread.join()

    def autoClear(self):
        """
        Clear inactive cookie. Timeout = 600 seconds (10 minutes)
        Change status of online users into off
        Should be called in self.start
        """
        while True:
            time.sleep(600)
            with self.lock:
                cursor = self.conn.cursor()
                timeout_time = datetime.datetime.now() - datetime.timedelta(seconds=600)
                cursor.execute("DELETE FROM Cookies WHERE last_acc < ?", (timeout_time,))
                cursor.execute("UPDATE Users SET status = 'off' WHERE user NOT IN (SELECT user FROM Cookies)")
                self.conn.commit()

    def getOnlineUsers(self):
        """Get all online users

        Return: list of online users
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Users WHERE status = 'on'")
            users = [row[0] for row in cursor.fetchall()]
            return users

    def getAllUsers(self):
        """Get all online users

        Return: list of all users
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Users")
            users = [row[0] for row in cursor.fetchall()]
            return users

    def getAllMsgs(self, cookie, usr2):
        """Return all messages between owner of COOKIE and USR2.
        All new messages will be set to be already read.

        Return value:
            + 'invalid_usr': if usr is invalid
            + 'invalid_cook': if cookie is invalid
            + [[sender, receiver, content, time, status],...]
                example: [['manh', 'thanh', 'Hello', '2018-20-06 18:21:26', 'yet']]
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Cookies WHERE cookie = ?", (cookie,))
            user_row = cursor.fetchone()
            if not user_row:
                return "invalid_cook"

            user = user_row[0]
            cursor.execute("SELECT * FROM Users WHERE user = ?", (usr2,))
            if not cursor.fetchone():
                return "invalid_usr"

            cursor.execute("SELECT sender, receiver, content, timestamp, read FROM Msgs WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)",
                           (user, usr2, usr2, user))
            messages = cursor.fetchall()
            cursor.execute("UPDATE Msgs SET read = 'already' WHERE receiver = ? AND sender = ?", (user, usr2))
            self.conn.commit()
            return messages

    def getNewMsgs(self, cookie, frm):
        """Return all new messages from FRM sending to owner of COOKIE.
        All those new messages will be set to be already read.

        Return value:
            + 'invalid_usr': if usr is invalid
            + 'invalid_cook': if cookie is invalid
            + [[content, time],...]
                example: [['Hello', '2018-20-06 18:21:26']]
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Cookies WHERE cookie = ?", (cookie,))
            user_row = cursor.fetchone()
            if not user_row:
                return "invalid_cook"

            user = user_row[0]
            cursor.execute("SELECT * FROM Users WHERE user = ?", (frm,))
            if not cursor.fetchone():
                return "invalid_usr"

            cursor.execute("SELECT content, timestamp FROM Msgs WHERE receiver = ? AND sender = ? AND read = 'yet'",
                           (user, frm))
            messages = cursor.fetchall()
            cursor.execute("UPDATE Msgs SET read = 'already' WHERE receiver = ? AND sender = ?", (user, frm))
            self.conn.commit()
            return messages

    def sendMsg(self, cookie, to, content):
        """Send message with content CONTENT from owner of COOKIE to TO.

        The time will be set to the current time on server.

        Return value:
            + 'invalid_usr': if usr is invalid
            + 'invalid_cook': if cookie is invalid
            + 'success'
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Cookies WHERE cookie = ?", (cookie,))
            sender_row = cursor.fetchone()
            if not sender_row:
                return "invalid_cook"

            sender = sender_row[0]
            cursor.execute("SELECT user FROM Users WHERE user = ?", (to,))
            if not cursor.fetchone():
                return "invalid_usr"

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("INSERT INTO Msgs (sender, receiver, timestamp, read, content) VALUES (?, ?, ?, ?, ?)",
                           (sender, to, timestamp, 'yet', content))
            self.conn.commit()
            return "success"

    def register(self, usr, wd):
        """Register user USR with word WD

        USR must be a 3-10 byte string.
        Return:
            'success': register successfully
            'invalid_usr': failed. The user name is not valid.
            'invalid_': failed. The word is not valid.
        """
        if not (3 <= len(usr) <= 10) or not (3 <= len(wd) <= 10):
            return "invalid_usr" if not (3 <= len(usr) <= 10) else "invalid_"

        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("INSERT INTO Users (user, passwd, status) VALUES (?, ?, ?)",
                               (usr, hashlib.sha1(wd.encode()).hexdigest(), 'off'))
                self.conn.commit()
                return "success"
            except sqlite3.IntegrityError:
                return "invalid_usr"

    def login(self, usr, wd):
        """Set user USR as logged in.

        Return:
            ['success', cookie]: login successfully. Cookie is a string specify the session.
            'invalid_usr': login failed because of invalid user name.
            'invalid_wd': login failed because of wrong word.
        """
        hashed_passwd = hashlib.sha1(wd.encode()).hexdigest()

        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM Users WHERE user = ? AND passwd = ?", (usr, hashed_passwd))
            if cursor.fetchone():
                cookie = self.generate_cookie()
                cursor.execute("INSERT INTO Cookies (cookie, user, last_acc) VALUES (?, ?, ?)",
                               (cookie, usr, datetime.datetime.now()))
                cursor.execute("UPDATE Users SET status = 'on' WHERE user = ?", (usr,))
                self.conn.commit()
                return ["success", cookie]
            else:
                return "invalid_usr"

    def logout(self, cookie):
        """Set owner of cookie as logged out
        Remove cookie from database

        Return:
            'success': log-out successfully
            'invalid': log-out failed. The cookie does not exist.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT user FROM Cookies WHERE cookie = ?", (cookie,))
            user_row = cursor.fetchone()
            if user_row:
                user = user_row[0]
                cursor.execute("DELETE FROM Cookies WHERE cookie = ?", (cookie,))
                cursor.execute("UPDATE Users SET status = 'off' WHERE user = ?", (user,))
                self.conn.commit()
                return "success"
            else:
                return "invalid"

    def generate_cookie(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


class ThreadedServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self, maxClient):
        self.sock.listen(maxClient)
        while True:
            client, address = self.sock.accept()
            threading.Thread(target=self.listenToClient,
                             args=(client, address)).start()

    def listenToClient(self, client, address):
        recvBuf = b''
        while True:
            data = self.recvLine(client, recvBuf)
            data = data.decode("utf-8")
            print(data)
            try:
                request = json.loads(data)
                response = self.processRequest(request)
                response_json = json.dumps(response)  # Chuyển đổi response sang JSON
                client.send((response_json + '\n').encode('utf-8'))
            except Exception as e:
                print("Error:", e)
                client.close()
                return

    def recvLine(self, client, recvBuf):  # receive line from client
        while b'\n' not in recvBuf:
            try:
                data = client.recv(1024)
                if data:
                    recvBuf += data
            except:
                client.close()
                return [False, 'error']
        lineEnd = recvBuf.index(b'\n')
        data = recvBuf[:lineEnd]
        recvBuf = recvBuf[lineEnd+1:]
        return data

    def processRequest(self, request):
        global chatdb
        """Process a request of a client

        A request is in the form:
            ['ONLINE'] => getOnlineUsers
            ['ALL'] => getAllUsers
            ['GET', cookie, usr2] => getAllMsgs
            ['NEW', cookie, frm] => getNewMsgs
            ['SEND', cookie, to, content] => sendMsg
            ['REG', usr, wd] => register
            ['LOGIN', usr, wd] => login
            ['LOGOUT', cookie] => logout
        """
        action = request[0]

        if action == 'ONLINE':
            return chatdb.getOnlineUsers()
        elif action == 'ALL':
            return chatdb.getAllUsers()
        elif action == 'GET':
            _, cookie, usr2 = request
            return chatdb.getAllMsgs(cookie, usr2)
        elif action == 'NEW':
            _, cookie, frm = request
            return chatdb.getNewMsgs(cookie, frm)
        elif action == 'SEND':
            _, cookie, to, content = request
            return chatdb.sendMsg(cookie, to, content)
        elif action == 'REG':
            _, usr, wd = request
            return chatdb.register(usr, wd)
        elif action == 'LOGIN':
            _, usr, wd = request
            return chatdb.login(usr, wd)
        elif action == 'LOGOUT':
            _, cookie = request
            return chatdb.logout(cookie)
        else:
            return "invalid_request"


chatdb = None
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: %s <port> <dbFile> <createNew>" % sys.argv[0])
        print("Example: %s 8081 chat.sqlite new" % sys.argv[0])
        exit(1)
    port = int(sys.argv[1])
    dbFile = sys.argv[2]
    createNew = sys.argv[3]
    if createNew == 'new':
        createNew = True
    else:
        createNew = False
    chatdb = chatDB(dbFile, createNew)
    chatdb.start()
    ThreadedServer('', port).listen(50)
