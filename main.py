from gevent import monkey
monkey.patch_all()
import uuid
from gevent.pywsgi import WSGIServer
from flask_compress import Compress
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
import flask_socketio
from flask_mail import Mail, Message
from flask_sslify import SSLify
import flask
import random
import time
import math
import csv
import os
import bcrypt
import datetime
import psycopg2
conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
)
conn.close()
app = Flask(__name__)
key = str(random.randrange(16**32))
app.secret_key = key
socketio = SocketIO(app)
sslify = SSLify(app)
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=360)
CONFIG_FILE = 'config.ini'
message_history = []
leaderboard = []
def get_admin_only_mode():
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT feature FROM flags WHERE feature = 'Admin_only_mode'")
  admin_only_mode = cur.fetchone()[0] == 'True'  # Convert to boolean
  return admin_only_mode
ADMIN_ONLY_MODE = get_admin_only_mode()  # Fetch initial value from database
app.config['MAIL_SERVER'] = 'smtppro.zoho.eu'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'verification@arjun.bond'  
app.config['MAIL_DEFAULT_SENDER'] = 'verification@arjun.bond'
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']

mail = Mail(app)

questions = [
  {
    'question': 'What is the atomic number of hydrogen?',
    'options': ['1', '2', '3', '4'],
    'answer': '1'
  },
  {
    'question': 'Who won the FIFA World Cup in 2018?',
    'options': ['France', 'Brazil', 'Germany', 'Argentina'],
    'answer': 'France'
  },
  {
    'question': 'What is the chemical symbol for gold?',
    'options': ['Au', 'Ag', 'G', 'Go'],
    'answer': 'Au'
  },
  {
    'question':
    'Who is the all-time leading goal scorer in the history of FIFA World Cup?',
    'options': ['Miroslav Klose', 'Ronaldo', 'Pelé', 'Diego Maradona'],
    'answer': 'Miroslav Klose'
  },
  {
    'question': 'What is the pH value of a neutral solution?',
    'options': ['7', '10', '5', '0'],
    'answer': '7'
  },
  {
    'question': 'Which country has won the most UEFA Champions League titles?',
    'options': ['Real Madrid', 'Barcelona', 'Bayern Munich', 'Liverpool'],
    'answer': 'Real Madrid'
  },
  {
    'question': 'What is the chemical formula for water?',
    'options': ['H2O', 'CO2', 'NaCl', 'O2'],
    'answer': 'H2O'
  },
  {
    'question':
    'Who is the all-time leading scorer for the Brazilian national football team?',
    'options': ['Pelé', 'Neymar', 'Ronaldo', 'Zico'],
    'answer': 'Pelé'
  },
  {
    'question': 'Which gas makes up the majority of Earth\'s atmosphere?',
    'options': ['Nitrogen', 'Oxygen', 'Carbon dioxide', 'Helium'],
    'answer': 'Nitrogen'
  },
  {
    'question': 'Which country has won the most FIFA World Cup titles?',
    'options': ['Brazil', 'Germany', 'Italy', 'Argentina'],
    'answer': 'Brazil'
  },
  {
    'question': 'What is the SI unit of electric current?',
    'options': ['Ampere', 'Volt', 'Ohm', 'Watt'],
    'answer': 'Ampere'
  },
  {
    'question':
    'Who holds the record for the highest individual score in Test cricket?',
    'options':
    ['Brian Lara', 'Sachin Tendulkar', 'Virender Sehwag', 'Don Bradman'],
    'answer':
    'Brian Lara'
  },
  {
    'question':
    'Which programming language is known as the "mother of all languages"?',
    'options': ['C', 'Java', 'Python', 'Assembly'],
    'answer': 'C'
  },
  {
    'question':
    'What is the unit of information in computing and telecommunications?',
    'options': ['Bit', 'Byte', 'Megabyte', 'Gigabyte'],
    'answer': 'Bit'
  },
  {
    'question': 'Which country has won the most ICC Cricket World Cup titles?',
    'options': ['Australia', 'India', 'West Indies', 'England'],
    'answer': 'Australia'
  },
  {
    'question':
    'Which algorithm is used to sort a list of elements in ascending or descending order?',
    'options': ['Bubble Sort', 'Binary Search', 'Quick Sort', 'Merge Sort'],
    'answer': 'Merge Sort'
  },
  {
    'question': 'What is the distance covered by light in one year called?',
    'options': ['Light-year', 'Parsec', 'Astronomical Unit', 'Nautical Mile'],
    'answer': 'Light-year'
  },
  {
    'question':
    'Who holds the record for the fastest century in One Day International (ODI) cricket?',
    'options':
    ['AB de Villiers', 'Chris Gayle', 'Shahid Afridi', 'Corey Anderson'],
    'answer':
    'AB de Villiers'
  },
  {
    'question': 'Which programming language was created by Guido van Rossum?',
    'options': ['Python', 'Ruby', 'C++', 'JavaScript'],
    'answer': 'Python'
  },
  {
    'question':
    'What is the diameter of a cricket ball?',
    'options': [
      'between 22.4 and 22.9 centimeters', 'between 21.0 and 21.7 centimeters',
      'between 23.5 and 24.1 centimeters', 'between 20.0 and 20.7 centimeters'
    ],
    'answer':
    'between 22.4 and 22.9 centimeters'
  },
]
@socketio.on('verify')
def handle_verification(username):
    emit('verified', room=username)


@app.route('/change-email-form', methods=["GET"])
def change_email():
  if 'username' not in session:
    return redirect('/')
  conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
    )
  cur = conn.cursor()
  cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
  id = cur.fetchone()[0]
  username = session['username']
  return render_template('change_email.html', username = username, user_id = id)
  
@app.route('/change-email/<int:id>/<username>', methods=["POST"])
def change_email_route(id, username):
  cusername = session.get('username')
  email = request.form['email']
  if cusername == None:
    return redirect('/')
  if cusername != username:
    return redirect('/')
  
  conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
    )
  cur = conn.cursor()

  cur.execute("SELECT id FROM users WHERE username = %s", (username,))
  cid = cur.fetchone()[0]
  if cid != id:
    flash('An error occurred',"error")
    return redirect('/')
  verification_token = str(uuid.uuid4().hex)
  cur.execute("UPDATE users SET verified = %s, verification_token = %s, email = %s WHERE username = %s", (False, verification_token, email, username,))

  conn.commit()
  msg = Message('Verify Your Account', recipients=[email])
  msg.html = render_template('verification_email.html', user_id=id, token=verification_token)
  mail.send(msg)
  return redirect('/verify')

@app.route('/verify/<int:user_id>/<token>')
def verify(user_id, token):
    conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    print(user_id)
    cur.execute("SELECT verification_token FROM users WHERE id = %s", (user_id,))
    expected_token = cur.fetchone()[0]
    print('token',expected_token)
    if token == expected_token:
        # Mark user as verified
        cur.execute("UPDATE users SET verified = True WHERE id = %s", (user_id,))
        conn.commit()
        cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        username = cur.fetchone()[0]
        socketio.emit('verified',room=username)
        session["username"] = username
        return render_template("verification_success.html")
    else:
        return render_template('verification_failed.html')
    
def check_admin_status(username):
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password= os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    cur.execute("SELECT admin_status FROM users WHERE username = %s", (username,))
    result = cur.fetchone()

    if result is not None:
      return result[0]
      print(result[0])# Assuming is_admin is a boolean or integer field in the database
    else:
      return False


def delete_account(username):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("DELETE FROM users WHERE username = %s", (username,))
  cur.execute("DELETE FROM logs WHERE username = %s", (username,))
  cur.execute("DELETE FROM messages WHERE sender = %s",(username,))
  cur.execute("DELETE FROM messages WHERE recipient = %s",(username,))
  
  conn.commit()
  log_activity(username,"Deleted Account")

@app.route('/delete-account', methods=['POST'])
def delete_account_for_user():
  if session['frozen'] == True:
    return redirect('/check-banned')
    
    username = session['username']
    conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    # Remove the user's data from the database
    cur.execute("DELETE FROM users WHERE username = %s", (username,))
    cur.execute("DELETE FROM logs WHERE username = %s", (username,))
    cur.execute("DELETE FROM messages WHERE sender = %s",(username,))
    cur.execute("DELETE FROM messages WHERE receiver = %s",(username,))
    # Commit the changes to the databases
    conn.commit()
    return redirect('/')

# @app.route('/purchase')
def purchase():
  return render_template('purchase.html')


def get_group_members(group_name):
  try:
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password=os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()

    # Fetch group members based on the group name
    cur.execute("""
        SELECT username
        FROM group_members
        WHERE group_id = (
            SELECT group_id
            FROM groups
            WHERE group_name = %s
        )
    """, (group_name,))
    group_members = [row[0] for row in cur.fetchall()]

  except Exception as e:
    # Handle the exception (print, log, etc.)
    print(f"Error getting group members: {e}")
    group_members = []

  finally:
    if cur:
        cur.close()
    if conn:
        conn.close()

  return group_members

@app.route('/get_group_members', methods=['GET'])
def get_group_members_route():
    group_name = request.args.get('group_name')
    group_members = get_group_members(group_name)

    return jsonify(group_members)

@app.route('/get_group_messages', methods=['GET'])
def get_group_messages():
    group_name = request.args.get('group_name')
    # Assuming you have a function to fetch group messages from the database
    group_messages = load_group_messages(group_name)

    # Convert messages to a list of dictionaries (replace with your actual message structure)
    group_messages_list = [{'sender': msg['sender'], 'message': msg['message']} for msg in group_messages]

    return jsonify(group_messages_list)
  
@socketio.on('send_message')
def handle_message(data):
    recipient = data['recipient']
    message = data['message']

    if recipient.startswith('_'):  # Check if it's a group message
        group_name = recipient[1:]
        sender = session['username']
        save_group_message(sender, group_name, message)

        # Fetch group members
        group_members = get_group_members(group_name)

        # Emit the message to each group member's room
        for member in group_members:
            emit('new_message', {'sender': sender, 'message': message, 'recipient': recipient}, room=member)
    else:
        # Handle private messages as before
        sender = session['username']
        save_message(sender, recipient, message)
        emit('new_message', {'sender': sender, 'message': message, 'recipient': recipient}, room=recipient)

@app.route('/leave_group/<group_name>', methods=['GET', 'POST'])
def leave_group(group_name):
    if 'username' not in session:
        return redirect('/')

    current_user = session['username']

    try:
        conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password=os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
        )
        cur = conn.cursor()

        # Fetch the group ID for the given group name
        cur.execute("SELECT group_id FROM groups WHERE group_name = %s", (group_name,))
        group_id = cur.fetchone()

        if group_id:
            # Remove the user from the group_members table
            cur.execute("DELETE FROM group_members WHERE group_id = %s AND username = %s", (group_id, current_user))
            conn.commit()

            # Redirect to the dashboard or another appropriate page after leaving the group
            return redirect('/message')
        else:
           flash('Group does not exist.', 'error')
           return redirect('/dashboard')

    except Exception as e:
        # Handle the exception (print, log, etc.)
        flash('An error occurred while leaving the group.', 'error')
        return redirect('/dashboard')

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
          
@socketio.on('create_group')
def handle_create_group(data):
    group_name = data['group_name']
    group_members = data['members']

    try:
        conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password=os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
        )

        cur = conn.cursor()

        # Check if the group already exists in the 'groups' table
        cur.execute("SELECT group_id FROM groups WHERE group_name = %s", (group_name,))
        existing_group_id = cur.fetchone()

        if existing_group_id:
            # If the group already exists, emit an error message or handle it as needed
            print(f"Group '{group_name}' already exists.")
            emit('group_creation_error', {'error_message': f"Group '{group_name}' already exists."})
        else:
            # Insert the group into the 'groups' table
            cur.execute("INSERT INTO groups (group_name) VALUES (%s) RETURNING group_id", (group_name,))
            group_id = cur.fetchone()[0]

            # Insert group members into the 'group_members' table
            for member in group_members:
                cur.execute("INSERT INTO group_members (group_id, username) VALUES (%s, %s)", (group_id, member))

            conn.commit()

            # Broadcast a message to all members of the group
            for member in group_members:
                room = f"{member}"
                emit('new_group', {'group_name': group_name}, room=room)

    except Exception as e:
        # Handle the exception (print, log, etc.)
        print(f"Error creating group: {e}")
        emit('group_creation_error', {'error_message': 'An error occurred while creating the group.'})

    finally:
        cur.close()
        conn.close()



@app.route('/get_messages', methods=['GET'])
def get_messages():
    recipient = request.args.get('username')  # Assuming the username is passed as a query parameter
    username = session.get('username')
    # Fetch messages from your database based on the provided username
    messages = load_past_messages(username, recipient)

    # Convert messages to a list of dictionaries (replace with your actual message structure)
    messages_list = [{'sender': msg['sender'], 'message': msg['message']} for msg in messages]

    return jsonify(messages_list)
#Save sent message
@app.route('/verify')
def wait_verify():
  username = session.get('username')
  if username == None:
    return redirect('/')
  return render_template('verification_wait.html')
# Broadcast the message to all connected clients
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        join_room(username)
        print(f"User {username} joined room {username}")

def get_active_chats(user):
  try:
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password=os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()

    # Fetch users with whom the current user has had conversations (either as sender or recipient)
    cur.execute("""
        SELECT DISTINCT sender AS username
        FROM messages
        WHERE recipient = %s
        UNION
        SELECT DISTINCT recipient AS username
        FROM messages
        WHERE sender = %s
    """, (user, user))

    active_chats = [row[0] for row in cur.fetchall()]

    # Filter out usernames with a leading underscore
    active_chats = [chat for chat in active_chats if not chat.startswith('_')]
    print(active_chats)
  except Exception as e:
    # Handle the exception (print, log, etc.)
    print(f"Error getting active chats: {e}")
    active_chats = []

  return active_chats


  
def load_past_messages(user, recipient):
  # Load past messages relevant to the user from the database
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password=os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()

  # Load messages where the user is either the sender or recipient
  cur.execute("""
      SELECT sender, recipient, message, date
      FROM messages
      WHERE (sender = %s AND recipient = %s) OR (sender = %s AND recipient = %s)
      ORDER BY date DESC LIMIT 10
  """, (user, recipient, recipient, user))

  past_messages = [{'sender': sender, 'recipient': recipient, 'message': message, 'timestamp': date.strftime("%Y-%m-%d %H:%M:%S")}
     for sender, recipient, message, date in cur.fetchall()]

  cur.close()
  conn.close()

  return past_messages


def save_message(sender, recipient, message):
  try:
      conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password=os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
      )
      cur = conn.cursor()

      # Use the sql module to safely format the SQL query
      timestamp = datetime.datetime.utcnow()
      cur.execute("""
      INSERT INTO messages (sender, recipient, message, date)
          VALUES (%s, %s, %s, %s)
      """, (sender, recipient, message, timestamp))
      cur.execute("""
      INSERT INTO message_log (sender_username, receiver_username, message_text, sent_timestamp) VALUES (%s, %s, %s, %s)""",(sender,recipient,message,timestamp))

      conn.commit()

  except Exception as e:
      # Print or log the exception for debugging
      print(f"Error saving message: {e}")

  finally:
      cur.close()
      conn.close()



#Get usernames from database
def get_usernames():
  users = get_user_accounts()
  usernames = [user['username'] for user in users]
  return usernames


#Get messages from database


def get_messages():
  messages = []
  with open('database.txt', 'r') as file:
    for line in file:
      message = line.strip()
      messages.append(message)
  return messages


#User Search (for admins)


def get_user_accounts():
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status FROM users")
  rows = cur.fetchall()

  users = []
  for row in rows:
    user = {
    'username': row[0],
    'password': row[1],  # Note: This is the hashed password, not the plaintext password
    'is_admin': row[2],
    'balance': row[3],
    'banned': row[4]
    }
    users.append(user)

  return users


#Checks account admin status



def admin_only_mode():
  global ADMIN_ONLY_MODE
  ADMIN_ONLY_MODE = not ADMIN_ONLY_MODE
  return redirect('/admin-control')


#Get user by username (checks which user to associate)


def get_user_by_username(username):
  users = get_user_accounts()
  for user in users:
    if user['username'] == username:
      return user
  return None


#Promotes User to Admin status


def promote_user(username):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("UPDATE users SET admin_status = True WHERE username = %s", (username,))
  conn.commit()
#Gets User Balance


def get_balance(username):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT balance FROM users WHERE username = %s", (username,))
  result = cur.fetchone()
  cur.close()

  if result is None:
    return 0  # or whatever default balance you want to return if the user does not exist

  return result[0]


#Updates User balance


def update_balance(username, balance):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("UPDATE users SET balance = %s WHERE username = %s", (balance, username))
  conn.commit()

#demotes user from Admin status


def demote_user(username):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("UPDATE users SET admin_status = False WHERE username = %s", (username,))
  conn.commit()


#Reads Message database and separates information


def load_message_history():
  with open('database.txt', 'r') as file:
    lines = file.readlines()
    for line in lines:
      parts = line.strip().split(' - ')
      if len(parts) == 4:
        message_history.append({
          'sender': parts[0],
          'recipient': parts[1],
          'message': parts[2],
          'timestamp': parts[3]
        })


#Get accounts for leaderboard and sort them based on balance


def get_leaderboard():
  users = get_user_accounts()
  users = sorted(users, key=lambda user: user['balance'], reverse=True)
  formatted_balance = "{:,}".format(user.balance)
  return render_template('leaderboard.html', users=users)


#Set Admin only mode (Cannot be disabled from web portal for some reason)


def set_admin_only_mode(admin_only_mode):
  global ADMIN_ONLY_MODE  # Declare intention to modify global variable
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()

  try:
      cur.execute("UPDATE flags SET feature = 'admin_only_mode', value = %s WHERE feature = 'Admin_only_mode'", (admin_only_mode,))
      conn.commit()
      ADMIN_ONLY_MODE = admin_only_mode  # Update global variable
      return True  # Indicate successful update
  except psycopg2.Error as e:
      conn.rollback()
      return False  # Indicate update failure
  finally:
      cur.close()



#Checks if Admin only mode is enabled




#Random choice Function


def choice():
  lst = ['higher', 'lower']
  chosen = random.choice(lst)
  return chosen


#Checks User credential with salt


def check_credentials(username, password):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT * FROM users WHERE username = %s", (username,))
  user_data = cur.fetchone()
  if user_data:
      hashed_password, salt, is_admin = user_data[1], user_data[2], user_data[3]
      try:
          if bcrypt.checkpw(password.encode('utf-8'), salt + hashed_password.encode('utf-8')):
              session['username'] = username
              session['is_admin'] = is_admin
              return True
      except ValueError as e:
          # Handle the ValueError (Invalid salt) gracefully
          print(f"Error: {e}")
          flash("An error occurred during login.")
          return False
  flash("Username or password incorrect")
  return False


def log_activity(username,action):
  conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("INSERT INTO logs (username, activity, time) VALUES (%s, %s, %s);", (username, action, datetime.datetime.utcnow()))
  conn.commit()

#Update Clicks per second leaderboard
def fetch_user_logs(username):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password=os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT time, activity FROM logs WHERE username = %s ORDER BY time DESC;", (username,))
  logs = cur.fetchall()
  formatted_logs = [(log[0].strftime('%Y-%m-%d %H:%M:%S'), log[1]) for log in logs]
  return formatted_logs

@app.route('/admin-control/view-logs/<username>')
def view_user_logs(username):
    if not check_admin_status(session['username']):
      flash('Access denied. You must be an admin to access this page.', 'error')
      return redirect('/dashboard')

    logs = fetch_user_logs(username)
    return render_template('admin_view_logs.html', logs=logs, username=username)
  
@app.route('/logs')
def user_logs():
    if 'username' not in session:
        flash('You must be logged in to view logs', 'error')
        return redirect('/')

    username = session['username']
    logs = fetch_user_logs(username)
    print(logs)
    return render_template('logs.html', logs=logs)


def update_leaderboard(data):
  leaderboard = read_from_csv()
  banned_users = ['shack', 'Zayd']  #Banned
  for entry in leaderboard:
    if entry['username'] == data['username']:
      if entry['username'] in banned_users:
        entry['cps'] = 0
        break
      if data['cps'] < 59:
        if data['cps'] > entry['cps']:
          entry['cps'] = data['cps']
          break
      else:
        ban_user(entry['username'],'add')
        return redirect('/check-banned')

  write_to_csv(leaderboard)


#Read CPS Leaderboard


def read_from_csv():
  leaderboard = []
  with open('cps.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
      leaderboard.append({'username': row['username'], 'cps': int(row['cps'])})
  return leaderboard


#Read Banned users - not in use

def get_banned_usernames():
  with open('bannedUsers.csv', 'r') as banned_file:
    reader = csv.reader(banned_file)
    return [row[0] for row in reader]



#Write to Cps leaderboard


def write_to_csv(leaderboard):
  with open('cps.csv', 'w', newline='') as csvfile:
    fieldnames = ['username', 'cps']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for entry in leaderboard:
      writer.writerow({'username': entry['username'], 'cps': entry['cps']})


#Transfer money between accounts

def get_account_details(recipient):
    conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (recipient,))
    account = cur.fetchone()
    if account:
        return account  # Return the account details if found
    else:
        return None  # Return None if the account is not found

def transfer_money(sender, recipient, amount):
  sender_balance = get_balance(sender)
  recipient_balance = get_balance(recipient)

  if recipient_balance is None:
      flash("Recipient account does not exist", 'error')
      return redirect('/transfer')

  if sender == recipient:
      flash("Error in recipient", 'error')
      return redirect('/transfer')

  if sender_balance < amount:
      flash("Insufficient balance", 'error')
      return redirect('/transfer')

  # Check if recipient account exists in the database
  recipient_account_details = get_account_details(recipient)
  if recipient_account_details is not None:
      sender_balance -= amount
      recipient_balance += amount
      update_balance(sender, sender_balance)
      update_balance(recipient, recipient_balance)
      log_activity(sender, f"Transferred {amount} to {recipient}")
      log_activity(recipient, f"Received {amount} from {sender}")
      flash("Money transfer successful", 'success')
      time.sleep(1)
      return redirect('/transfer')
  else:
      flash("Recipient account does not exist", 'error')
      return redirect('/transfer')



#Double or nothing system (Random number and Comparison)


def don(username, guess):
  balance = get_balance(username)

  if balance < 2:
    flash("Insufficient balance", 'error')
    return redirect('/don')

  random_number = random.randint(0, 100)
  if guess == random_number:
    balance = balance * 2 - 2
    update_balance(username, balance)
    log_activity(username, f"Double or nothing: Won {balance}")
    flash(f"You beat the odds! Your balance is now £{balance}", 'success')
  else:
    balance -= 2
    update_balance(username, balance)
    log_activity(username, f"Double or nothing: Lost {balance}")
    flash(
      f"Better luck next time! The number was {random_number}. Your balance is now £{balance}",
      'error')

  return redirect('/don')


#Higherlower System - number comparison


def higherlower(username, guess, chosen):
  balance = get_balance(username)

  if balance < 1:
    flash('Insufficient balance', 'error')
    return redirect('/higher-lower')

  num = random.randint(1, 99)
  print(num)

  if chosen == 'higher':
    if guess > num:
      balance = math.floor(balance + 50)
      update_balance(username, balance)
      log_activity(username, f"Higher or lower: Won {balance}")
      flash(
        f"Correct {guess} is higher than {num}, your balance is now £{balance}",
        'success')
    else:
      balance -= 1
      update_balance(username, balance)
      log_activity(username, f"Higher or lower: Lost {balance}")
      flash(
        f"Unfortunately {guess} is not higher than {num}, your balance is now £{balance}",
        'error')
  elif chosen == 'lower':
    if guess < num:
      balance = math.floor(balance + 50)
      update_balance(username, balance)
      flash(
        f"Correct {guess} is lower than {num}, your balance is now £{balance}",
        'success')
    else:
      balance -= 1
      update_balance(username, balance)
      flash(
        f"Unfortunately {guess} is not lower than {num}, your balance is now £{balance}",
        'error')
      log_activity(username, f"Higher or lower: Lost {balance}")

  return redirect('/higher-lower')


#404
@app.errorhandler(404)
def page_not_found(e):
  return render_template('404.html'), 404


#405
@app.errorhandler(405)
def method_not_allowed(e):
  return render_template('405.html'), 405


#403
@app.errorhandler(403)
def access_denied(e):
  return render_template('403.html'), 403


@app.errorhandler(500)
def interalError():
  return render_template('500.html'), 500



#Mainpage
@app.route('/')
def login():
  return render_template('index.html')


#HigherLower page


@app.route('/higher-lower', methods=['GET', 'POST'])
def play_higher_lower():
  if 'username' not in session:
    return redirect('/')
  is_banned = session.get('is_banned') 
  if is_banned:
      return redirect('/check-banned')
  if session['frozen'] == True:
    return redirect('/check-banned')
    
  if request.method == 'GET':
    return render_template('Higherlower.html',
                           messages=flask.get_flashed_messages())

  username = session['username']
  guess = int(request.form['guess'])
  chosen = choice()

  return higherlower(username, guess, chosen)


#UserLookup Admin control


@app.route('/admin-control/user-lookup', methods=['POST'])
def user_lookup():
      if 'username' not in session:
        return redirect('/')

      if session['username'] not in ['admin', 'Arjun']:
        flash('Access denied', 'error')
        return redirect('/admin-control')

      lookup_username = request.form['lookup_username']
      admin_only_mode = get_admin_only_mode()
      conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password= os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
      )
      cur = conn.cursor()
      cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status, account_created, last_login, frozen, email FROM users WHERE username = %s", (lookup_username,))
      user = cur.fetchone()


      if user:
        flash(f"User '{lookup_username}' found.")
        user_lookup = {
          'username': user[0],
          'password': user[1],  # Note: This is the hashed password, not the plaintext password
          'is_admin': user[2],
          'balance': user[3],
          'banned': user[4],
          'created': user[5],
          'login': user[6],
          'frozen': user[7],
          'email': user[8]
        }
        # Fetch all users if needed for the admin-control page
        conn = psycopg2.connect(
            dbname=os.environ['PGDATABASE'],
            user=os.environ['PGUSER'],
            password= os.environ['PGPASSWORD'],
            host=os.environ['PGHOST']
        )
        cur = conn.cursor()
        cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status, account_created, last_login, frozen, email FROM users")
        users = cur.fetchall()
        # Convert the list of tuples into a list of dictionaries for the template
        users = [{'username': u[0], 'password': u[1], 'is_admin': u[2], 'balance': u[3], 'banned': u[4], 'created':u[5], 'login':u[6]} for u in users]
        return render_template('admin-control.html',
                               users=users,
                               admin_only_mode=admin_only_mode,
                               user_lookup=user_lookup)
      else:
        flash(f"User '{lookup_username}' not found.", 'error')
        return redirect('/admin-control')

# app.py
@app.route('/admin/user-actions/<username>', methods=['GET', 'POST'])
def admin_user_actions(username):
    if 'username' not in session or session['is_admin'] != True:
        flash('Access denied', 'error')
        return redirect('/')

    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password=os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status, account_created, last_login, frozen FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if user:
        user_details = {
            'username': user[0],
            'password': user[1],  # Note: This is the hashed password, not the plaintext password
            'is_admin': user[2],
            'balance': user[3],
            'banned': user[4],
            'created': user[5],
            'login': user[6],
            'frozen': user[7]
        }

        return render_template('admin_user_actions.html', user=user_details)
    else:
        flash(f"User '{username}' not found.", 'error')
        return redirect('/admin-control')


def get_all_user_info(username):
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password= os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status, account_created, last_login, cps, email FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    if user:
      user_info = {
          'username': user[0],
          'password': user[1],
          'is_admin': user[2],
          'balance': user[3],
          'banned': user[4],
          'created': user[5],
          'login': user[6],
          'cps': user[7],
          'email': user[8]
      }
      return user_info
    else:
      # Handle the case where the user is not found
      return None
    return user_info
  
#Update balance for user Admin Control


@app.route('/admin-control/update-balance', methods=['POST'])
def balance_update():
  if 'username' not in session:
    return redirect('/')

  if session['username'] not in ['admin', 'Arjun']:
    flash('Access denied', 'error')
    return redirect('/admin-control')

  username = request.form['username']
  amount = int(request.form['amount'])
  operation = request.form['operation']

  # Retrieve the user's current balance
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT balance FROM users WHERE username = %s", (username,))
  result = cur.fetchone()
  cur.close()

  if result is None:
    flash(f"User '{username}' not found.", 'error')
    return redirect('/admin-control')

  balance = result[0]

  # Perform the balance update based on the selected operation
  if operation == 'increase':
    balance += amount
  elif operation == 'decrease':
    balance -= amount

  # Update the balance in the database
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("UPDATE users SET balance = %s WHERE username = %s", (balance, username))
  conn.commit()
  cur.close()

  flash(f"Balance updated for user '{username}'", 'success')
  return redirect('/admin-control')


#Login Submission


@app.route('/login', methods=['POST'])
def user_login():
  username = request.form['username']
  password = request.form['password']

  # Regular login for all users
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT hashed_password, salt, admin_status FROM users WHERE username = %s", (username,))
  result = cur.fetchone()
  

  if result is None:
    flash('Username or password incorrect', 'error')
    return redirect('/')

  hashed_password, salt, is_admin = result

  if get_admin_only_mode() and not is_admin:
    flash('Login restricted', 'error')
    return redirect('/')

  if bcrypt.checkpw(password.encode(), hashed_password.encode()):
    session['username'] = username
    session['is_admin'] = is_admin
    cur.execute('UPDATE users SET last_login = %s WHERE username = %s', (datetime.datetime.utcnow(), username))
    conn.commit()
    print(datetime.datetime.utcnow())
    cur.close()
    flash('Login successful', 'success')
    return redirect('/check-banned')
  else:
    flash('Username or password incorrect', 'error')
    return redirect('/')

  return redirect('/')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/check-banned', methods=['GET'])
def check_banned():
    username = session.get('username')

    if username is None:
      return redirect('/')
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password= os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()

    cur.execute("SELECT email FROM users WHERE username = %s",(username,))
    result = cur.fetchone()
    if result[0] is None:
      return redirect('/change-email-form')
    cur.execute("SELECT verified FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    if result and result[0] == 0:
      return redirect('/verify')
    
    cur.execute("SELECT frozen FROM users WHERE username = %s", (username,))

    result = cur.fetchone()

    if result and result[0]:
      session['frozen'] = True
      return render_template('frozen.html')
    else:
      session['frozen'] = False
    cur.execute("SELECT banned_status FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    
    if result and result[0]:
      session['is_banned'] = True
      return render_template('delete_account.html')  # Create a template for account deletion
    else:
      session['is_banned'] = False

      return redirect('/dashboard')  # Redirect to the dashboard if the user is not banned

#Delete account admin DOES NOT WORK


@app.route('/admin-control/delete-account', methods=['POST'])
def delete_account_route():
  if 'username' not in session or session['username'] != 'Arjun':
    flash(f"Access Denied")
    return redirect('/admin-control')

  username = request.form['username']
  delete_account(username)
  flash(f"Account '{username}' deleted successfully", 'success')
  return redirect('/admin-control')


#Leaderboard


@app.route('/leaderboard')
def leaderboard():
  if session['frozen'] == True:
    return redirect('/check-banned')
  if session['is_banned'] == True:
    return redirect('/check-banned')
  
  users = get_user_accounts()
  sorted_users = sorted(users, key=lambda user: user['balance'], reverse=True)
  return render_template('leaderboard.html', users=sorted_users)


#Register User


@app.route('/register', methods=['GET', 'POST'])
def register():
  if get_admin_only_mode():
    flash('Registration is currently unavailable', 'error')
    return redirect('/')

  if request.method == 'GET':
    return render_template('register.html')

  username = request.form['username']
  password = request.form['password']
  confirm_password = request.form['confirm_password']
  email = request.form['email']
  
  if password != confirm_password:
    flash('Passwords do not match', 'error')
    return redirect('/register')

  if get_admin_only_mode() and not check_admin_status(username):
    flash('Registration is currently unavailable', 'error')
    return redirect('/')

  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT username FROM users WHERE username = %s", (username,))
  existing_usernames = [item[0] for item in cur.fetchall()]

  if username in existing_usernames:
    flash('Username already exists', 'error')
    return redirect('/register')
  if username[0] == '_':
    flash('Cannot start with an underscore', 'error')
    return redirect('/register')
  if len(password) < 6:
    flash('Password too short', 'error')
    return redirect('/register')

  salt = bcrypt.gensalt().decode()
  hashed_password = bcrypt.hashpw(password.encode(), salt.encode()).decode()
  verification_token = str(uuid.uuid4().hex)
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  
  cur = conn.cursor()
  cur.execute(
    "INSERT INTO users (username, hashed_password, salt, admin_status, balance, banned_status, cps, account_created, frozen, email, verification_token) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s)",
    (username, hashed_password, salt, False, 100, False, 0, datetime.datetime.utcnow(), False, email, verification_token)
  )
  cur.execute('UPDATE users SET last_login = %s WHERE username = %s', (datetime.datetime.utcnow(), username))
  conn.commit()
  cur.execute('SELECT id FROM users WHERE username = %s', (username,))
  user_id = cur.fetchone()[0]
  msg = Message('Verify Your Account', recipients=[email])
  msg.html = render_template('verification_email.html', user_id=user_id, token=verification_token)
  mail.send(msg)
  session['username'] = username
  flash('Registration successful', 'success')
  return redirect('/check-banned')

@app.route('/admin-control/update-frozen-users', methods=['POST'])
def update_frozen_users():
  if 'username' not in session or session['is_admin'] == 'False':
    flash("Access Denied")
    return redirect('/admin-control')

  username = request.form['username']
  action = request.form['action']
  if username == 'Arjun':
    flash('You do not have the permissions to freeze this user')
  else:
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password= os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    if action == 'add':
      # Set the banned_status to True for the specified username
      cur.execute("UPDATE users SET frozen = True WHERE username = %s", (username,))
      log_activity(username, "Frozen user")
      log_activity(session['username'], f"Froze {username}'s acccount")
      flash(f"User '{username}' added to Frozen Users", 'success')
    elif action == 'remove':
      # Set the banned_status to False for the specified username
      cur.execute("UPDATE users SET frozen = False WHERE username = %s", (username,))
      log_activity(username, "Thawed user")
      log_activity(session['username'], f"Thawed {username}'s acccount")
      flash(f"User '{username}' removed from Frozen Users", 'success')

    conn.commit()

  return redirect('/admin-control')

@app.route('/admin-control/update-banned-users', methods=['POST'])
def update_banned_users():
  if 'username' not in session or session['is_admin'] == 'False':
    flash(f"Access Denied")
    return redirect('/admin-control')

  username = request.form['username']
  action = request.form['action']
  if username == 'Arjun':
    flash('You do not have the permissions to ban this user')
  else:
    conn = psycopg2.connect(
        dbname=os.environ['PGDATABASE'],
        user=os.environ['PGUSER'],
        password= os.environ['PGPASSWORD'],
        host=os.environ['PGHOST']
    )
    cur = conn.cursor()
    if action == 'add':
      # Set the banned_status to True for the specified username
      cur.execute("UPDATE users SET banned_status = True WHERE username = %s", (username,))
      flash(f"User '{username}' added to Banned Users", 'success')
    elif action == 'remove':
      # Set the banned_status to False for the specified username
      cur.execute("UPDATE users SET banned_status = False WHERE username = %s", (username,))
      flash(f"User '{username}' removed from Banned Users", 'success')

    conn.commit()

  return redirect('/admin-control')


#Message Web page
def ban_user(username,action):

  if username == 'Arjun':
    return redirect('/check-banned')
  else:
    if action == 'add':
  # Add the username to the banned users list
      with open("bannedUsers.csv", 'a') as banned_file:
        banned_file.write(username + '\n')
        flash(f"User '{username}' has been banned")
        return redirect('/check-banned')
    elif action == 'remove':
  # Remove the username from the banned users list
     with open("bannedUsers.csv", 'r') as banned_file:
      lines = banned_file.readlines()
     with open("bannedUsers.csv", 'w') as banned_file:
      for line in lines:
        if line.strip() != username:
          banned_file.write(line)
  flash(f"User '{username}' removed from Banned Users", 'success')
  return redirect('/check-banned')

def load_group_messages(group_name):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password=os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()

  cur.execute("""
      SELECT sender, recipient, message, date
      FROM messages
      WHERE recipient = %s
      ORDER BY date DESC LIMIT 20
  """, (f"_{group_name}",))

  group_messages = [{'sender': sender, 'recipient': group_name, 'message': message, 'timestamp': date.strftime("%Y-%m-%d %H:%M:%S")}
                     for sender, _, message, date in cur.fetchall()]

  cur.close()
  conn.close()

  return group_messages


def save_group_message(sender, group_name, message):
  try:
      conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password=os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
      )
      cur = conn.cursor()

      timestamp = datetime.datetime.utcnow()
      cur.execute("""
          INSERT INTO messages (sender, recipient, message, date)
          VALUES (%s, %s, %s, %s)
      """, (sender, f"_{group_name}", message, timestamp))

      conn.commit()

  except Exception as e:
      print(f"Error saving group message: {e}")

  finally:
      cur.close()
      conn.close()

def get_user_group_names(username):
  try:
    conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
    )
    cur = conn.cursor()

    # Fetch the group names based on the group IDs from the 'group_members' table
    cur.execute("""
        SELECT groups.group_name
        FROM groups
        JOIN group_members ON groups.group_id = group_members.group_id
        WHERE group_members.username = %s
    """, (username,))
    user_group_names = [row[0] for row in cur.fetchall()]

  except Exception as e:
    # Handle the exception (print, log, etc.)
    print(f"Error getting user group names: {e}")
    user_group_names = []

  finally:
    if cur:
        cur.close()
    if conn:
        conn.close()

  return user_group_names

def get_group_list():
  current_user = session.get('username')

  if current_user:
    user_group_names = get_user_group_names(current_user)
  else:
    user_group_names = []

  return user_group_names

@app.route('/message', methods=['GET', 'POST'])
def message():
  if 'username' not in session:
    return redirect('/')
    
  if session['is_banned'] == True:
    return redirect('/check-banned')
  
  if session['frozen'] == True:
    return redirect('/check-banned')
  if request.method == 'POST':
    sender = session['username']
    recipient = request.form['recipient']
    message = request.form['message']
    save_message(sender, recipient, message)
  group_list = get_group_list()
  print(group_list)
  current_user = session.get('username')
  active_chats = get_active_chats(current_user)
  return render_template('message.html',
                         active_chats=active_chats,group_list=group_list)


#Login User Function

#Dashboard


@app.route('/dashboard')
def dashboard():

  if 'username' not in session:
    return redirect('/')
  conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  username = session.get('username')
  cur.execute("SELECT banned_status FROM users WHERE username = %s", (username,))
  result = cur.fetchone()

  if result and result[0]:
    session['is_banned'] = True
    return redirect('/check-banned')

  cur.execute("SELECT frozen FROM users WHERE username = %s", (username,))
  result = cur.fetchone()

  if result and result[0]:
    session['frozen'] = True
    return redirect('/check-banned')
  
  username = session['username']
  balance = get_balance(username)
  is_admin = check_admin_status(username)

  return render_template('dashboard.html',
                         username=username,
                         balance=balance,
                         is_admin=is_admin)


@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
  if 'username' not in session:
    return redirect('/')
  is_banned = session.get('is_banned') 
  if is_banned:
      return redirect('/check-banned')
  if session['frozen'] == True:
    return redirect('/check-banned')
    

  username = session['username']
  user = get_user_by_username(username)
  balance = user['balance']

  if request.method == 'GET':
    question = random.choice(questions)
    return render_template('quiz.html', question=question, balance=balance)

  answer = request.form.get('answer')
  question_id = request.form.get('question_id')

  question = next((q for q in questions if q['question'] == question_id), None)
  if question is None:
    flash('Invalid question', 'error')
    return redirect('/quiz')

  if answer == question['answer']:
    balance += 2
    update_balance(username, balance)
    flash('Correct answer! Your balance has been updated.', 'success')
  else:
    flash('Incorrect answer.', 'error')

  return redirect('/quiz')


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
  if 'username' not in session:
    return redirect('/')
  is_banned = session.get('is_banned') 
  if is_banned:
      return redirect('/check-banned')
  if request.method == 'GET':
    return render_template('transfer.html')

  sender = session['username']
  recipient = request.form['recipient']
  amount = int(request.form['amount'])
  if amount < 0:
    flash(f"Please enter a valid Value")
    return redirect('/transfer')
  result = transfer_money(sender, recipient, amount)
  return result


@app.route('/command-inactive', methods=['GET', 'POST'])
def command_inactive():
  return render_template('command_inactive.html')


@app.route('/don', methods=['GET', 'POST'])
def play_don():
  if 'username' not in session:
    return redirect('/')
  is_banned = session.get('is_banned') 
  if is_banned:
      return redirect('/check-banned')
  if request.method == 'GET':
    return render_template('don.html')

  username = session['username']
  guess = int(request.form['guess'])

  return don(username, guess)


@app.route('/signout', methods=['POST'])
def sign_out():
  session.pop('username', None)
  session.pop('is_admin', None)
  return redirect('/')




@app.route('/toggle-admin-only-mode', methods=['POST'])
def toggle_admin_only_mode():
    admin_only_mode = 'admin_only_mode' in request.form
    if set_admin_only_mode(admin_only_mode):
        flash('Admin-only mode toggled successfully!', 'success')
    else:
        flash('Error toggling admin-only mode.', 'error')
    return redirect('/admin-control')  # Redirect back to admin control page
# For some reason Python still does not register an update and I am too tired to figure this out :/

@app.route('/admin-control', methods=['GET', 'POST'])
def admin_control():
  if 'username' not in session:
    return redirect('/')

  if not check_admin_status(session['username']):  # Call the renamed function
    flash('Access denied. You must be an admin to access this page.', 'error')
    return redirect('/dashboard')

  if request.method == 'POST':
    # Handle the form submission
    if 'action' in request.form:
      username = request.form['username']
      action = request.form['action']

      # Perform the necessary actions based on the form input
      if action == 'promote':
        # Promote the user to admin status
        promote_user(username)
      elif action == 'demote':
        # Demote the user from admin status
        demote_user(username)




  # Retrieve the list of user accounts
  users = get_user_accounts()
  admin_only_mode = get_admin_only_mode()

  return render_template('admin-control.html',
                         users=users,
                         admin_only_mode=admin_only_mode)


@app.route('/cps', methods=['GET'])
def cps():
  if 'username' in session:
    is_banned = session.get('is_banned') 
    if is_banned:
        return redirect('/check-banned')
    if session['frozen'] == True:
      return redirect('/check-banned')
    return render_template('cps.html')
      
  else:
    return redirect('/')

def update_cps_if_higher(username, cps):
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT cps FROM users WHERE username = %s", (username,))
  current_cps = cur.fetchone()

  if current_cps is None or cps > current_cps[0]:
    cur.execute("UPDATE users SET cps = %s WHERE username = %s", (cps, username))
    conn.commit()


@app.route('/cps-process', methods=['POST'])
def cps_process():
  username = request.form['username']
  cps = int(request.form['cps'])
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT banned_status FROM users WHERE username = %s", (username,))
  result = cur.fetchone()

  if cps > 58:
    if username != 'Arjun':
      cur.execute("UPDATE users SET banned_status = True WHERE username = %s", (username,))
      conn.commit()
      cur.close()
      return redirect('/check-banned')
    else:
      action = f"{username} scored {cps} CPS"
      log_activity(username, action)
      update_cps_if_higher(username, cps)  # Integrate the update_cps_if_higher function here
      return redirect('/clicks-leaderboard')
  else:
    update_cps_if_higher(username,cps)
    return redirect('/clicks-leaderboard')

@app.route('/clicks-leaderboard')
def clicks_leaderboard():
  is_banned = session.get('is_banned') 
  if is_banned:
      return redirect('/check-banned')
  if session['frozen'] == True:
    return redirect('/check-banned')
    
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute("SELECT username, cps FROM users ORDER BY cps DESC")
  sorted_leaderboard = cur.fetchall()
  formatted_leaderboard = [{
    "rank": rank + 1,
    "username": user[0],
    "cps": user[1]
  } for rank, user in enumerate(sorted_leaderboard)]
  cur.close()
  return render_template('clicks_leaderboard.html', leaderboard=formatted_leaderboard)


@app.route('/settings')
def settings():
  if 'username' not in session:
    return redirect('/')
  frozen_status = session.get('frozen')
  if frozen_status == True:
    return redirect('/check-banned')
  user_lookup = get_all_user_info(session['username'])
  return render_template('settings.html', user_lookup=user_lookup)


@app.route('/user-delete', methods=["POST"])
def user_delete():
  if session['frozen'] == True:
    return redirect('/check-banned')
  username = session['username']
  delete_account(username=username)
  flash("Account Deleted", "info")
  return redirect('/')


@app.route('/change-password', methods=['POST'])
def change_password():
    if 'username' not in session:
        flash('You must be logged in to change your password', 'error')
        return redirect('/login')

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        username = session['username']

      
        conn = psycopg2.connect(
          dbname=os.environ['PGDATABASE'],
          user=os.environ['PGUSER'],
          password= os.environ['PGPASSWORD'],
          host=os.environ['PGHOST']
        )
        cur = conn.cursor()
        cur.execute("SELECT hashed_password, salt FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        hashed_password, salt = result
        # Check if the old password matches the current password
        username = session['username']
        if bcrypt.checkpw(old_password.encode(), hashed_password.encode()):
          if new_password != confirm_new_password:
              flash('New passwords do not match', 'error')
          elif len(new_password) < 6:
              flash('New password must be at least 6 characters long', 'error')
          else:
            
              salt = bcrypt.gensalt().decode()
              hashed_password = bcrypt.hashpw(new_password.encode(), salt.encode()).decode()

              # Update the password in the database
              conn = psycopg2.connect(
                  dbname=os.environ['PGDATABASE'],
                  user=os.environ['PGUSER'],
                  password=os.environ['PGPASSWORD'],
                  host=os.environ['PGHOST']
              )
              cur = conn.cursor()
              cur.execute("UPDATE users SET hashed_password = %s, salt = %s WHERE username = %s", (hashed_password, salt, username))
              conn.commit()
              conn.close()
              flash('success')
              return redirect('/dashboard')
        else:
          flash("Old password incorrect","error")
          return redirect('/dashboard')


    return render_template('settings.html')


def update_password(username, new_password, new_salt):
  # Update the user's password and salt in the database
  with open('database.csv', 'r') as db_file:
    data = [line.strip().split(', ') for line in db_file]

  for i, record in enumerate(data):
    if record[0] == username:
      data[i][1] = new_password  # Update the password
      break

  with open('database.csv', 'w') as db_file:
    for record in data:
      db_file.write(', '.join(record) + '\n')

  # Update the user's salt in the salts.csv file
  with open('salts.csv', 'r') as salts_file:
    salt_data = [line.strip().split(', ') for line in salts_file]

  for i, record in enumerate(salt_data):
    if record[0] == username:
      salt_data[i][1] = new_salt  # Update the salt
      break

  with open('salts.csv', 'w') as salts_file:
    for record in salt_data:
      salts_file.write(', '.join(record) + '\n')

"""
def delete_old_password(username):
  # Delete the old password hash from the database
  with open('database.csv', 'r') as db_file:
    data = [line.strip().split(', ') for line in db_file]

  for i, record in enumerate(data):
    if record[0] == username:
      data[i][1] = ''  # Set the password hash to an empty string
      break

  with open('database.csv', 'w') as db_file:
    for record in data:
      db_file.write(', '.join(record) + '\n')

This code is deprecated, but im leaving it here :)
"""

if __name__ == "__main__":
  Compress(app)
  http_server = WSGIServer(('', 5000), app)
  http_server.serve_forever()