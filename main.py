from gevent import monkey
monkey.patch_all()
from gevent.pywsgi import WSGIServer
from flask_compress import Compress
from flask import Flask, render_template, request, redirect, session, flash
import flask
import random
import time
import math
import csv
import os
import bcrypt
import datetime
import _strptime
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
  conn.commit()

@app.route('/delete-account', methods=['POST'])
def delete_account_for_user():
    username = session['username']

    # Remove the user's data from the database
    cur.execute("DELETE FROM users WHERE username = %s", (username,))
    # Commit the changes to the database
    conn.commit()

    return redirect('/')

def get_user_messages(username):
  messages = []
  with open('database.txt', 'r') as file:
    for line in file:
      sender, recipient, message, timestamp = line.strip().split(' - ')
      if sender == username or recipient == username:
        messages.append({
          'sender': sender,
          'recipient': recipient,
          'message': message,
          'timestamp': timestamp
        })
  return messages


#Save sent message


def save_message(sender, recipient, message):
  timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  with open('database.txt', 'a') as file:
    file.write(f"{sender} - {recipient} - {message} - {timestamp}\n")
  flash(f"You have a new message from {sender}: {message}", 'info')


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


#Update Clicks per second leaderboard


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


def transfer_money(sender, recipient, amount):
  sender_balance = get_balance(sender)
  recipient_balance = get_balance(recipient)
  if sender == recipient:
    flash("Error")
    return redirect('/transfer')
  if sender_balance < amount:
    flash("Insufficient balance", 'error')
    return redirect('/transfer')

  sender_balance -= amount
  recipient_balance += amount

  update_balance(sender, sender_balance)
  update_balance(recipient, recipient_balance)

  flash("Money transfer successful", 'success')
  time.sleep(1)
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
    flash(f"You beat the odds! Your balance is now £{balance}", 'success')
  else:
    balance -= 2
    update_balance(username, balance)
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
      flash(
        f"Correct {guess} is higher than {num}, your balance is now £{balance}",
        'success')
    else:
      balance -= 1
      update_balance(username, balance)
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


#Not used
@app.route('/messages/<username>')
def messages(username):
  user_messages = get_user_messages(username)
  return render_template('messages.html', messages=user_messages)


#Mainpage
@app.route('/')
def login():
  return render_template('index.html')


#HigherLower page


@app.route('/higher-lower', methods=['GET', 'POST'])
def play_higher_lower():
  if 'username' not in session:
    return redirect('/')
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
      cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status FROM users WHERE username = %s", (lookup_username,))
      user = cur.fetchone()


      if user:
        flash(f"User '{lookup_username}' found.")
        user_lookup = {
          'username': user[0],
          'password': user[1],  # Note: This is the hashed password, not the plaintext password
          'is_admin': user[2],
          'balance': user[3],
          'banned': user[4]
        }
        # Fetch all users if needed for the admin-control page
        conn = psycopg2.connect(
            dbname=os.environ['PGDATABASE'],
            user=os.environ['PGUSER'],
            password= os.environ['PGPASSWORD'],
            host=os.environ['PGHOST']
        )
        cur = conn.cursor()
        cur.execute("SELECT username, hashed_password, admin_status, balance, banned_status FROM users")
        users = cur.fetchall()
        # Convert the list of tuples into a list of dictionaries for the template
        users = [{'username': u[0], 'password': u[1], 'is_admin': u[2], 'balance': u[3], 'banned': u[4]} for u in users]
        return render_template('admin-control.html',
                               users=users,
                               admin_only_mode=admin_only_mode,
                               user_lookup=user_lookup)
      else:
        flash(f"User '{lookup_username}' not found.", 'error')
        return redirect('/admin-control')


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
  cur.close()

  if result is None:
    flash('Invalid username', 'error')
    return redirect('/')

  hashed_password, salt, is_admin = result

  if get_admin_only_mode() and not is_admin:
    flash('Login restricted', 'error')
    return redirect('/')

  if bcrypt.checkpw(password.encode(), hashed_password.encode()):
    session['username'] = username
    session['is_admin'] = is_admin
    flash('Login successful', 'success')
    return redirect('/check-banned')
  else:
    flash('Invalid password', 'error')
    return redirect('/')

  return redirect('/')


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
    cur.execute("SELECT banned_status FROM users WHERE username = %s", (username,))
    result = cur.fetchone()

    if result and result[0]:  # Assuming banned_status is a boolean or integer field
      return render_template('delete_account.html')  # Create a template for account deletion
    else:
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

  if len(password) < 6:
    flash('Password too short', 'error')
    return redirect('/register')

  salt = bcrypt.gensalt().decode()
  hashed_password = bcrypt.hashpw(password.encode(), salt.encode()).decode()
  
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  cur.execute(
    "INSERT INTO users (username, hashed_password, salt, admin_status, balance, banned_status, cps) VALUES (%s, %s, %s, %s, %s, %s, %s)",
    (username, hashed_password, salt, False, 100, False, 0)
  )
  conn.commit()


  flash('Registration successful', 'success')
  return redirect('/')


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

@app.route('/message', methods=['GET', 'POST'])
def message():
  if 'username' not in session:
    return redirect('/')

  if request.method == 'POST':
    sender = session['username']
    recipient = request.form['recipient']
    message = request.form['message']
    save_message(sender, recipient, message)

  message_history = []

  # Fetch all messages sent or received by the user
  with open('database.txt', 'r') as file:
    for line in file:
      values = line.strip().split(' - ')
      if len(values) == 4:
        sender, recipient, message, timestamp = values
        if sender == session['username'] or recipient == session['username']:
          message_history.append({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': timestamp
          })

  # Sort the message history in reverse order based on timestamp
  message_history.sort(
    key=lambda x: _strptime._strptime(x['timestamp'], "%Y-%m-%d %H:%M:%S"),
    reverse=True)

  recipient_filter = request.args.get(
    'recipient_filter',
    '')  # Get the recipient filter from the query parameters

  # Apply the recipient filter if specified
  if recipient_filter:
    message_history = [
      message for message in message_history
      if message['recipient'] == recipient_filter
      or message['sender'] == recipient_filter
    ]

  return render_template('message.html',
                         users=get_user_accounts(),
                         message_history=message_history,
                         recipient_filter=recipient_filter)


#Login User Function

#Dashboard


@app.route('/dashboard')
def dashboard():
  conn = psycopg2.connect(
      dbname=os.environ['PGDATABASE'],
      user=os.environ['PGUSER'],
      password= os.environ['PGPASSWORD'],
      host=os.environ['PGHOST']
  )
  cur = conn.cursor()
  if 'username' not in session:
    return redirect('/')

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


@app.route('/message/<username>')
def message_user(username):
  if 'username' not in session:
    return redirect('/')

  recipient = get_user_by_username(username)
  if not recipient:
    flash(f"User '{username}' not found.", 'error')
    return redirect('/message')

  return render_template('message.html',
                         users=get_user_accounts(),
                         recipient=recipient,
                         message_history=message_history)

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
      update_cps_if_higher(username, cps)  # Integrate the update_cps_if_higher function here
      return redirect('/clicks-leaderboard')
  else:
    update_cps_if_higher(username,cps)
    return redirect('/clicks-leaderboard')

@app.route('/clicks-leaderboard')
def clicks_leaderboard():
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
  return render_template('settings.html')


@app.route('/user-delete', methods=["POST"])
def user_delete():
  username = session['username']
  delete_account(username=username)
  flash("Account Deleted", "info")
  return redirect('/')


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
  if 'username' not in session:
    flash('You must be logged in to change your password', 'error')
    return redirect('/login')

  if request.method == 'POST':
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_new_password = request.form['confirm_new_password']
    print(old_password, new_password, confirm_new_password)
    # Check if the old password matches the current password
    username = session['username']
    if not check_credentials(username, old_password):
      flash('Old password is incorrect', 'error')
    elif new_password != confirm_new_password:
      flash('New passwords do not match', 'error')
    elif len(new_password) < 6:
      flash('New password must be at least 6 characters long', 'error')
    else:
      # Generate a new salt and hash for the new password
      salt = bcrypt.gensalt().decode()
      hashed_password = bcrypt.hashpw(new_password.encode(),
                                      salt.encode()).decode()

      # Update the password and salt in the database
      update_password(username, hashed_password, salt)

      # Delete the old password hash
      delete_old_password(username)

      flash('Password changed successfully', 'success')
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


if __name__ == "__main__":
  Compress(app)
  http_server = WSGIServer(('', 5000), app)
  http_server.serve_forever()
