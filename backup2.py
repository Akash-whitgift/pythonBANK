from gevent import monkey
monkey.patch_all()
from gevent.pywsgi import WSGIServer
from flask_compress import Compress
from flask import Flask, render_template, request, redirect, session, flash
from flask import jsonify
import flask
import random
import time
import math
import configparser
import csv
import os
import bcrypt
import datetime
import _strptime
app = Flask(__name__)
key = str(random.randrange(16**32))
app.secret_key = key
CONFIG_FILE = 'config.ini'
ADMIN_ONLY_MODE = False
message_history = []
leaderboard = []
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
        'question': 'Who is the all-time leading goal scorer in the history of FIFA World Cup?',
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
        'question': 'Who is the all-time leading scorer for the Brazilian national football team?',
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
        'question': 'Who holds the record for the highest individual score in Test cricket?',
        'options': ['Brian Lara', 'Sachin Tendulkar', 'Virender Sehwag', 'Don Bradman'],
        'answer': 'Brian Lara'
    },
    {
        'question': 'Which programming language is known as the "mother of all languages"?',
        'options': ['C', 'Java', 'Python', 'Assembly'],
        'answer': 'C'
    },
    {
        'question': 'What is the unit of information in computing and telecommunications?',
        'options': ['Bit', 'Byte', 'Megabyte', 'Gigabyte'],
        'answer': 'Bit'
    },
    {
        'question': 'Which country has won the most ICC Cricket World Cup titles?',
        'options': ['Australia', 'India', 'West Indies', 'England'],
        'answer': 'Australia'
    },
    {
        'question': 'Which algorithm is used to sort a list of elements in ascending or descending order?',
        'options': ['Bubble Sort', 'Binary Search', 'Quick Sort', 'Merge Sort'],
        'answer': 'Merge Sort'
    },
    {
        'question': 'What is the distance covered by light in one year called?',
        'options': ['Light-year', 'Parsec', 'Astronomical Unit', 'Nautical Mile'],
        'answer': 'Light-year'
    },
    {
        'question': 'Who holds the record for the fastest century in One Day International (ODI) cricket?',
        'options': ['AB de Villiers', 'Chris Gayle', 'Shahid Afridi', 'Corey Anderson'],
        'answer': 'AB de Villiers'
    },
    {
        'question': 'Which programming language was created by Guido van Rossum?',
        'options': ['Python', 'Ruby', 'C++', 'JavaScript'],
        'answer': 'Python'
    },
    {
        'question': 'What is the diameter of a cricket ball?',
        'options': ['between 22.4 and 22.9 centimeters', 'between 21.0 and 21.7 centimeters', 'between 23.5 and 24.1 centimeters', 'between 20.0 and 20.7 centimeters'],
        'answer': 'between 22.4 and 22.9 centimeters'
    },
]


bannedUsers = ['Zayd','RYAN PATEL','k.patel@whitgift.co.uk']

#delete account (Currently not working)
def delete_account(username):
    # Delete the user's file
    filename = f"{username}"
    os.remove(filename)

    # Remove the user's data from the database
    with open("database.csv", 'r') as db:
        data = [line.strip().split(', ') for line in db]

    for i, record in enumerate(data):
        if record[0] == username:
            del data[i]
            break

    with open("database.csv", 'w') as db:
        for record in data:
            db.write(', '.join(record) + '\n')

#Get messages for a user

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
    users = []
    with open('database.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            username = row[0]
            hashed_password = row[1]
            is_admin = int(row[2] == 'True')

            # Read the user file to retrieve the balance
            with open(username, 'r') as balance_file:
                balance = int(balance_file.read().strip())

            user = {
                'username': username,
                'password': hashed_password,
                'is_admin': is_admin,
                'balance': balance
            }
            users.append(user)

    return users

#Checks account admin status

def is_admin(username):
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

        for record in data:
            if record[0] == username:
                return record[2] == 'True'

        return False

# Admin only mode (breaks for some reason if turned on)

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
   
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

    for i, record in enumerate(data):
        if record[0] == username:
            data[i][2] = 'True'

    with open("database.csv", 'w') as db:
        for record in data:
            db.write(','.join(record) + '\n')

#Gets User Balance

def get_balance(username):
    with open(username, 'r') as balance_file:
        balance = int(balance_file.read())
    return balance

#Updates User balance

def update_balance(username, balance):
    with open(username, 'w') as balance_file:
        balance_file.write(str(balance))

#demotes user from Admin status
      
def demote_user(username):
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

    for i, record in enumerate(data):
        if record[0] == username:
            data[i][2] = 'False'

    with open("database.csv", 'w') as db:
        for record in data:
            db.write(','.join(record) + '\n')

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
    return render_template('leaderboard.html',users=users)

#Set Admin only mode (Cannot be disabled from web portal for some reason)

def set_admin_only_mode(admin_only_mode):
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'AppConfig' not in config:
        config.add_section('AppConfig')
    config.set('AppConfig', 'admin_only_mode', str(admin_only_mode))

    with open(CONFIG_FILE, 'w') as config_file:
        config.write(config_file)

#Checks if Admin only mode is enabled

def get_admin_only_mode():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'AppConfig' in config and 'admin_only_mode' in config['AppConfig']:
        return config.getboolean('AppConfig', 'admin_only_mode')
    return False

#Random choice Function

def choice():
    lst = ['higher', 'lower']
    chosen = random.choice(lst)
    return chosen

#Checks User credential with salt

def check_credentials(username, password):
    with open("database.csv", 'r') as db:
        data = [line.strip().split(',') for line in db]

    with open("salts.csv", 'r') as salts_file:
        salts_data = [line.strip().split(',') for line in salts_file]

    users = {record[0]: (record[1], None) for record in data}
    salts = {record[0]: record[1] for record in salts_data}

    if username in users and username in salts:
        hashed_password, salt = users[username][0].encode('utf-8'), salts[username].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), salt + hashed_password):
            session['username'] = username
            session['is_admin'] = users[username][2] == 'True'
            return session['is_admin']

    flash("Username or password incorrect")
    return False

#Update Clicks per second leaderboard

def update_leaderboard(data):
    leaderboard = read_from_csv()
    banned_users = ['shack','Zayd'] #Banned
    for entry in leaderboard:
        if entry['username'] == data['username']:
            if entry['username'] in banned_users:
                entry['cps'] = 0
                break
            if data['cps'] < 100:
                if data['cps'] > entry['cps']:
                    entry['cps'] = data['cps']
                    break

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

def readBannedUsers():
    leaderboard = []
    with open('banned.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            leaderboard.append({'username': row['username'], 'Banned': str(row['Banned'])})
    return bannedUsers

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
    time.sleep(2)
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
        flash(f"Better luck next time! The number was {random_number}. Your balance is now £{balance}", 'error')

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
            flash(f"Correct {guess} is higher than {num}, your balance is now £{balance}", 'success')
        else:
            balance -= 1
            update_balance(username, balance)
            flash(f"Unfortunately {guess} is not higher than {num}, your balance is now £{balance}", 'error')
    elif chosen == 'lower':
        if guess < num:
            balance = math.floor(balance + 50)
            update_balance(username, balance)
            flash(f"Correct {guess} is lower than {num}, your balance is now £{balance}", 'success')
        else:
            balance -= 1
            update_balance(username, balance)
            flash(f"Unfortunately {guess} is not lower than {num}, your balance is now £{balance}", 'error')

    return redirect('/higher-lower')

#404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#405
@app.errorhandler(405)
def method_not_allowed(e):
  return render_template('405.html'),405

#403
@app.errorhandler(403)
def access_denied(e):
  return render_template('403.html'),403

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
        return render_template('Higherlower.html', messages=flask.get_flashed_messages())

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
    users = get_user_accounts()
    admin_only_mode = get_admin_only_mode()
    user = None

    for u in users:
        if u['username'] == lookup_username:
            user = u
            break

    if user:
        flash(f"User '{lookup_username}' found.")
        user_lookup = {
            'username': user['username'],
            'password': user['password'],
            'is_admin': user['is_admin'],
            'balance': user['balance']  # Include the balance in the user_lookup dictionary
        }
        return render_template('admin-control.html', users=users, admin_only_mode=admin_only_mode, user_lookup=user_lookup)
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
    balance = get_balance(username)

    # Perform the balance update based on the selected operation
    if operation == 'increase':
        balance += amount
    elif operation == 'decrease':
        balance -= amount

    # Update the balance in the database
    update_balance(username, balance)

    flash(f"Balance updated for user '{username}'", 'success')
    return redirect('/admin-control')

#Login Submission

@app.route('/login', methods=['POST'])
def user_login():
    username = request.form['username']
    password = request.form['password']

    if get_admin_only_mode():
        # Check if the user is an admin
        if not check_credentials(username, password):
            flash('Invalid Credentials, do you have an account?', 'error')
            return redirect('/')

        # Perform additional checks for admin users
        if not is_admin(username):
            flash('Admin-only mode is enabled. Only admin users can log in at the moment.', 'error')
            return redirect('/')
    else:
        # Regular login for non-admin users
        with open('database.csv', 'r') as db:
            reader = csv.reader(db)
            for row in reader:
                if row[0] == username:
                    hashed_password = row[1]
                    is_admin = row[2] == 'True'
                    break
            else:
                flash('Invalid username', 'error')
                return redirect('/')

        with open('salts.csv', 'r') as salts_file:
            reader = csv.reader(salts_file)
            for row in reader:
                if row[0] == username:
                    salt = row[1]
                    break
            else:
                flash('Invalid username', 'error')
                return redirect('/')

        if bcrypt.checkpw(password.encode(), hashed_password.encode()):
            session['username'] = username
            session['is_admin'] = is_admin
            flash('Login successful', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid password', 'error')
            return redirect('/')

    return redirect('/dashboard')

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

    if get_admin_only_mode() and not is_admin(username):
        flash('Registration is currently unavailable', 'error')
        return redirect('/')

    with open('database.csv', 'r') as db:
        existing_usernames = [line.split(',')[0].strip() for line in db.readlines()]

    if username in existing_usernames:
        flash('Username already exists', 'error')
        return redirect('/register')

    if len(password) < 6:
        flash('Password too short', 'error')
        return redirect('/register')

    salt = bcrypt.gensalt().decode()
    hashed_password = bcrypt.hashpw(password.encode(), salt.encode()).decode()

    with open('database.csv', 'a', newline='') as db:
        writer = csv.writer(db, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        writer.writerow([username, hashed_password, 'False'])

    with open('salts.csv', 'a', newline='') as salts_file:
        writer = csv.writer(salts_file)
        writer.writerow([username, salt])

    with open(username, 'w') as name_balance:
        name_balance.write('100')
    with open('cps.csv','a',newline='') as cps:
      writer = csv.writer(cps,delimiter=',',quoting=csv.QUOTE_MINIMAL)
      writer.writerow([username,'0'])
    flash('Registration successful', 'success')
    return redirect('/')

#Message Web page

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
    message_history.sort(key=lambda x: _strptime._strptime(x['timestamp'], "%Y-%m-%d %H:%M:%S"), reverse=True)

    recipient_filter = request.args.get('recipient_filter', '')  # Get the recipient filter from the query parameters

    # Apply the recipient filter if specified
    if recipient_filter:
        message_history = [message for message in message_history if
                           message['recipient'] == recipient_filter or message['sender'] == recipient_filter]

    return render_template('message.html', users=get_user_accounts(), message_history=message_history,
                           recipient_filter=recipient_filter)

#Login User Function

def user_login():
    username = request.form['username']
    password = request.form['password']

    if get_admin_only_mode():
        if not check_credentials(username, password):
            flash('Invalid Credentials, do you have an account?', 'error')
            return redirect('/')

        if not is_admin(username):
            flash('Login is currently unavailable', 'error')
            return redirect('/')

    else:
        if not check_credentials(username, password):
            flash('Invalid Credentials, do you have an account?', 'error')
            return redirect('/')
    return redirect('/dashboard')

#Change password - not used - no template

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        username = session['username']
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = authenticate_user(username, old_password)
        if not user:
            flash('Invalid old password', 'error')
            return redirect('/change-password')

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect('/change-password')

        change_user_password(username, new_password)
        flash('Password changed successfully', 'success')
        return redirect('/dashboard')

    return render_template('change_password.html')

#Dashboard

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    username = session['username']
    balance = get_balance(username)
    is_admin = session.get('is_admin', False)



    return render_template('dashboard.html', username=username, balance=balance, is_admin=is_admin)

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

    return render_template('message.html', users=get_user_accounts(), recipient=recipient, message_history=message_history)


@app.route('/admin-control', methods=['GET', 'POST'])
def admin_control():
    if 'username' not in session:
        return redirect('/')

    if not is_admin(session['username']):
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
        else:
            # Handle the admin_only_mode checkbox
            admin_only_mode = False
            if 'admin_only_mode' in request.form:
                admin_only_mode = True
            set_admin_only_mode(admin_only_mode)

    # Retrieve the list of user accounts
    users = get_user_accounts()
    admin_only_mode = get_admin_only_mode()

    return render_template('admin-control.html', users=users, admin_only_mode=admin_only_mode)
@app.route('/cps',methods=['GET'])
def cps():
    if 'username' in session:
        return render_template('cps.html')
    else:
        return redirect('/login')
@app.route('/cps-process', methods=['POST'])
def cps_process():
    username = request.form['username']
    cps = int(request.form['cps'])
    update_leaderboard({'username': username, 'cps': cps})
    return redirect('/clicks-leaderboard')


@app.route('/clicks-leaderboard')
def clicks_leaderboard():
    leaderboard = read_from_csv()
    sorted_leaderboard = sorted(leaderboard, key=lambda user: user["cps"], reverse=True)
    formatted_leaderboard = [{"rank": rank + 1, "username": user["username"], "cps": user["cps"]} for rank, user in enumerate(sorted_leaderboard)]
    return render_template('clicks_leaderboard.html', leaderboard=formatted_leaderboard)



if __name__ == "__main__":
    Compress(app)
    http_server = WSGIServer(('', 5000), app)
    http_server.serve_forever()

