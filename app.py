from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from functools import wraps
from flask import session, redirect, url_for, flash
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key


# Configure AWS RDS connection
# Configure AWS RDS connection
RDS_ENDPOINT = 'dbdemo.cluw0oqy8wj5.us-east-1.rds.amazonaws.com'
RDS_USERNAME = 'admin'
RDS_DB_NAME = 'counter'

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

# Fetch user by ID
@login_manager.user_loader
def load_user(user_id):
    with get_db_connection().cursor() as cursor:
        cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
    if user:
        return User(user['id'], user['username'], user['role'])
    return None

# Initialize counts for doors
door_counts = {
    "main_door": 0,
    "side_door": 0
}

def get_db_connection():
    return pymysql.connect(
        host=RDS_ENDPOINT,
        user=RDS_USERNAME,
        password=os.environ['db_pw'],
        db=RDS_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        role = request.form.get('role', 'user')  # Default to 'user' if no role is specified

        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                sql = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
                cursor.execute(sql, (username, password_hash,role))
            connection.commit()
        finally:
            connection.close()

        #flash('Signup successful! Please log in.')

        return redirect(url_for('login'))
    return render_template('signup.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()
        finally:
            connection.close()

        if user['role'] != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function

@app.route('/redirect_dashboard')
@login_required
def redirect_dashboard():
    print(("Taking to dashboard"))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_portal'))
    else:
        return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username + " "+password)
        connection = get_db_connection()
        try:
            # Update the order quantities and inventory numbers
            with connection.cursor() as cur:
                cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                cur.close()
                print(user)

                if user and check_password_hash(user['password_hash'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    print("User authenticated")
                    user_obj = User(user['id'], user['username'], user['role'])
                    login_user(user_obj)
                    print(f"User {username} logged in successfully.")
                    if user['role'] == 'admin':
                        print("Admin role detected")
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('index'))

                #flash('Invalid username or password.')
                return redirect(url_for('login'))
        finally:
            connection.close()
    return render_template('login.html')



# @app.route('/dashboard', methods=['GET', 'POST'])
# @login_required
# def dashboard():
#     if 'username' not in session:
#         flash('Please log in to access this page.')
#         return redirect(url_for('login'))

#     username = session['username']
#     search_query = request.form.get('search', '')

#     connection = get_db_connection()
#     try:
#         with connection.cursor() as cursor:
#             sql = "SELECT id FROM users WHERE username = %s"
#             cursor.execute(sql, (username,))
#             user = cursor.fetchone()

#             if user:
#                 user_id = user['id']
#                 sql = "SELECT * FROM orders WHERE user_id = %s AND status != 'Deleted' ORDER BY id DESC"
#                 cursor.execute(sql, (user_id,))
#                 orders = cursor.fetchall()
#                 # print(orders)

#                 if search_query:
#                     sql = "SELECT id, name FROM items WHERE name LIKE %s"
#                     cursor.execute(sql, ('%' + search_query + '%',))
#                 else:
#                     sql = "SELECT id, name FROM items"
#                     cursor.execute(sql)
#                 items = cursor.fetchall()
#             else:
#                 orders = []
#                 items = []
#     finally:
#         connection.close()

#     return render_template('dashboard.html', orders=orders)



# @app.route('/admin')
# @login_required
# @admin_required
# def admin_portal():
#     if session.get('role') != 'admin':
#         flash('Access denied.')
#         return redirect(url_for('dashboard'))

#     connection = get_db_connection()
#     with connection.cursor() as cur:
#         query = """
#                 SELECT orders.id, orders.created_at, orders.status, users.username
#                 FROM orders
#                 JOIN users ON orders.user_id = users.id
#                 WHERE orders.status = %s ORDER BY orders.id DESC
#             """
#         cur.execute(query, ('Pending',))
#         pending_orders = cur.fetchall()
#         cur.close()
#         return render_template('admin_portal.html', pending_orders=pending_orders,user=session.get('role'))



@app.route('/logout')
def logout():
    session.pop('username', None)
    #flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if new_password != confirm_new_password:
            flash('New passwords do not match')
            return redirect(url_for('reset_password'))

        username = session['username']
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                sql = "SELECT password FROM users WHERE username = %s"
                cursor.execute(sql, (username,))
                user = cursor.fetchone()

                if user and check_password_hash(user['password'], current_password):
                    hashed_new_password = generate_password_hash(new_password)
                    update_sql = "UPDATE users SET password = %s WHERE username = %s"
                    cursor.execute(update_sql, (hashed_new_password, username))
                    connection.commit()
                    flash('Password successfully updated')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Current password is incorrect')
        except Exception as e:
            print(f"Error: {e}")
        finally:
            connection.close()

    return render_template('reset_password.html')





#counter functions


# Function to save the counts to MySQL
def save_count():
    if current_user.is_authenticated:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            print("Saving counts to AWS RDS MySQL...")
            cursor.execute("UPDATE door_counts SET count = %s WHERE user_id = %s AND door = 'main_door'", (door_counts["main_door"], current_user.id))
            cursor.execute("UPDATE door_counts SET count = %s WHERE user_id = %s AND door = 'side_door'", (door_counts["side_door"], current_user.id))
        
        connection.commit()
        print("Counts saved to the database.")
    Timer(10, save_count).start()

# Route to get the current counts for a user
@app.route('/get_count', methods=['GET'])
def get_count():
    if current_user.is_authenticated:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT door, count FROM door_counts WHERE user_id = %s", (current_user.id,))
            counts = cursor.fetchall()
            door_counts = {door: count for door, count in counts}
            return jsonify(door_counts)
    return jsonify({"error": "User not authenticated"}), 401


# Route to update the count for a specific door for the logged-in user
@app.route('/update_count', methods=['POST'])
@login_required
def update_count():
    data = request.json
    door = data.get('door')
    count = data.get('count')

    if not door or count is None:
        return jsonify({'status': 'error', 'error': 'Invalid data'})

    try:
        # Update the count for the selected door and user
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE door_counts 
                SET count = count + %s 
                WHERE user_id = %s AND door = %s
            """, (count, current_user.id, door))
        connection.commit()

        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error updating count: {e}")
        return jsonify({'status': 'error', 'error': str(e)})

# Function to sync count manually or from the timer
def sync_count():
    if current_user.is_authenticated:
        print("Syncing counts to backend...")
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE door_counts SET count = %s WHERE user_id = %s AND door = 'main_door'", 
                        (door_counts["main_door"], current_user.id))
            cursor.execute("UPDATE door_counts SET count = %s WHERE user_id = %s AND door = 'side_door'", 
                       (door_counts["side_door"], current_user.id))
        connection.commit()
        print("UPDATE door_counts SET count = %s WHERE user_id = %s AND door = 'side_door'")
        print()
        print()
        return jsonify({"status": "success", "message": "Counts synced to the backend"})
    return jsonify({"error": "User not authenticated"}), 401

# Admin dashboard to view all users and their counts


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':  # Ensure only admin can access this page
        return "Unauthorized", 403

    try:
        # Fetch all users and their door counts
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.username, 
                    SUM(CASE WHEN dc.door = 'main_door' THEN dc.count ELSE 0 END) AS main_door_count,
                    SUM(CASE WHEN dc.door = 'side_door' THEN dc.count ELSE 0 END) AS side_door_count
                FROM users u
                LEFT JOIN door_counts dc ON u.id = dc.user_id
                GROUP BY u.id
            """)
            users_data = cursor.fetchall()

            # Calculate total count across all users
            cursor.execute("SELECT SUM(count) AS total_count FROM door_counts")
            total_count = cursor.fetchone()['total_count'] or 0

            return render_template('admin_dashboard.html', users_data=users_data, total_count=total_count)
    except Exception as e:
        print(f"Error loading admin dashboard: {e}")
        return "Error loading admin dashboard", 500



@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT u.username, d.door, d.count FROM door_counts d JOIN users u ON d.user_id = u.id")
    user_data = cursor.fetchall()
    users_info = {}
    for username, door, count in user_data:
        if username not in users_info:
            users_info[username] = {"main_door": 0, "side_door": 0}
        users_info[username][door] = count
    
    return render_template('dashboard.html', users_info=users_info)


@app.route('/get_total_count', methods=['POST'])
@login_required
def get_total_count():
    if not request.json or 'door' not in request.json:
        return jsonify({'error': 'Invalid request'}), 400

    door = request.json['door']

    try:
        # Fetch the total count for the specified door
        connection = get_db_connection()
        print('checking the door value in backend')
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT count AS total_count
                FROM door_counts
                WHERE door = %s and user_id = %s
            """, (door,current_user.id))
            result = cursor.fetchone()
            total_count = result['total_count'] or 0  # Default to 0 if no count exists

        return jsonify({'status': 'success', 'total_count': total_count})
    except Exception as e:
        print(f"Error fetching total count: {e}")
        return jsonify({'error': 'Could not fetch total count'}), 500
    

# Route to the main page (user selects the door)
@app.route('/')
def index():
    return render_template('index.html')

# # Admin dashboard to view all users and their counts
# @app.route('/dashboard')
# @login_required
# def dashboard():
#     if current_user.role != 'admin':
#         return redirect(url_for('index'))

#     cursor.execute("SELECT u.username, d.door, d.count FROM door_counts d JOIN users u ON d.user_id = u.id")
#     user_data = cursor.fetchall()
#     users_info = {}
#     for username, door, count in user_data:
#         if username not in users_info:
#             users_info[username] = {"main_door": 0, "side_door": 0}
#         users_info[username][door] = count
    
#     return render_template('dashboard.html', users_info=users_info)

if __name__ == '__main__':
    app.run( debug=True,host='0.0.0.0')