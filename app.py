import mysql.connector
import bcrypt
import random
import smtplib
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function to establish a connection to the MySQL database
def get_db_connection():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='root',
        database='auth_system'
    )
    return connection

def send_otp(email, otp):
    sender_email = "sai402707@gmail.com"  # Replace with your Gmail
    sender_password = ""  # Replace with your Google App Password
    
    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}"
    
    message = f"Subject: {subject}\n\n{body}"
    
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message)
        server.quit()
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        if not validate_password(password):
            flash("Password must contain at least one uppercase letter, one lowercase letter, and be at least 8 characters long.")
            return render_template('signup.html')

        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Email already exists! Please try a different one.")
            return render_template('signup.html')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        cursor.execute('INSERT INTO users (name, email, password) VALUES (%s, %s, %s)', (name, email, hashed_password.decode('utf-8')))
        connection.commit()
        
        cursor.close()
        connection.close()
        
        flash("Account successfully created! Please login.")
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute('SELECT email, password FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            flash("You have successfully logged in!", "success")
        else:
            flash("Please enter correct details!", "error")
        
        cursor.close()
        connection.close()
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if email and not otp and not new_password:
            if user:
                session['reset_email'] = email
                session['otp'] = str(random.randint(100000, 999999))
                send_otp(email, session['otp'])
                flash("OTP sent successfully to your email!")
                return render_template('forgot_password.html', step=2)
            else:
                flash("No account exists with that email.")
                return render_template('forgot_password.html', step=1)

        elif otp and otp == session.get('otp'):
            return render_template('forgot_password.html', step=3)

        elif new_password and confirm_password:
            if new_password == confirm_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, session['reset_email']))
                connection.commit()
                
                session.pop('reset_email', None)
                session.pop('otp', None)
                
                flash("Password updated successfully! Please login.")
                return redirect(url_for('login'))
            else:
                flash("Passwords do not match.")
                return render_template('forgot_password.html', step=3)

        cursor.close()
        connection.close()
    
    return render_template('forgot_password.html', step=1)

# Helper function to validate password
def validate_password(password):
    if len(password) < 8 or not any(char.islower() for char in password) or not any(char.isupper() for char in password):
        return False
    return True

if __name__ == '__main__':
    app.run(debug=True)
