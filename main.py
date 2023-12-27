# Standard Imports
import os
import re
from datetime import date, datetime, timedelta

# Third-Party Imports
import bleach
import string
import random
import smtplib
import logging
import psycopg2
from functools import wraps

import requests
from flask_mail import Mail, Message
from requests import RequestException
from flask import send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, session, flash, redirect, url_for, g


app = Flask(__name__, static_folder="Uploads", static_url_path="/Uploads")


#  ALL CONFIGURATIONS.
UPLOAD_FOLDER = "Uploads/Profile"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Set the maximum file size to 1MB for file uploads
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB limit

# Set up Flask app configuration with updated reCAPTCHA keys
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld6zBQpAAAAAMgNi9K1FcZ1P5p9vpFKHhHFP5Tu'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Ld6zBQpAAAAACCeLS0sOyQhgpiNuMneP-_EuX1b'

# Set session lifetime to 60 minutes (3600 seconds) == 1 hour
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)

app.config["SECRET_KEY"] = "*(SbXi=a<bV~8a4v@AWlOT-w"
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "intuitivers@gmail.com"
app.config["MAIL_PASSWORD"] = "kgan dfin hlmj fgfu "
app.config["MAIL_DEFAULT_SENDER"] = "intuitivers@gmail.com"
mail = Mail(app)


# Database connection
conn = psycopg2.connect(
    database="altruistics",
    user="postgres",
    password="perfect",
    host="localhost",
    port="5432",
)


@app.teardown_appcontext
def close_db_connection(exception=None):
    """
    Teardown function to close the database connection.

    Parameters:
    - exception: Exception object (default is None).

    Functionality:
    - Closes the database connection if it exists in the global context ('g').
    """
    # Get the database connection from the global context ('g')
    db_connection = getattr(g, "_db_connection", None)
    # Check if the connection exists
    if db_connection is not None:
        # Close the database connection
        db_connection.close()


# Establish a connection to PostgreSQL database
def get_db_connection():
    """
    Establish a connection to the PostgreSQL database.

    Returns:
    - PostgreSQL database connection.

    Functionality:
    - Retrieves the database connection from the global context ('g').
    - If the connection is not present,
    establishes a new connection and stores it in 'g'.
    """
    # Get the database connection from the global context ('g')
    db_connection = getattr(g, "_db_connection", None)
    # Check if the connection is not present
    if db_connection is None:
        # Establish a new connection to the PostgreSQL database
        db_connection = g._db_connection = psycopg2.connect(
            database="altruistics",
            user="postgres",
            password="perfect",
            host="localhost",
            port="5432",
        )
    # Return the established or existing database connection
    return db_connection


# AM NOT SURE WITH THIS PART: I HAVE NOT TESTED IT YET.
def get_old_email(user_id):
    """
    Retrieve the old email address associated with a user.

    Parameters:
    - user_id: ID of the user in the database.

    Returns:
    - Old email address associated with the user.

    Functionality:
    - Executes an SQL query to fetch the email address for the specified user_id.
    """
    # Create a cursor to interact with the database
    cursor = conn.cursor()

    # Execute an SQL query to select the email from the 'accounts' table based on user_id
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))

    # Fetch the first row of the result and get the email value
    email = cursor.fetchone()[0]

    # Close the cursor to release resources
    cursor.close()

    # Return the retrieved email address
    return email


#  generate a random verification token of length 64
def generate_verification_token(length=64):
    """
    Generate a random verification token.

    Parameters:
    - length: Length of the token (default is 64).

    Returns:
    - Randomly generated verification token.

    Functionality:
    - Uses a combination of letters and digits
    to generate a random token of the specified length.
    """
    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


#  THIS PART (index, about, contact terms of services, privacy policies)
@app.route("/")
def index():
    """
    Route for the main index page.

     Returns:
     - flask.render_template: Renders the 'index.html' template.
    """

    return render_template("index-.html")


@app.route("/about")
def about():
    """
    Route for the 'About' page.

    Returns:
    - flask.render_template: Renders the 'about.html' template.
    """
    return render_template("Intuitivers/about-.html")


@app.route("/terms")
def terms_of_services():
    """
    Route for the 'Terms of service Page'
    :return:
        - flask.render_template terms-of-services template,
        -located in Intuitivers folder
    """
    return render_template("Intuitivers/terms-of-services-.html")


@app.route("/privacy_policy")
def privacy_policy():
    """
    Route for the 'Privacy Policy Page'
    :return:
        - flask.render_template privacy-policy template,
        -located in Intuitivers folder
    """
    return render_template("Intuitivers/privacy-policy-.html")


@app.route("/services")
def services():
    """
    Route for 'services' Page

    return:
     - flask.render_template: Renders the services.html Page
      located in the Intuitivers folder
    """
    return render_template("Intuitivers/services-.html")


@app.route('/Intuitivers/contact-.html')
def contacts():
    return render_template('Intuitivers/contact.html')


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """
    Handle the contact form functionality.

    This contact route handles both GET and POST requests.
    On GET, it renders the 'contact.html' template, allowing users
    to view and fill out the contact form. On POST, it processes the submitted form,
    sends an email to the support team, and redirects the user to the home page.

    Args:
        (GET request) or form data (POST request) None.

    Returns:
        flask.render_template or flask.redirect:
        The rendered template or a redirection response.
    """
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        message = request.form["message"]
        subject = request.form["subject"]

        # sanitize user inputs.
        name = bleach.clean(name)
        email = bleach.clean(email)
        message = bleach.clean(message)
        subject = bleach.clean(subject)

        # Email your support team with the user's message
        support_email = "intuitivers@gmail.com"  # support team's email address
        email_message = Message(
            f"{subject.upper()} " f"from {name.title()}", recipients=[support_email]
        )
        email_message.body = (
            f"Name: {name.title()}\nEmail: "
            f"{email.lower()}\n\nMessage:\n{message.upper()}"
        )

        mail.send(email_message)

        flash(
            "success: Message has been sent to our support team."
            " We will get back to you soon!",
            "success",
        )
        # Redirect to the homepage page after submission
        return redirect(url_for("contact"))

    return render_template("/Intuitivers/contact-.html")


# Minimum length of character in first name, last name and country.
MIN_LENGTH = 3


# THIS FUNCTION HERE WORK WELL: VERSION 2.0. Nov 14 Tuesday
def generate_security_pin(first_name, last_name, country, username):
    """
    Generate a security pin for account deletion.
    Extract the first letter from each field and convert to uppercase.

    Parameters:
    - first_name: First name of the user.
    - last_name: Last name of the user.
    - country: Country of the user.
    - username: Username of the user.

    Returns:
    - Security PIN generated from the first letters of the input fields.
    """
    # Extract the first letter from the first name and convert to uppercase
    first_letter_first_name = first_name[0].upper()

    # Extract the first letter from the last name and convert to uppercase
    first_letter_last_name = last_name[0].upper()

    # Extract the first letter from the country and convert to uppercase
    first_letter_country = country[0].upper()

    # Extract the first letter from the username and convert to uppercase
    first_letter_username = username[0].upper()

    # Combine the first letters to form the security PIN
    pin = (
        f"{first_letter_first_name}{first_letter_last_name}"
        f"{first_letter_country}{first_letter_username}"
    )

    # Return the generated security PIN
    return pin


# THIS FUNCTION WORK WELL: VERSION 2.0
def send_security_pin_email(email, pin, username):
    try:
        # Create a message with the security PIN and send it to the user's email
        email_message = Message(
            "Security PIN for Account Deletion", recipients=[email]
        )
        email_message.body = (
            # I CHANGED THIS PART WHEN OFF LINE I WILL BE BACK.
            f"Hello {username.title()}!!,\n\n"
            f"Your security PIN for account deletion is: {pin}\n\n"
            f"Please keep this PIN secure, as it will be used "
            f"during account deletion purposes. If you lose this PIN, "
            f"please contact our support team for assistance. Please note that"
            f" we may require additional information to verify your identity.\n\n"
            f"Thank you for choosing us!\n\n"
            f"Best regards,\n"
            f"The AuthFlaskApp Team"
        )
        mail.send(email_message)

        return True  # Email sent successfully
    except smtplib.SMTPAuthenticationError:
        flash(
            "Error: Failed to authenticate with the email server. "
            "Please contact our support team for assistance.",
            "error",
        )
        return False  # Email sending failed due to authentication error

    except smtplib.SMTPException:
        flash(
            "Error: An error occurred while sending the email. "
            "Please contact our support team for assistance.",
            "error",
        )
        return False  # Email sending failed due to other SMTP-related issues


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def is_strong_password(password):
    """
    Check if a password meets the criteria for a strong password.

    Parameters:
    - password (str): The password to be checked.

    Returns:
    - bool: True if the password is strong, False otherwise.

    Criteria:
    - The password must be at least eight characters long.
    - It must contain at least one numeric character or one special character.
    """
    # The Password must be
    # at least eight characters
    # long and contain, one space
    # and one special character
    # and one alphanumeric character
    return len(password) >= 8 and (
        re.search(r"\d", password)
        or re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        or " " in password
    )


# WORK AS I NEED: VERSION: 2.0 Nov 14 Tues
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handle user registration. If the request method is POST:
        - Extract user information from the registration form.
        - Validate email, password strength, first and last name,
          username, and country before storing them in a database.

        - Hash the password using PBKDF2 with SHA-256 salt_length = 8.
        - Check if the email or username already exists in the database.
        - Generate a random security PIN and a verification token for email verification.
        - Insert user data into the database and send email verification messages.
        - Render the registration success page.

    If the request method is GET:
        - Render the registration form.

    Returns:
        flask.render_template: Renders the 'registration_form.html' template for GET requests.
        flask.redirect: Redirects to the 'register' route after successfully registering a user.
        flask.render_template: Renders the 'registration_success.html' template after successful registration.
        flask.render_template: Renders the 'email_send_error.html' template if there's an email sending failure.

    """

    if request.method == "POST":
        email = request.form["email"].lower()
        first_name = request.form["first_name"].title()
        last_name = request.form["last_name"].title()
        username = request.form["username"]
        password = request.form["password"]
        country = request.form["country"].title()

        # it's a good practice to
        # sanitize user inputs in all routes
        # where user input is accepted, especially
        # if that input is later displayed on your web page.
        # Sanitizing inputs helps prevent security
        # vulnerabilities such as Cross-Site Scripting (XSS).

        # Sanitize user inputs
        email = bleach.clean(email)
        first_name = bleach.clean(first_name)
        last_name = bleach.clean(last_name)
        username = bleach.clean(username)
        password = bleach.clean(password)
        country = bleach.clean(country)

        # Generate security PIN
        pin = generate_security_pin(first_name, last_name, country, username)

        # Validate reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Error: reCAPTCHA verification failed. Please try again.', 'error')
            return redirect(url_for('register'))

        # Include reCAPTCHA secret key
        recaptcha_secret_key = '6Ld6zBQpAAAAACCeLS0sOyQhgpiNuMneP-_EuX1b'
        recaptcha_data = {
            'secret': recaptcha_secret_key,
            'response': recaptcha_response
        }

        recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify', data=recaptcha_data)
        recaptcha_result = recaptcha_verification.json()

        if not recaptcha_result['success']:
            flash('reCAPTCHA verification failed. Please try again.', 'error')
            return redirect(url_for('register'))

        # Validate email format
        if not email or "@" not in email:
            flash("Error: Invalid email address.", "error")
            return redirect(url_for("register"))

        # Validate the password strength
        # if not is_strong_password(password):
        #   flash(
        #      'Password must be at least eight characters
        #      long and contain at least one uppercase, lowercase,
        #      digit,and special character.' 'error')
        # return redirect(url_for('register'))  # redirect tho the same page to try again

        if (
                len(password) < 8
                or not re.search(r"[A-Z]", password)
                or not re.search(r"[a-z]", password)
                or not re.search(r"[0-9]", password)
                or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        ):
            flash(
                "Error: Password must be at least 8 characters long "
                "and contain at least one uppercase letter, one lowercase letter,"
                " one digit, and one special character.",
                "error",
            )
            return redirect(url_for("register"))

        # Validate first name, last name, and username
        if (
                len(first_name) < MIN_LENGTH
                or len(last_name) < MIN_LENGTH
                or len(username) < MIN_LENGTH
        ):
            flash(
                "Error: Name and username must be at least {}"
                " characters long.".format(MIN_LENGTH),
                "error",
            )
            return redirect(url_for("register"))

            # Validate first name, last name, username, and country
        if not (first_name.isalpha() and first_name[0].isalpha()):
            flash("Invalid first name.", "error")
            return redirect(url_for("register"))

        if not (last_name.isalpha() and last_name[0].isalpha()):
            flash("Invalid last name.", "error")
            return redirect(url_for("register"))

        if not (username.isalpha() and username[0].isalpha()):
            flash("Invalid username.", "error")
            return redirect(url_for("register"))

        if not (country.isalpha() and country[0].isalpha()):
            flash("Invalid country name.", "error")
            return redirect(url_for("register"))

        # Hash the password using PBKDF2 with SHA-256 before storing it in the database
        hashed_password = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=8
        )

        # Check if the email and username already exist
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM accounts " "WHERE email = %s OR username = %s",
            (email, username),
        )
        existing_user = cursor.fetchone()

        if existing_user:
            flash(
                "Error: username or email address already used. "
                "Use another email and or username",
                "error",
            )
            return redirect(url_for("register"))

        # Generate a random token for email verification
        verification_token = "".join(
            random.choices(string.ascii_letters + string.digits, k=32)
        )

        # Calculations of day, date, month and year of registration
        registration_date = datetime.now()
        day = registration_date.day
        month = registration_date.month
        year = registration_date.year

        # Insert the user data into the database
        cursor.execute(
            "INSERT INTO accounts (email, first_name, last_name, "
            "username, password, country, day, month, year, verified, pin) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                email,
                first_name,
                last_name,
                username,
                hashed_password,
                country,
                day,
                month,
                year,
                False,
                pin,
            ),
        )
        # Get the id of the newly inserted account
        account_id = cursor.fetchone()[0]

        #  An SQL cursor named 'cursor' and a database connection named 'conn'
        cursor.execute(
            "INSERT INTO tokens "
            "(account_id, username, email, verification_token) VALUES (%s, %s, %s, %s)",
            (account_id, username, email, verification_token),
        )

        # Send an email verification message
        email_message = Message("Account Activation.", recipients=[email])

        # local server is running on port 5000
        server_address = "http://localhost:5000"
        email_message.body = (
            f"Hello {username},\n\n"
            f"We are excited to welcome you to our AuthFlaskApp platform! To complete your registration please "
            f"verify your email address, click the link below:\n\n"
            f"Verification Link: {server_address}/verify/{verification_token}\n\n"
            f"This link is valid for 10 minutes. If you didn't sign up for an account, please ignore "
            f"this email someone might mistyped your email address. "
            f"For any assistance or questions, feel free to contact our support team.\n\n"
            f"Best regards,\n"
            f"The AuthFlaskApp Team"
        )
        mail.send(email_message)

        # Send security PIN email
        email_sent = send_security_pin_email(email, pin, username)

        if not email_sent:
            # Handle email sending failure
            return render_template("email_send_error.html")

        # Send a congratulatory email for social media account registration
        congratulatory_message = Message(
            "Welcome to Our Social Media Community", recipients=[email]
        )
        congratulatory_message.body = (
            f"Hello,\n\n"
            f"Welcome to our social media community! We are delighted to have you on board. You have successfully registered "
            f"for our platform, and we can't wait for you to start connecting with others and exploring the exciting content "
            f"our community has to offer.\n\n"
            f"Here are a few things you can do to get started:\n"
            f"- Complete your profile: Add a profile picture and a short bio to let others know more about you.\n"
            f"- Connect with others: Find and connect with friends, family, and people with shared interests.\n"
            f"- Explore content: Dive into posts, photos, videos, and discussions shared by our vibrant community members.\n\n"
            f"If you have any questions or need assistance, feel free to reach out to our support team. Thank you for joining "
            f"us, and we hope you have a wonderful experience!\n\n"
            f"Best regards,\n"
            f"The AuthFlaskApp Team"
        )
        mail.send(congratulatory_message)

        return render_template("/General/Info/Success/registration-success-.html")

    return render_template("/Auth/registration-form-.html")


@app.route("/verify/<token>", methods=["GET"])
def verify_email(token):
    """
    Verify the user's email using a verification token.

    This route is responsible for
    processing the verification token provided in the URL during registration.
    It checks the validity of the token, whether it has expired or not, and updates the
    user's account status to 'verified' in the database. The verification link is valid for
    10 minutes. If the token is valid, the user is redirected to the login page with a
    notification to log in. If the token is invalid or has expired, an appropriate error
    message is displayed, and the user is redirected to request a new verification token.

    Args:
        token (str): The verification token extracted from the URL.

    Returns:
        flask.Response: A redirect to the login page or the resend_verification page, or
        a rendered template in case of an error.
    """

    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM tokens " "WHERE verification_token = %s", (token,))
    token_data = cursor.fetchone()

    if token_data:
        # Check if the verification link has expired (valid for 10 minutes)
        verification_sent_time = token_data[
            5
        ]  # Verification_sent_time is in the 6th column
        current_time = datetime.now()

        # Calculate the time difference in minutes
        time_difference = (
            current_time - verification_sent_time).total_seconds() / 60

        # the verification link is valid for 10 minutes
        if time_difference <= 10:
            # Update the 'verified' column to
            # mark the user as verified in the table accounts
            cursor.execute(
                "UPDATE accounts SET verified = TRUE " "WHERE id = %s", (
                    token_data[1],)
            )

            # Delete the verification token
            # from the table tokens after successful verification
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))

            # Commit transaction to save changes in the database
            conn.commit()
            cursor.close()

            # flash a success message after successful verification.
            # redirect to login page.
            flash("success: Account verified, you can now log in.")

            # after success verification
            # of the account redirect to log in page to continue
            return redirect(url_for("login"))
        else:
            # Verification link has expired, delete the token from the table tokens
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))
            conn.commit()
            cursor.close()

            # if the token has been expired due to time
            flash(
                "Error: The token already "
                "expired due to time. Request a new token here.",
                "error",
            )

            # redirect to resend_verification route
            # to request a new email for verifying users' email account
            return redirect(url_for("resend_verification"))
    else:
        # the token has been used, and it is not present in the database
        return render_template("General/verification_error.html")


# Function to generate a 6-digit random token for 2FA accounts
def generate_token():
    two_fa_token = "".join(random.choices(string.digits, k=6))
    # Print generated token for debugging
    print(f"Generated Token: {two_fa_token}")
    return two_fa_token


# Function to insert 2FA token into the accounts table if 2FA is enabled for the user
def insert_tfa_token_to_table(user_id, token):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT tfa " "FROM accounts WHERE id = %s", (user_id,))
                enable_tfa = cursor.fetchone()

                if enable_tfa and enable_tfa[0] == "T":
                    # Update the auth_token field and
                    # token_timestamp in the table accounts for the specific user
                    update_query = (
                        "UPDATE accounts "
                        "SET auth_token = %s, ttmp = %s WHERE id = %s"
                    )

                    token_timestamp = datetime.now()  # Get the current timestamp
                    cursor.execute(
                        update_query, (token, token_timestamp, user_id))

                    # Print the stored token and user ID for debugging
                    print("Stored Token: {token} for User ID: {user_id}")

                    # Commit the transaction to save changes to the database
                    conn.commit()

                else:
                    print(
                        f"2FA is not enabled for User ID: {user_id}. Token not stored."
                    )

    # handle database-specific error
    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        flash("Error: Database error occurred. " "Please try again later.", "error")

    # handle network-related error
    except RequestException as request_error:
        print(f"Network request error: {request_error}")
        flash(
            "Error: Network request error occurred. " "Please try again later.", "error"
        )

    # handle value-related error
    except ValueError as value_error:
        print(f"Value error: {value_error}")
        flash(
            "Error: Invalid value error occurred. " "Please check your input.", "error"
        )

    except Exception as e:
        print(f"Unexpected error: {e}")
        flash(
            "Error: An unexpected error occurred. " "Please try again later.", "error"
        )

        conn.rollback()  # Rollback the transaction in case of an error


def send_tfa_token_email(email, token, username):
    # Print the token and email for debugging
    print(f"Sending token: {token} to email: {email}")

    msg = Message(
        "Authentication Code for Your Account",
        sender="intuitivers@gmail.com",
        recipients=[email],
    )
    msg.html = (
        f"<p>Hello {username},</p>"
        f"<p>We detected a new login attempt on your account. "
        f"To continue, please enter the verification code below:</p>"
        f"<p style='font-size: 30px; font-weight: bold; color: teal'>Verification Code: {token}</p>"
        f"<p>Please enter this code to complete the login process. "
        f"If you did not request this, please ignore this email.</p>"
        f"<p>For your account security, if you did not initiate this login attempt, "
        f"your password might be compromised, "
        f"we recommend changing your password immediately to prevent"
        f" unauthorized access.</p>"
        f"<p>Thank you for using our service!</p>"
        f"<p>Best regards,<br>The AuthFlaskApp Team</p>"
    )
    mail.send(msg)


# Function to store 2FA token in the database
def store_tfa_token(user_id, token):
    """
    Store 2FA token in the database.

    Update the auth_token field and
    token_timestamp in the table accounts for the specific user.

    Args:
        user_id (int): The user's ID.
        token (str): The generated 2FA token. 2FA Two-Factor Authentication token

    Returns:
        None
    """
    # Update the auth_token field and
    # token_timestamp in the table accounts for the specific user
    update_query = "UPDATE accounts SET auth_token = %s, ttmp = %s WHERE id = %s"
    token_timestamp = datetime.now()
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(update_query, (token, token_timestamp, user_id))
            conn.commit()


# Function to get user by username from the database
def get_user_by_username(username):
    """
    Get user by username from the database.

    Args:
        username (str): The username of the user.

    Returns:
        dict or None: A dictionary representing the user if found, None otherwise.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM accounts " "WHERE username = %s", (username,)
                )
                user = cursor.fetchone()
                return user
    except psycopg2.Error as e:
        # Handle the exception based on your application's needs
        # logging.error(f"Database error: {e}", exc_info=True)
        print(f"Database error: {e}")
        return None


# Function to get stored 2FA token and timestamp from the database based on user_id
def get_stored_tfa_token_and_timestamp(user_id):
    """
    Get stored 2FA token and timestamp from the database based on user_id.

    Args:
        user_id (int): The user's ID.

    Returns:
        tuple or None:
        A tuple containing the stored token and timestamp if found, None otherwise.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT auth_token, ttmp FROM accounts " "WHERE id = %s", (
                        user_id,)
                )
                stored_token, token_timestamp = cursor.fetchone()
                return stored_token, token_timestamp

    except psycopg2.Error as e:
        # Handle the exception based on your application's needs
        print(f"Database error: {e}")

        return None, None


MAX_FAILED_ATTEMPTS = 3  # Maximum allowed consecutive failed attempts
LOCKOUT_DURATION_MINUTES = 5  # Lockout duration in minutes


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handle user login functionality.

    If the request method is POST, retrieve the entered username and password from the database.
    Check if the username exists in the database and verify the entered password to match with the stored password.
    If the username and password match with the stored user data AND If the user is verified and has 2FA enabled,
    generate a token, send it via email, and proceed to the 2FA verification process.

    Else:
        If 2FA is not enabled, proceed to the dashboard and store user data in the session.
        If the user is not verified, render an account not verified template to inform a user.
        If the username or password is incorrect, display a flash message for incorrect login credentials.
        If the request method is GET, render the login form again.

    Returns:
        If login credentials (username and or password) are incorrect, flash an invalid username or password message.
        A rendered template or a redirect to another route based on the login outcome.
    """

    if "user_id" in session:
        # If the user is already logged in,
        # and their session data is still active
        # try to access the login page to log in again.
        # Direct them directly to the dashboard without
        # the need to provide login credentials at this time
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Verify reCAPTCHA response
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash("Error: Please complete the reCAPTCHA challenge.", "error")
            return render_template("/Auth/login-form-.html")

        #  reCAPTCHA secret key
        recaptcha_secret_key = "6Ld6zBQpAAAAACCeLS0sOyQhgpiNuMneP-_EuX1b"

        # Verify reCAPTCHA response using Google reCAPTCHA API
        recaptcha_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_params = {
            'secret': recaptcha_secret_key,
            'response': recaptcha_response,
        }

        recaptcha_verification = requests.post(recaptcha_url, data=recaptcha_params)
        recaptcha_data = recaptcha_verification.json()

        if not recaptcha_data['success']:
            flash("Error: Failed reCAPTCHA verification.", "error")
            return render_template("/Auth/login-form-.html")

        username = request.form["username"]
        password = request.form["password"]

        # Check if the username exists in the database
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM accounts " "WHERE username = %s", (username,)
                )
                user = cursor.fetchone()

        # check if the password during login matches with the stored hashed password
        if user and check_password_hash(user[5], password):
            print(f"User {username} found and password matched.")

            # Check if the user is verified
            if user[12]:  # verified column is the 13th column in the table accounts
                print("User is verified.")

                # Check if 2FA is activated for the user's account
                if user[14] == "T":  # tfa column is the 15th column in the table accounts
                    print("2FA is enabled.")
                    # Generate a 6-digit token
                    token = generate_token()  # generate_token: The function responsible

                    # Print the token for debugging
                    print(f"Generated Token: {token}")

                    # Inside the login route, after setting session variables
                    # Send the token to the user's email address and store it in the database
                    # user[1] is the email column, and its (2nd column in table accounts)

                    # send_tfa_token_email: The function responsible
                    send_tfa_token_email(user[1], token, username)

                    # Insert the token into the table accounts
                    # 'insert_tfa_token_to_table': The function responsible
                    insert_tfa_token_to_table(user[0], token)

                    conn.commit()  # Commit transaction to save changes in the database

                    # Inside the '2FA is enabled' branch
                    print(
                        f"Setting session variables: "
                        f"user_id={user[0]}, username={user[4]}, "
                        f"email={user[1]}, first_name={user[2]}, "
                        f"last_name={user[3]}, 2fa_token={token}"
                    )
                    session["user_id"] = user[0]
                    session["username"] = user[4]
                    session["email"] = user[1]
                    session["first_name"] = user[2]
                    session["last_name"] = user[3]
                    session["2fa_token"] = token

                    # Before redirecting or rendering templates,
                    # print the session variables again to confirm their values
                    print(f"Session variables after setting: {session}")

                    # Redirect to the 2FA verification page
                    return render_template("/2FA/tfa-login-verification-.html")

                elif user[14] == "F":
                    print(f"2FA is not enabled. Token Not generated hence not stored.")
                    # After setting session variables
                    # 2FA is not enabled, proceed to the dashboard
                    # Store user data in the session

                    session["user_id"] = user[0]
                    print(
                        f"Setting session variables: "
                        f"user_id={user[0]}, username={user[4]}, "
                        f"email={user[1]}, first_name={user[2]}, last_name={user[3]}"
                    )

                    print(
                        f"user_id: {session['user_id']}, "
                        f"2fa_token: {session.get('2fa_token')}"
                    )

                    # 5th column in the table accounts
                    session["username"] = user[4]
                    # 2nd column in the table accounts
                    session["email"] = user[1]
                    # 3rd column in the table accounts
                    session["first_name"] = user[2]
                    # 4th column in the table accounts
                    session["last_name"] = user[3]
                    print(f"Session variables after setting: {session}")
                    flash("success: You logged in successfully.", "success")

                    # Redirect to the dashboard after successful login
                    return redirect(url_for("dashboard"))

            else:
                # if an account is not verified and user tries to log in.
                return render_template("/Info/Failure/account-not-verified-.html")
        else:
            #  Extend the login process if the username or password is incorrect.
            flash("Error: invalid username or password.", "error")

    # the GET request
    return render_template("/Auth/login-form-.html")


# WORK AS I NEED: VERSION: 2.0 Nov 14 Tuesday
@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    """
    Verify the two-factor authentication (2FA) code entered by the user.

    This route performs the following steps:
    1. Check if the user is logged in
    and has a 2FA token stored in the session.
    2. Retrieve the entered 2FA token from the form.
    3. Retrieve the stored 2FA token and its timestamp
    from the database based on the user ID.
    4. Print relevant information for debugging purposes.
    5. Verify if the entered token matches the stored token.
    6. Check if the token has expired or not.
    7. Update session variables after successful 2FA verification.
    8. Display appropriate flash messages and redirect the user accordingly.

    Returns:
    - Redirects the user to the login page
    with an error message if not logged in or missing 2FA token.

    - Redirects the user to the login page
    with an error message for an invalid id or expired token.

    - Redirects the user to the dashboard
    with a success message after successful 2FA verification.
    """
    print("Verifying 2FA...")  # Print "Verifying 2FA ..." for debugging
    # Print session variables for debugging
    print(f"Session variables: {session}")

    # Check if the user is logged in and has a 2FA token
    if "user_id" not in session or "2fa_token" not in session:
        flash("You need to be logged in to verify 2FA.", "error")
        return redirect(url_for("login"))

    # Retrieve user_id from the session
    user_id = session["user_id"]
    entered_token = request.form["verification_code"]

    # Retrieve stored token and timestamp from the database based on user_id
    # get_stored_2fa_token_and_timestamp: The function responsible
    stored_token, token_timestamp = get_stored_tfa_token_and_timestamp(user_id)

    # Print the entered token, stored token, and token timestamp for debugging
    print(f"Entered Token: {entered_token}")
    print(f"Stored Token: {stored_token}")
    print(f"Token Timestamp: {token_timestamp}")

    # Verify if the entered token matches the stored token
    if stored_token and entered_token == stored_token:
        # Check if the token has expired
        # (tfa token is valid in 2 minutes) that is: tfa token is invalid after 2 minutes
        current_timestamp = datetime.now()
        token_expiration_time = token_timestamp + timedelta(minutes=2)
        if current_timestamp <= token_expiration_time:
            # Clear the stored token from the session after successful verification
            del session["2fa_token"]

            # Query the database to get user information based on the username
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT * FROM accounts WHERE username = %s",
                        (session["username"],),
                    )
                    user = cursor.fetchone()

            # Set session variables after successful 2FA verification
            session["user_id"] = user[0]
            session["username"] = user[4]
            session["email"] = user[1]
            session["first_name"] = user[2]
            session["last_name"] = user[3]

            flash("success: " "Two-Factor Authentication verified.", "success")

            # after success tfa verification
            return redirect(url_for("dashboard"))
        else:
            flash(
                "Info: The 2FA verification code has expired. "
                "Please request a new one.",
                "error",
            )  # expired due to time.
            # Clear all user data from the session after an invalid token
            del session["user_id"]
            del session["username"]
            del session["email"]
            del session["first_name"]
            del session["last_name"]
            del session["2fa_token"]

            return redirect(
                url_for("login")
            )  # redirect to the login page to start again
    else:
        # the error occurred due to mismatch of the number,
        # indeed the token is still valid, but there is a mismatch of inputs
        flash("Error: Invalid verification code. " "Please try again.", "error")

        # Clear all user data from the session after an invalid token
        del session["user_id"]
        del session["username"]
        del session["email"]
        del session["first_name"]
        del session["last_name"]
        del session["2fa_token"]

        # redirect tho the login page to start again.
        return redirect(url_for("login"))


# WORK AS I NEED: VERSION 2.0 14 Nov Tuesday.
def format_registration_date(registration_date):
    """
    Format the registration date into a human-readable string.

    This function takes a registration_date object and formats it into a string
    like "Wednesday, November 1st 2023". It extracts the month name, day with suffix
    (1st, 2nd, 3rd, etc.), full day name, and year.

    Args:
        registration_date (datetime.date): The date of registration.

    Returns:
        str: A formatted string representing the registration date.
    """

    # Extract the full month name
    month_name = registration_date.strftime("%B")

    # Extract the day with suffix (1st, 2nd, 3rd, etc.)
    day_with_suffix = registration_date.strftime("%d").lstrip("0").replace("0", "")

    # Extract the full day name
    day_name = registration_date.strftime("%A")

    # Extract the year
    year = registration_date.strftime("%Y")

    # Combine the extracted components into a formatted date string
    formatted_date = f" {day_name}, {month_name} {day_with_suffix} {year}"

    # Print the formatted date for debugging
    print("Formatted Date inside format_registration_date function:", formatted_date)

    # Return the formatted date string
    return formatted_date


# Register the format_registration_date function as a Jinja filter
app.jinja_env.filters["format_registration_date"] = format_registration_date


def login_required(view):
    """
    Decorator to ensure that the user is logged in.

    Redirects to the login page if the user is not logged in.

    Args:
        view (function): The view function to decorate.

    Returns:
        function: The decorated view function.
    """

    @wraps(view)
    def wrapped_view(*args, **kwargs):
        # Check if 'user_id' is not in the session
        if "user_id" not in session:
            # Flash an error message and redirect to the login page
            flash("You need to login first.", "error")
            return redirect(url_for("login"))
        # If the user is logged in, proceed to the original view function
        return view(*args, **kwargs)

    return wrapped_view


# AM NOT SURE HERE! SORRY: version 2.0 Nov 14 Tuesday
# I did not see the changes that I made here!!!
@app.route("/dashboard")
@login_required
def dashboard():
    """
    Render the user's dashboard with relevant information.

    The route checks if a user is logged in and
    user_id is in session, fetches their user data,
    including username and profile picture and, from the database.

    It then prints the logged-in user's username,
    and renders the dashboard template of a logged-in user.

    User cannot access the dashboard page if they cannot log in.
    if the user is in the dashboard and their session time, expires, they are redirected
    back to the login page with a message to log in to access the dashboard page.

    Returns:
        str: Rendered HTML template for the user's dashboard or a redirection response.
    """

    # Get the user_id from the session
    user_id = session["user_id"]

    # Fetch user data from the database based on user_id
    cursor = conn.cursor()
    cursor.execute(
        "SELECT profile_picture, username, role " "FROM accounts WHERE id = %s",
        (user_id,),
    )
    user = cursor.fetchone()
    cursor.close()

    # Extract user data
    username = user[1]
    role = user[2]
    profile_picture_filename = user[0] or "default_profile_picture.jpg"
    profile_picture_url = url_for(
        "uploaded_file", filename=profile_picture_filename)

    # Print information for debugging
    print(
        f"Logged-in user is {username}: {username.title()} Your Role is {role}")
    print(f"Logged-in User's Username: {username}")

    # Pass user information to the dashboard template
    return render_template(
        "/Accounts/dashboard-.html",
        profile_picture=profile_picture_url,
        username=username,
        role=role,
        user=user,
        user_id=user_id,
    )


# AM NOT SURE HERE! SORRY: version 2.0 Nov 14 Tuesday
# I did not see the changes that I made here!!!
@app.route("/logout")
@login_required
def logout():
    """
    Handle user logout functionality.

    This route retrieves user data from the session before removing it.
    It prints (or logs) the user data for auditing purposes and then clears
    the user data from the session. Finally, it flashes a message to inform the user
    about the successful logout and redirects them to the index page.

    Returns:
        flask.Response: A redirection response to the index page.
    """

    # Set the logout flag in the session
    session["logout_flag"] = True

    # Retrieve user data before removing it from the session
    user_id = session.get("user_id")
    username = session.get("username")
    email = session.get("email")
    first_name = session.get("first_name")
    last_name = session.get("last_name")

    # Remove the user data from the session
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("email", None)
    session.pop("first_name", None)
    session.pop("last_name", None)

    # Clear all user data from the session after an
    # invalid token entered during 2FA authentication
    # del session["user_id"]
    # del session["username"]
    # del session["email"]
    # del session["first_name"]
    # del session["last_name"]

    # Print the user data (or log it) before redirecting
    print(f"User ID: {user_id}")
    print(f"Username: {username}")
    print(f"Email: {email}")
    print(f"First Name: {first_name}")
    print(f"Last Name: {last_name}")

    flash("Info: You have been logged out.", "info")
    return redirect(url_for("index"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/profile", methods=["GET"])
def profile():
    """
    Render user profiles based on the provided user_id or the logged-in user's information.

    This route checks if a user is logged in,
    retrieves the user_id from the query parameters,
    and fetches non-sensitive user data from the database
    example non-sensitive data (username, date registered, profile_picture).

    If the user is not found in the database or not logged in,
     it flashes an error message and redirects to the login page.

    Returns:
        str: Rendered HTML template for the user's profile or a redirection response.
    """

    # Check if the user is logged in
    if "user_id" in session:
        logged_in_user_id = session["user_id"]
        # Get user_id from query parameters or use logged-in user's id
        user_id = request.args.get("user_id", type=int)

        if user_id is None:
            user_id = logged_in_user_id

        # Connect to the database
        cursor = conn.cursor()
        # Fetch user data from the database based on user_id
        cursor.execute(
            "SELECT username, profile_picture, registration_date "
            "FROM accounts WHERE id = %s",
            (user_id,),
        )
        user = cursor.fetchone()
        cursor.close()

        # Check if the user was found in the database
        if user:
            username = bleach.clean(user[0])
            registration_date = user[2]
            # Get profile picture information
            profile_picture_filename = user[1] or "default_profile_image.png"
            profile_picture_url = url_for(
                "uploaded_file", filename=profile_picture_filename
            )

            # Render the user's profile template with the fetched data
            return render_template(
                "/Accounts/profile-.html",
                username=username,
                registration_date=registration_date,
                profile_picture=profile_picture_url,
            )
        else:
            # If user not found, flash an error and redirect to log in
            flash("Error: User not found.", "error")
            return redirect(url_for("login"))

    else:
        # If not logged in, flash an error and redirect to log in
        flash("Error: login first to access this page.", "error")
        return redirect(url_for("login"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    """
    Handle user profile editing functionality.

    This route allows logged-in users to edit their profile information.

    If the request method is POST, it updates the user's information
    like first name and last name based on data included during the form submission.

    It then commits the changes to the database and redirects the user
    to the account page with a success message. If the request method is GET,
    it fetches the user's data from the database and renders the edit profile form
    with pre-filled data.

    Returns:
        flask.Response: A rendered template or a redirection response.
    """

    # Check if the user is logged in
    if "user_id" in session:
        # Get the user_id from the session
        user_id = session["user_id"]
        # Create a cursor to interact with the database
        cursor = conn.cursor()

        # Check if the form is submitted using the POST method
        if request.method == "POST":
            # Get updated profile information from the form
            first_name = request.form["first_name"].title()
            last_name = request.form["last_name"].title()
            new_username = request.form.get("username")

            # Clean the input data to prevent potential security issues
            first_name = bleach.clean(first_name)
            last_name = bleach.clean(last_name)
            new_username = bleach.clean(new_username)

            # Check if the new username is unique
            cursor.execute(
                "SELECT id FROM accounts WHERE username = %s AND id != %s",
                (new_username, user_id),
            )
            existing_user = cursor.fetchone()

            # Check if the new username is unique
            if existing_user:
                flash(
                    "Error: Username already in use. Please choose a different one.",
                    "error",
                )
                return redirect(url_for("edit_profile"))

            # Update the user's information in the database
            if new_username:
                cursor.execute(
                    "UPDATE accounts " "SET username = %s WHERE id = %s",
                    (new_username, user_id),
                )

            # Check which fields are included in the
            # form submission and update only those fields
            if first_name:
                cursor.execute(
                    "UPDATE accounts " "SET first_name = %s WHERE id = %s",
                    (first_name, user_id),
                )
            if last_name:
                cursor.execute(
                    "UPDATE accounts " "SET last_name = %s WHERE id = %s",
                    (last_name, user_id),
                )

            # Commit the transaction to save changes to the database
            conn.commit()

            # Flash a success message and redirect to the account route
            flash("Success: Profile updated successfully", "success")
            return redirect(url_for("account"))

        # Fetch user data from the database
        cursor.execute(
            "SELECT id, email, first_name, last_name " "FROM accounts WHERE id = %s",
            (user_id,),
        )
        user = cursor.fetchone()
        cursor.close()

        # Check if the user is found in the database
        if user:
            # Pass user data to the edit profile form
            return render_template(
                "/Accounts/edit-profile-form-.html", user=user)
        else:
            # Flash an error if the user is not found
            flash("Error: User not found.", "error")
            # Render a template indicating that the user is not found
            return render_template("/General/user-not-found-.html")
    else:
        # Flash an error if the user is not logged in
        flash("Log in first to access this page!", "error")
        # Redirect to the login page
        return redirect(url_for("login"))


# WORK AS I NEED: version 2.0 Nov 14 Tuesday
@app.route("/resend_verification", methods=["GET", "POST"])
def resend_verification():
    """
    Handle the resend verification email functionality.

    This route allows users to request a new
    verification email in case the initial email was not received or expired.

    If the provided email exists in the database and is
    associated with a non-verified account, a new verification token is generated.

    This token is then stored in the 'tokens' table,
    and an email containing the new verification token is sent to the user.

    If the email is already verified, a flash message is displayed to inform the user
    that their email address is already verified, and they should log in.
    If the email is not found in the records, a flash message is also displayed,
    informing the user that there is no account associated with the provided email address.

    Args:
        (None)

    Returns:
        str: A rendered template or a redirection response.
    """
    # Check if the request method is POST
    if request.method == "POST":
        # Get the email from the form
        email = request.form["email"]

        # Sanitize user input: email
        email = bleach.clean(email)

        # Create a cursor to interact with the database
        cursor = conn.cursor()

        # Execute a query to check if the email exists in the database
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()

        # Check if the user exists
        if user:
            # Check if the user is already verified (user_verified is the 13th column in table accounts)
            if user[12]:
                # If already verified, flash a message and redirect to the login page
                flash("Info: Already verified, Log in Please!.")
                return redirect(url_for("login"))
            else:
                # Generate a new verification token and update the verification_sent_time
                verification_token = "".join(
                    random.choices(string.ascii_letters + string.digits, k=32)
                )
                verification_sent_time = datetime.now()
                cursor.execute(
                    "UPDATE tokens "
                    "SET verification_token = %s, "
                    "verification_sent_time = %s WHERE id = %s",
                    (verification_token, verification_sent_time, user[0]),
                )

                # Commit the transaction to save changes to the database
                conn.commit()

                # Send the new verification email
                email_message = Message("Email Verification", recipients=[email])
                server_address = "http://localhost:5000"
                email_message.body = (
                    f"Click the following link to verify your email: "
                    f"{server_address}/verify/"
                    f"{verification_token}"
                )
                mail.send(email_message)

                # Close the database connection
                cursor.close()

                # Inform the user to check the new email in their inbox for a new link
                return render_template("/General/Info/new-verification-link-sent-.html")
        else:
            # If the email is not found in the records, render a template with a failure message
            cursor.close()
            return render_template("/General/Info/Failure/email-not-found-.html")

    # Handle GET request, render the resend verification form
    return render_template("/Auth/resend-verification-form-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    """
    Handle the password reset functionality.

    This route allows users to request a password reset.
    Users must provide their registered email address in our records.

    If the provided email is associated with a verified account,
    a random token is generated for password reset for that email address.

    The token, along with the username,
    email, and expiration time, is stored in the 'tokens' table for verification.

    A password reset link is sent to the user's email address with the generated token.

    Users are instructed to click the link to reset their password.
    The link is valid for 10 minutes.

    Returns:
        str: A rendered template or a redirection response.
    """
    # Check if the request method is POST
    if request.method == "POST":
        # Get the email from the form
        email = request.form["email"]

        # Sanitize user input: email
        email = bleach.clean(email)

        # Create a cursor to interact with the database
        cursor = conn.cursor()

        # Execute a query to check if the email exists in the database
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()

        # Check if the user exists
        if user:
            # Check if the account is not verified
            if not user[12]:  # Verified column is the 13th column in the table accounts
                # Account is not verified, display an error message
                flash(
                    "Error: Account is not verified. "
                    "Verify your account to reset your password.",
                    "error",
                )
                # Redirect to the resend_verification route
                return redirect(url_for("resend_verification"))

            # Generate a random token for password reset
            reset_password_token = "".join(
                random.choices(string.ascii_letters + string.digits, k=32)
            )

            # Get the username associated with the account
            # Username is the 5th column in the table accounts
            username = user[4]

            # Store the reset token, username,
            # email, security pin, and expiration time in the table tokens
            # Set expiration time to 10 minutes from now
            expiration_time = datetime.now() + timedelta(minutes=10)
            cursor.execute(
                "INSERT INTO tokens "
                "(account_id, username, email, reset_password_token, "
                "reset_password_token_expiration) VALUES (%s, %s, %s, %s, %s)",
                (user[0], username, email,
                 reset_password_token, expiration_time),
            )
            # Commit the transaction to save changes to the database
            conn.commit()
            # Close the database connection
            cursor.close()

            # Send an email with the password reset link
            reset_link = f"http://localhost:5000/reset_password/{reset_password_token}"

            email_message = Message("Password Reset", recipients=[email])
            email_message.html = (
                f"Dear User,\n\n"
                f"<p>We received a request to reset your password associated with the AuthFlaskApp account.</p>"
                f"<p> If you initiated this request, please click the link below to reset your password:\n\n"
                f"<p style: font-size 20px><a href='{reset_link}'>{reset_link}</a>\n\n"
                f"<p>If you did not request a password reset, please ignore this email. "
                f"Ensure your account security by not sharing this link with anyone. not even supporter team</p>\n\n"
                f"Best regards,\n\n"
                f"\n\nThe AuthFlaskApp Support Team"
            )

            mail.send(email_message)

            # Inform the user that the password reset link will be generated
            # The user is required to check their social and spam folders for a notification
            # email with the password reset link, which is valid only for 10 minutes
            return render_template("/Auth/reset-password-processing-.html")

        else:
            # Inform the user that the password link will be generated
            # The user is required to check their social and spam folders for a notification
            # email with the password reset link, which is valid only for 10 minutes
            return render_template("/Auth/reset-password-processing-.html")

    # Handle GET request, render the reset password request form
    return render_template("/Auth/reset-password-request-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    """
    Handle password reset using a unique token.

    This route is accessed through a link sent to the user's email for password reset.
    The link contains a unique token. If the token is valid and not expired, the user
    is allowed to reset their password. The new password is hashed and updated in the
    database. The token is cleared after a successful password reset.

    Args:
        token (str): The unique token for password reset.

    Returns:
        str: A rendered template for password reset or expiration message.

    Raises:
        HTTPException: If the token is invalid or expired.
    """
    # Create a cursor to interact with the database
    cursor = conn.cursor()

    # Execute a query to check if the token is valid and not expired
    cursor.execute(
        "SELECT * "
        "FROM tokens WHERE reset_password_token = %s "
        "AND reset_password_token_expiration > %s",
        (token, datetime.now()),
    )
    token_data = cursor.fetchone()

    # Check if the token is valid
    if token_data:
        # Get data from the token
        # account_id is the 2nd column of the table tokens
        account_id = token_data[1]
        # email is the 4th column of the table tokens
        email = token_data[3]

        # Check if the request method is POST (form submission)
        if request.method == "POST":
            # Get the new password from the form
            new_password = request.form["password"]

            # Check if the new password is strong
            if not is_strong_password(new_password):
                flash(
                    "Error: The password must be at least eight characters long "
                    "and contain at least one numeric character or one special character.",
                    "error",
                )
                return render_template("/Auth/reset-password-.html")

            # Hash the new password using: method='pbkdf2: sha256', salt_length=8
            hashed_password = generate_password_hash(
                new_password, method="pbkdf2:sha256", salt_length=8
            )

            # Update the user's password in table accounts and clear the reset token
            cursor.execute(
                "UPDATE accounts " "SET password = %s WHERE id = %s",
                (hashed_password, account_id),
            )

            cursor.execute(
                "DELETE FROM tokens " "WHERE reset_password_token = %s", (
                    token,)
            )

            # Commit the transaction to save changes to the database
            conn.commit()

            # Close the database connection
            cursor.close()

            # Email to inform the user that the password has been reset
            email_message = Message(
                "Password Reset Successful", recipients=[email])
            email_message.html = (
                f"Hello!,\n\n"
                f"<p> We would like to inform you that your password has been successfully reset.</p>\n\n"
                f"<p>If you did not initiate this action, please "
                f"reach out to our support team by visiting our "
                f"<a href='http://localhost:5000/Intuitivers/contact.html'> Contact Us page</a></p>."
                f"<p>Best regards</p>\n\n"
                f"<p>The AuthFlaskApp Support Team</p>"

            )
            mail.send(email_message)

            # Flash a success message and redirect to the login page
            flash(
                "Success: Password successfully reset. "
                "You can now log in with your new password.",
                "success",
            )
            return redirect(url_for("login"))

        else:
            # If the request method is GET, render the reset password form
            return render_template("/Auth/reset-password-.html")

    else:
        # If the token is invalid or expired, flash an error message
        flash("Error: Reset password link has expired", "error")
        # Redirect to the reset_password route
        return redirect(url_for("reset_password"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def get_current_email(user_id):
    """
    Retrieve the current email address associated with the user ID from the database.

    :param user_id: User ID
    :return: Current email address or None if the user is not found
    """
    # Create a cursor to interact with the database
    cursor = conn.cursor()

    # Execute an SQL query to fetch the email address for the specified user_id
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))

    # Fetch the result of the query
    current_email = cursor.fetchone()

    # Close the cursor to release resources
    cursor.close()

    # Return the current email address or None if the user is not found
    return current_email[0] if current_email else None


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def email_exists(email):
    """
    Check if the given email address is already in use by another user in the database.

    :param email: Email address to check
    :return: True if the email address exists, False otherwise
    """
    # Create a cursor to interact with the database
    cursor = conn.cursor()

    # Execute an SQL query to check if the email address exists in the database
    cursor.execute("SELECT id FROM accounts WHERE email = %s", (email,))

    # Fetch the result of the query
    existing_user = cursor.fetchone()

    # Close the cursor to release resources
    cursor.close()

    # Return True if the email address exists, False otherwise
    return True if existing_user else False


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def send_email(recipient, subject, body):
    """
    Send an email with the specified subject and body to the given recipient.

    :param recipient: Email address of the recipient
    :param subject: Subject of the email
    :param body: Body of the email
    :return: True if the email is sent successfully, else render an error template
    """
    # Create a Message object with the specified subject, sender, and recipients
    msg = Message(subject, sender="intuitivers@example.com", recipients=[recipient])

    # Set the body of the email
    msg.body = body

    try:
        # Attempt to send the email
        mail.send(msg)

        # Return True if the email is sent successfully
        return True

    except Exception as e:
        # Handle email sending failure here (log the error)
        # print(f'Failed to send email: {e}')
        logging.error(f"Failed to send email: {e}")

        # If sending fails, render an error template with an error message
        error_message = (
            "Failed to send email. Please try again later or contact support."
        )
        return render_template("error.html", error_message=error_message)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/update_email", methods=["GET", "POST"])
def update_email():
    """
    Handle the functionality of updating a user's email address.

    This route allows logged-in users to change their email address.
    Users are required to provide their current email, the new email they
    want to use, and verification is done to ensure that the provided current
    email matches the email associated with the user's account and not otherwise.

    Additionally, it checks if the new email is already in use by another user.
    If the verification is successful and the new email is available, a verification
    email is sent to the new email address, and a notification email is sent to the old
    email address. The user is then redirected to a success page.

    Returns:
        str: A rendered template or a redirection response.
    """
    # Check if the user is logged in
    if "user_id" in session:
        # Check if the request method is POST (form submission)
        if request.method == "POST":
            # Retrieve the new email from the form
            new_email = request.form["new_email"]

            # Retrieve the username from the session
            username = session["username"]

            # Sanitize user input: email
            new_email = bleach.clean(new_email)

            # Get the current email associated with the user's account
            old_email = get_current_email(session["user_id"])

            # Verify that the provided current email matches the email associated with the user's account
            if request.form["old_email"] != old_email:
                flash(
                    "Error: The provided "
                    "current email does not match the email "
                    "associated with your account.",
                    "error",
                )
                return redirect(url_for("update_email"))

            # Check if the new email address is already in use by another user
            if email_exists(new_email):
                flash("Error: Email address is already in use.", "error")

                # Redirect to the update email form
                return redirect(url_for("update_email"))

            # Generate a new verification token
            verification_token = "".join(
                random.choices(string.ascii_letters + string.digits, k=32)
            )

            # Store the new email, verification token, and expiration time in the table tokens
            # The token is valid for 10 minutes from now (when the form was submitted)
            verification_sent_time = datetime.now()
            verification_token_expiration = verification_sent_time + timedelta(
                minutes=10
            )
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tokens "
                "(account_id, username, email, "
                "verification_token, verification_sent_time, "
                "verification_token_expiration) VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    session["user_id"],
                    session["username"],
                    new_email,
                    verification_token,
                    verification_sent_time,
                    verification_token_expiration,
                ),
            )

            # Commit the transaction to save the change in the database.
            conn.commit()
            cursor.close()

            # Send a verification email to the new email address
            verification_link = (
                f"http://localhost:5000/verify_new_email/" f"{verification_token}"
            )

            email_verification_body = (
                f"Hello {username},\n\n"
                f"A request has been made to update the "
                f"email address associated with your account. "
                f"If you made this request, please click the "
                f"following link to verify your new email "
                f"address: {verification_link}\n\n"
                f"If you did not initiate this change, "
                f"please ignore this email. Your account security "
                f"is important to us. For an extra layer of security,"
                f" we recommend changing your password immediately. "
                f"If you have any concerns or questions, please "
                f"contact our support team immediately."
            )

            email_verification_subject = "Verify Email Change Request."

            send_email(new_email, email_verification_subject,
                       email_verification_body)

            # Send a notification email to the old email address
            notification_body = (
                f"Hello, {username}\n\n"
                f"We received a request to change "
                f"your email address associated with your "
                f"AuthFlaskApp account. A verification token  "
                f"has been sent to a new email address that "
                f"requested this action.\n\n"
                f"If this was you, simply check your second email "
                f"that initiated the process. You should have received a "
                f"notification from AuthFlaskApp to verify that email in our "
                f"records.\n\n"
                f"If this wasn't you, quickly change your "
                f"password for security reasons. For further "
                f"assistance and if you have any questions, feel "
                f"free to contact our support team. We are here to "
                f"help you.\n\n"
                f"Best regards,\n"
                f"The AuthFlaskApp Team"
            )
            notification_subject = "Email Update Request."

            send_email(old_email, notification_subject, notification_body)

            # Flash a success message and redirect to the success page
            flash(
                "success: Verification email has been sent to your "
                "new email address. Check your inboxes for instructions.",
                "success",
            )
            return redirect(url_for("update_email_success"))

        # Handle GET request (render the update email form)
        return render_template("/Auth/update-email-form-.html")

    # If the user is not logged in, flash an error and redirect to the update_email_success route
    else:
        flash("You need to log in first.", "error")
        return redirect(url_for("update_email_success"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/update_email_success")
def update_email_success():
    # Flash an informational message and redirect to the login page
    flash("Info: Verify your new email address, then come back", "info")
    return redirect(url_for("login"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/verify_new_email/<token>", methods=["GET"])
def verify_new_email(token):
    """
    Handle the verification of a new email address.

    Parameters:
    - token (str): The verification token received via email.

    Returns:
    - Redirects the user to the appropriate page based on the verification result.

    This route verifies the new email address by
    checking the validity of the provided verification token.

    It performs the following steps:
    1. Retrieve token information from the database using the provided token.
    2. Check if the verification link has expired (valid for 30 minutes).
    3. If the link has expired, delete the token and
    prompt the user to request a new verification email.
    4. If the link is still valid, update the
    'user_verified' column in the 'accounts' table, marking the new
    email as verified. Also, delete the verification token from the 'tokens' table.
    5. Construct and send confirmation emails to both the new and old email addresses.
    6. Display a success message and redirect the user to the appropriate page.
    7. Handle potential errors such as database errors or issues with sending confirmation emails.

    Flash Messages:
    - 'Verification link has expired.
    Please request a new verification email.' (if the link has expired).

    - 'Your new email address has been
    verified successfully. Confirmation emails have been sent
    to both your old and new addresses.' (on successful verification).

    - 'Invalid verification link. Please
    request a new verification email.' (if the provided token is invalid).

    - 'Database error occurred.
    Please try again later or contact support.' (if a database error occurs).

    - 'Failed to send confirmation email.
    Please contact support.' (if an email sending error occurs).

    - 'An unexpected error occurred.
    Please try again later or contact support.' (for other unexpected errors).

    Redirects:
    - 'update_email_success': On successful email verification.
    - 'update_email': In case of errors or expired verification links.
    """
    # Connect to the database
    cursor = conn.cursor()

    # Retrieve token information from the database using the provided token
    cursor.execute(
        "SELECT * FROM tokens WHERE verification_token = %s", (token,))
    token_data = cursor.fetchone()

    if token_data:
        # Check if the verification link has expired (valid for 30 minutes)
        verification_sent_time = token_data[5]
        current_time = datetime.now()

        # Calculate the time difference in minutes
        time_difference = (
            current_time - verification_sent_time).total_seconds() / 60

        # If the link has expired, delete the token and prompt the user to request a new verification email
        if time_difference > 30:
            cursor.execute("DELETE FROM tokens WHERE id = %s", (token_data[0],))
            conn.commit()
            cursor.close()

            flash(
                "Error: Verification link has expired. "
                "Request a new verification email.",
                "error",
            )
            return redirect(url_for("update_email"))

        else:
            # Update the 'verified' column to mark
            # the user's new email as verified in the table accounts
            cursor.execute(
                "UPDATE accounts SET verified = TRUE, email = %s WHERE id = %s",
                (token_data[3], token_data[1]),
            )

            # Delete the verification token from the
            # table tokens after successful verification
            cursor.execute("DELETE FROM tokens WHERE id = %s", (token_data[0],))

            # Commit the transaction to save the changes in the database
            conn.commit()
            cursor.close()

            # Constructing the confirmation email body and subject
            confirmation_email_body = (
                "Dear user,\n\n"
                "We are pleased to inform you that your email "
                "address has been successfully updated in our system. "
                "This change has been processed and verified.\n\n"
                "If you did not initiate this change, please contact our "
                "support team immediately.\n\n"
                "Best regards,\n"
                "The AuthFlaskApp Team"
            )

            confirmation_email_subject = "Email Address Update Confirmation"

            try:
                # Send confirmation email to the new email address
                send_email(
                    token_data[3], confirmation_email_subject, confirmation_email_body
                )

                # Send notification email to the old email address
                notification_email_body = (
                    "Hello,\n\nYour email address associated with your AuthFlaskApp "
                    "account has been updated successfully. "
                    "If you did not make this change, please contact support immediately."
                )
                notification_email_subject = "Email Address Update Notification"

                # Print statements to see the old email address, notification email body, and subject
                print("Old Email Address:", token_data[2])
                print("Notification Email Body:", notification_email_body)
                print("Notification Email Subject:", notification_email_subject)

                send_email(
                    token_data[2], notification_email_subject, notification_email_body
                )

                flash(
                    "Info: Your new email address "
                    "has been verified successfully. Check your inboxes."
                    "success",
                )
                return redirect(url_for("update_email_success"))
            except psycopg2.Error as db_error:
                print("Database Error:", db_error)
                flash(
                    "Error: Database error occurred. "
                    "Please try again later or contact support.",
                    "error",
                )
                return redirect(url_for("update_email"))

            except smtplib.SMTPException as email_error:
                print("Email Sending Error:", email_error)
                flash(
                    "Error: Failed to send confirmation email. "
                    "Please contact support.",
                    "error",
                )
                return redirect(url_for("update_email"))

            except Exception as generic_error:
                print("Unexpected Error:", generic_error)
                flash(
                    "Error: An unexpected error occurred. "
                    "Please try again later or contact support.",
                    "error",
                )
                return redirect(url_for("update_email"))

    # If the token is invalid, flash an error and redirect to the update_email route
    print("Invalid verification link. Please request a new verification email.")
    flash(
        "Error: Invalid verification link. " "Please request a new verification email.",
        "error",
    )
    return redirect(url_for("update_email"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
# Function to check allowed file extensions
def allowed_file(filename):
    """
    Checks if the file has an allowed extension.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the file extension is allowed, False otherwise.
    """
    # Check if the filename has a dot and the extension is in ALLOWED_EXTENSIONS
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/upload_profile_picture", methods=["POST"])
def upload_profile_picture():
    """
    Handle the upload of a user's profile picture.

    This route is designed to handle POST requests for uploading a user's profile picture.
    It checks if the user is logged in, validates the uploaded file format,
    saves the file to the server's UPLOAD_FOLDER, and updates the 'profile_picture'
    column in the 'accounts' table with the file name. It then redirects the user to
    the dashboard page with a success message to inform them.

    Args:
        (Uses data from the POST request) None.

    Returns:
        flask.redirect: Redirects the user to the
        dashboard page after uploading the profile picture.
    """
    # Check if the user is logged in
    if "user_id" in session:
        user_id = session["user_id"]

        # Check if the 'profile_picture' key is in the request files
        if "profile_picture" in request.files:
            file = request.files["profile_picture"]

            # Check if the file is present and has an allowed format
            if file and allowed_file(file.filename):
                # Sanitize the filename using secure_filename
                filename = secure_filename(file.filename)

                # Save the file to the UPLOAD_FOLDER on the server
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

                # Save the file path to the user's profile picture in the database
                cursor = conn.cursor()
                # Update the 'profile_picture' column in
                # the 'accounts' table with the uploaded profile file
                cursor.execute(
                    "UPDATE accounts SET profile_picture = %s WHERE id = %s",
                    (filename, user_id),
                )
                conn.commit()
                cursor.close()

                # Flash a success message
                flash("success: " "Profile picture uploaded successfully.", "success")

            else:
                # Flash an error message for an invalid file format
                flash(
                    "Error: " "Invalid file format. " "Allowed formats: png, jpg, jpeg",
                    "error",
                )
        else:
            # Flash an error message for no file part
            flash("Error: No file part", "error")

        # Redirect to the dashboard page to see the image
        return redirect(url_for("dashboard"))

    else:
        # Flash an error message for not being logged in
        flash("Error: You need to log in first.", "error")

        # Redirect to the login page
        return redirect(url_for("login"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """
    Serve an uploaded file from the UPLOAD_FOLDER directory.

    This route is designed to serve files uploaded to the server.
    It retrieves the specified file by its filename and sends it to the client.

    Args:
        filename (str): The name of the file to be served.

    Returns:
        flask.Response: The file to be sent as a response.
    """
    # Serve the specified file from the UPLOAD_FOLDER directory
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/upload_profile_image")
def upload_profile_image():
    """
    Render the page for uploading a user's profile image.

    This route renders the 'upload_profile_image.html' template, allowing users to
    upload or change their profile images.

    Returns:
        flask.render_template: The rendered template for uploading profile images.
    """
    # Render the 'upload_profile_image.html' template
    return render_template("/Accounts/upload-profile-image-.html")


# FROM HERE, THE CODES WORK FINER AND IT DOES WHAT I SCHEDULED.
# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def send_password_change_email(email, username):
    """
    Send a confirmation email for a password change.

    Args:
        email (str): The recipient's email address.
        username (str): The recipient's username.

    Returns:
        None
    """
    # Sender's email address
    sender_email = "intuitivers@gmail.com"

    # Email subject
    subject = "Password Changed Confirmation"

    # Recipient's email address
    recipients = [email]

    # Message body for the password change confirmation email
    message_body = (
        f"Dear {username},\n\n"
        f"We wanted to inform you that your "
        f"password has been successfully changed. "
        f"This email serves as confirmation of the recent "
        f"update. If you authorized this change, you can disregard this message.\n\n"
        f"However, if you did not initiate this password change, it could indicate a "
        f"security concern. We urge you to immediately contact our support team for "
        f"further assistance. Your security is our top priority.\n\n"
        f"Thank you for your attention and cooperation.\n\n"
        f"Best regards,\n"
        f"The AuthFlaskApp Team"
    )

    # Create a Message object with the specified subject, sender, and recipients
    msg = Message(subject, sender=sender_email, recipients=recipients)

    # Set the body of the email
    msg.body = message_body

    # Send the email using the mail.send() method
    mail.send(msg)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Handle the change password functionality.

    This route allows users to change their password.
    Users must be logged in to access this feature.

    If the request method is POST, the function verifies
    the current password, checks if the new password meets
    the strength requirements, hashes the new password, updates
    it in the database, logs out the user from all sessions, sends an
    email notification to the user, and redirects them to the login page.

    If the request method is GET, it renders the change_password.html template.

    Returns:
        str: A rendered template or a redirection response.
    """
    # Check if the user is logged in
    if "user_id" in session:
        user_id = session["user_id"]
        username = session["username"]
        cursor = conn.cursor()

        # Check if the request method is POST
        if request.method == "POST":
            # Get the current and new passwords from the form
            current_password = request.form["current_password"]
            new_password = request.form["new_password"]

            # Sanitize user input: current_password and new_password
            current_password = bleach.clean(current_password)
            new_password = bleach.clean(new_password)

            # Fetch the current hashed password and user email from the database
            cursor.execute(
                "SELECT password, email " "FROM accounts WHERE id = %s", (
                    user_id,)
            )
            result = cursor.fetchone()
            stored_password, user_email = result[0], result[1]

            # Verify the current password provided by the user
            if check_password_hash(stored_password, current_password):
                # Check if the new password meets the strength requirements
                if is_strong_password(new_password):
                    # Hash the new password before updating it in the database
                    hashed_password = generate_password_hash(
                        new_password, method="pbkdf2:sha256", salt_length=8
                    )

                    # Update the user's password in the database
                    cursor.execute(
                        "UPDATE accounts " "SET password = %s WHERE id = %s",
                        (hashed_password, user_id),
                    )

                    # Clear all session data (log out user from all sessions)
                    session.clear()

                    # Commit the transaction to save changes to the database
                    conn.commit()

                    # Send email notification to the user
                    send_password_change_email(user_email, username)

                    # Flash a success message
                    flash("success: " "Password changed successfully.", "success")

                    # Redirect back to the login page
                    return redirect(url_for("login"))
                else:
                    # Flash an error message for weak password
                    flash(
                        "Error: "
                        "Password must be at least 8 "
                        "characters long and contain at least "
                        "one space and one alphanumeric character.",
                        "error",
                    )
            else:
                # Flash an error message for incorrect current password
                flash(
                    "Error: " "Incorrect current password. Please try again.", "error"
                )

        # Render the change password template for GET requests
        return render_template("/Auth/change-password-.html")
    else:
        # Flash an error message for users not logged in
        flash(
            "Error: You are not logged in. " "Please log in to change your password.",
            "error",
        )

        # Redirect to the login page
        return redirect(url_for("login"))


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/settings", methods=["GET", "POST"])
def settings():
    """
    Renders the settings page.

    If the user is not logged in, redirects to the login page and displays an error message.
    """
    # Check if the user is not logged in
    if "user_id" not in session:
        # Flash an error message and redirect to the login page
        flash(
            "Error: You need to be logged in " "to access the settings page.", "error"
        )
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session["username"]
    print(
        f"User ID: {user_id} | Username: {username} accessing settings page.")

    # Rendering the settings page
    return render_template("Accounts/settings-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/account", methods=["GET", "POST"])
def account():
    """
    Renders the account page.

    If the user is not logged in, redirects to the login page and displays an error message.
    """
    # Check if the user is not logged in
    if "user_id" not in session:
        # Flash an error message and redirect to the login page
        flash("Error: You need to be logged in " "to access the account page.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session["username"]
    print(f"User ID: {user_id} | Username: {username} accessing account page.")

    # Rendering the account page
    return render_template("/Accounts/account-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/privacy")
def privacy():
    """
    Renders the privacy page.

    If the user is not logged in, redirects to the login page and displays an error message.
    """
    # Check if the user is not logged in
    if "user_id" not in session:
        # Flash an error message and redirect to the login page
        flash("Error: You need to be logged in " "to access the privacy page.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session["username"]
    print(f"User ID: {user_id} | Username: {username} accessing privacy page.")

    # Rendering the privacy page
    return render_template("/Accounts/privacy-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def update_tfa_status(email, status):
    """
    Updates the Two-Factor Authentication
    (2FA) status for the specified user in the database.

    Args:
        email (str): The user's email address.
        status (str): The new 2FA status ('T' for enabled, 'F' for disabled).

    Returns:
        None
    """
    # Get a connection to the database
    conn = get_db_connection()
    with conn.cursor() as cursor:
        # Update the 'tfa' column in 'accounts' table with the new status
        cursor.execute(
            "UPDATE accounts " "SET tfa = %s WHERE email = %s", (status, email)
        )

    # Commit the transaction to save changes in the database.
    conn.commit()
    conn.close()


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def check_tfa_status(email):
    """
    Retrieves the Two-Factor Authentication
    (2FA) status, user ID, and username for the specified email address.

    Args:
        email (str): The user's email address.

    Returns:
        tuple: A tuple containing 2FA status
              ('T' for enabled, 'F' for disabled), user ID, and username.
              Returns (None, None, None) if the user is not found.
    """
    email = str(email)  # Ensure email is a string
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            # Retrieve 'tfa', 'id', and 'username' from 'accounts' table for the given email
            cursor.execute(
                "SELECT tfa, id, username " "FROM accounts WHERE email = %s", (
                    email,)
            )
            user_data = cursor.fetchone()

    # Return 2FA status, user ID, and username if user is found, otherwise return None
    if user_data:
        return (
            user_data[0],
            user_data[1],
            user_data[2],
        )  # 2FA status, user ID, and username
    return (
        None,
        None,
        None,
    )  # 2FA status, user ID, and username are None if user not found


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def send_activation_email(email, activation_status, username):
    """
    Sends an email notification to the user
    confirming the activation or deactivation of Two-Factor Authentication (2FA).

    Args:
        email (str): The recipient's email address.
        activation_status (str): The status of 2FA
        ('T' for activation, 'F' for deactivation).
        username (str): The username of the recipient.

    Returns:
        None
    """
    # Set the subject of the email
    subject = "2FA Activation"

    # Set the sender's email address
    sender_email = "intuitivers@gmail.com"

    # Set the recipient's email address
    recipient_email = [email]

    # Check the activation status to determine the email message content
    if activation_status == "T":
        # Message body for 2FA activation
        message_body = (
            f"Dear {username},\n\n"
            f"We received a request to activate "
            f"Two-Factor Authentication (2FA) for your account. "
            f"We're pleased to inform you that the activation process was successful.\n\n"
            f"Now, your account is safeguarded with an "
            f"additional layer of security. Whenever you log in, "
            f"you will be required to provide an additional verification code, "
            f"enhancing the protection of your account information and you in general.\n\n"
            f"Thank you for choosing our service and "
            f"we prioritizing your account's security. "
            f"If you have any questions or concerns, please "
            f"do not hesitate to contact us in our support team\n\n"
            f"Best regards,\n"
            f"The AuthFlaskApp Team"
        )
    else:
        # Message body for 2FA deactivation
        message_body = (
            f"Dear {username},\n\n"
            f"We received a request to deactivate "
            f"Two-Factor Authentication (2FA) for your account. "
            f"We're confirming that 2FA has been successfully deactivated.\n\n"
            f"Your account no longer requires an additional verification code during login. "
            f"If you have any questions or concerns, please do not hesitate to contact us.\n\n"
            f"Thank you for choosing our service.\n\n"
            f"Best regards,\n"
            f"The AuthFlaskApp Team"
        )

    # Create a Message object with the specified subject, sender, and recipients
    msg = Message(subject, sender=sender_email, recipients=recipient_email)

    # Set the body of the email
    msg.body = message_body

    # Send the email using the mail object
    mail.send(msg)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/activate_2fa", methods=["GET", "POST"])
def activate_2fa():
    """
    Handles the activation and deactivation of
    Two-Factor Authentication (2FA) for the user's account.

    If the user is not logged in,
    redirects them to the login page.
    On POST request, processes the form data,
    validates the input, and updates 2FA status accordingly.

    Displays appropriate flash messages based on the input and current 2FA status.

    Returns:
        str: Redirects the user to the activate_2fa.html template on GET request.
    """
    # Check if the user is not logged in
    if "user_id" not in session:
        flash("Error: You need to be logged in to manage 2FA.", "error")
        return redirect(url_for("login"))

    # Get user information from the session
    user_id = session["user_id"]
    stored_email = session["email"]  # Get stored email from the session
    username = session["username"]

    # Retrieve the current 2FA status from the database
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT tfa FROM accounts WHERE id = %s", (user_id,))
            current_2fa_status = cursor.fetchone()[0]

    # Print user information for debugging purposes
    print(f"Logged-in user ID: {user_id}")
    print(f"Logged-in username: {username}")
    print(f"Stored email address: {stored_email}")

    # Check if the form was submitted (POST request)
    if request.method == "POST":
        # Get entered email and user input from the form
        entered_email = request.form["email"]
        entered_email = str(entered_email)  # Ensure entered_email is a string
        user_input = request.form["user_input"].lower()

        # Sanitize user input: email
        entered_email = bleach.clean(entered_email)

        # Print the entered email address for 2FA activation
        print(f"Entered email address: {entered_email}")

        # Check if the entered email matches the stored email and if the entered input is valid
        if entered_email == stored_email:
            # Check user input and current 2FA status to determine the action
            if user_input == "deactivate" and current_2fa_status == "T":
                # Deactivate 2FA and notify the user
                send_activation_email(stored_email, "F", username)
                update_tfa_status(stored_email, "F")

                flash("success: "
                      "2FA has been deactivated successfully.", "success")
                return redirect(url_for('settings'))

            elif user_input == "deactivate" and current_2fa_status == "F":
                # Display an error message if 2FA is not activated
                flash(
                    "Error: " "2FA is not activated yet so cannot deactivate.",
                    "success",
                )

            elif user_input == "activate" and current_2fa_status == "T":
                # Display a message if 2FA is already activated
                flash(
                    "Info: "
                    "your account is already activated. Enter "
                    "'deactivate' to deactivate it.",
                    "success",
                )
                return redirect(url_for('settings'))

            elif user_input == "activate" and current_2fa_status == "F":
                # Activate 2FA, notify the user, and display a success message
                update_tfa_status(stored_email, "T")
                send_activation_email(stored_email, "T", username)
                flash(
                    "success: "
                    "2FA has been activated successfully. "
                    "Check your email.",
                    "success",
                )
                return redirect(url_for('settings'))
            else:
                # Display an error message for invalid input or 2FA status
                flash(
                    "Error: " "Invalid input or 2FA status. " "Please try again.",
                    "error",
                )
        else:
            # Display an error message if the user is not associated with the entered email
            flash("Error: You are not associated with that email!", "error")

        return redirect(url_for("activate_2fa"))

    # Render the template for 2FA activation with the current 2FA status
    return render_template(
        "/2FA/activate-tfa-.html", current_2fa_status=current_2fa_status
    )


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def is_valid_email(email):
    """
    Check if the given email address is valid and exists in the database.

    Args:
        email (str): The email address to be validated.

    Returns:
        bool: True if the email exists in the database, else False.
    """
    try:
        # Establish a database connection
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Execute SQL query to count occurrences of the email in the 'accounts' table
                cursor.execute(
                    "SELECT COUNT(*) " "FROM accounts WHERE email = %s", (email,)
                )
                # Retrieve the count from the query result
                count = cursor.fetchone()[0]
        # Return True if email exists in the database, else False
        return count > 0
    except Exception as e:
        # Print an error message if an exception occurs during validation
        print(f"Error validating email: {e}")
        return False


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def is_valid_username(username):
    """
    Check if the given username is valid and exists in the database.

    Args:
        username (str): The username to be validated.

    Returns:
        bool: True if the username exists in the database, else False.
    """
    try:
        # Establish a database connection
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Execute SQL query to count occurrences of the username in the 'accounts' table
                cursor.execute(
                    "SELECT COUNT(*) "
                    "FROM accounts WHERE username = %s", (username,)
                )
                # Retrieve the count from the query result
                count = cursor.fetchone()[0]
        # Return True if username exists in the database, else False
        return count > 0
    except Exception as e:
        # Print an error message if an exception occurs during validation
        print(f"Error validating username: {e}")
        return False


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def is_valid_password(email, password):
    """
    Validate the provided password for the given email address.

    Args:
        email (str): The email address associated with the account.
        password (str): The password to be validated.

    Returns:
        bool: True if the provided password matches the stored password, else False.
    """
    try:
        # Establish a database connection
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Execute SQL query to retrieve the stored password for the given email
                cursor.execute(
                    "SELECT password FROM accounts " "WHERE email = %s", (
                        email,)
                )
                # Fetch the stored password from the query result
                stored_password = cursor.fetchone()

        # Return True if the provided password matches the stored password, else False
        return stored_password and check_password_hash(stored_password[0], password)
    except Exception as e:
        # Print an error message if an exception occurs during validation
        print(f"Error validating password: {e}")
        return False

# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def is_valid_security_pin(email, security_pin):
    """
    Validate the provided security pin for the given email address.

    Args:
        email (str): The email address associated with the account.
        security_pin (str): The security pin to be validated.

    Returns:
        bool: True if the provided security pin matches the stored security pin, else False.
    """
    try:
        # Establish a database connection
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Execute SQL query to retrieve the stored security pin for the given email
                cursor.execute(
                    "SELECT pin " "FROM accounts WHERE email = %s", (email,))
                # Fetch the stored security pin from the query result
                stored_security_pin = cursor.fetchone()
        # Return True if the provided security pin matches the stored security pin, else False
        return stored_security_pin and stored_security_pin[0] == security_pin
    except Exception as e:
        # Print an error message if an exception occurs during validation
        print(f"Error validating security pin: {e}")
        return False


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
# Function to send an account deletion confirmation email to non-2FA users
def send_account_deletion_confirmation_non_tfa_email(email, username):
    """
    Send an account deletion confirmation email to non-2FA users.

    This function constructs and sends an
    email confirming the successful deletion of the user's
    account for users who do not have Two-Factor Authentication
    (2FA) enabled. The email includes a personalized greeting
    using the user's username.

    Args:
        email (str): The recipient's email address.
        username (str): The username of the user whose account is being deleted.

    Returns:
        None
    """
    sender_email = "intuitivers@gmail.com"
    subject = "Account Deletion Confirmation"
    recipients = [email]

    message_body = (
        f"Hello {username},\n\n"
        f"We want to inform you that your "
        f"account has been successfully deleted. "
        f"You are receiving this email to confirm the deletion "
        f"of your account. If you wish to create a new account, "
        f"you can use this email address ({email}) to register again. \n\n"
        f"Thank you for being with us. If you need further assistance, "
        f"please don't hesitate to contact our support team.\n\n"
        f"Best regards,\n"
        f"The AuthFlaskApp Team"
    )

    msg = Message(subject, sender=sender_email, recipients=recipients)
    msg.body = message_body

    mail.send(msg)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/delete_account", methods=["GET", "POST"])
def delete_account():
    """
    Handle the account deletion functionality.

    This route allows users to delete their account.
    Users must be logged in to access this feature.
    If the user has Two-Factor Authentication (2FA),
    enabled, they are prompted to enter their email, username,
    password, and 2FA token for verification.

    If the verification is successful, the account is deleted.
    If 2FA is not enabled, the user's account is deleted directly
    after password, username, email and security pin verification.

    Returns:
        str: A rendered template or a redirection response.
    """
    if "user_id" not in session:
        # Redirect to login page if user is not logged in
        flash("Error: You need to be logged in to delete your account.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Fetch user data including 2FA status from the database
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT tfa, email, username, password, pin "
                "FROM accounts WHERE id = %s",
                (user_id,),
            )
            user_data = cursor.fetchone()

    current_tfa_status = user_data[0] if user_data else "F"
    stored_email = user_data[1] if user_data else ""
    stored_username = user_data[2] if user_data else ""
    stored_password = user_data[3] if user_data else ""
    stored_security_pin = user_data[4] if user_data else ""

    # Print logged-in user ID for debugging
    print(f"Logged-in User ID: {user_id}")
    # Print 2FA status for debugging
    print(f"2FA Status: {current_tfa_status}")
    print(f"Stored Email: {stored_email}")  # Print stored email for debugging
    # Print stored username for debugging
    print(f"Stored Username: {stored_username}")
    # Print stored password for debugging
    print(f"Stored Password: {stored_password}")

    # Print stored security pin for debugging
    print(f"Stored Security Pin: {stored_security_pin}")

    if current_tfa_status == "T" and request.method == "POST":
        # Handling 2FA verification
        entered_email = request.form.get("email")
        entered_username = request.form.get("username")
        entered_password = request.form.get("password")
        entered_security_pin = request.form.get("security_pin")

        # Validate email, username, password, and security pin
        if (
                entered_email == stored_email
                and entered_username == stored_username
                and is_valid_password(entered_email, entered_password)
                and entered_security_pin == stored_security_pin
        ):
            # Generate and send 2FA token to user's email
            two_fa_token = generate_token()

            print(f"2FA Token: {two_fa_token}")  # Print 2FA token for debugging
            print(f"Username: {stored_username}")  # Print username for debugging
            print(f"Email: {stored_email}")  # Print email for debugging
            print(f"User ID: {user_id}")  # Print user ID for debugging

            # Send 2FA token to user's email address
            send_tfa_token_email(
                stored_email,
                f"Your 2FA token for account deletion is: {two_fa_token}",
                stored_username,
            )

            # Store the token in the session for verification
            session["verification_token"] = two_fa_token

            return render_template("/2FA/tfa-deletion-verification-.html")

        else:
            # Display error messages for invalid input
            if entered_username != stored_username:
                flash("Error: Invalid username!.", "error")
            elif entered_email != stored_email:
                flash("Error:" " You are not associated with that email", "error")
            elif entered_password != stored_password:
                flash("Error: Invalid Password", "error")
            elif entered_security_pin != stored_security_pin:
                flash("Error: Does that PIN belongs to You!.", "error")
            return redirect(url_for("delete_account"))

    elif current_tfa_status == "F" and request.method == "POST":
        # Handling account deletion for non-2FA users
        entered_email = request.form.get("email")
        entered_username = request.form.get("username")
        entered_password = request.form.get("password")
        entered_security_pin = request.form.get("security_pin")

        # Validate email, username, password, and security pin
        if (
                entered_email == stored_email
                and entered_username == stored_username
                and is_valid_password(entered_email, entered_password)
                and entered_security_pin == stored_security_pin
        ):
            # Store user data in the deleted_accounts table
            deletion_reason = request.form.get("deletion_reason")
            deletion_date = date.today()

            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Copy user data to deleted_accounts table
                    cursor.execute(
                        "INSERT INTO deleted_accounts "
                        "(email, first_name, last_name, country, day, "
                        "month, year, deleted_date, deletion_reason) "
                        "SELECT email, first_name, last_name, "
                        "country, day, month, year, %s, %s FROM accounts WHERE id = %s",
                        (deletion_date, deletion_reason, user_id),
                    )

                    # Delete the account since 2FA is not enabled
                    # and user credentials are correct
                    cursor.execute(
                        "DELETE FROM accounts " "WHERE id = %s", (user_id,))
                    conn.commit()

                    # Send confirmation email to non-2FA user
                    send_account_deletion_confirmation_non_tfa_email(
                        stored_email, stored_username
                    )

            session.clear()

            # Display a success message and render success template
            flash("Your account has been deleted successfully.", "success")
            return render_template(
                "/General/Info/Success/account-deleted-success-.html"
            )
        else:
            # Display error message for invalid input
            flash(
                "Error: Invalid email, username, password, or security pin. "
                "Please try again.",
                "error",
            )
            return redirect(url_for("delete_account"))

    # Render the account deletion confirmation template
    return render_template("/Auth/confirm-delete-account-.html")


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def send_tfa_deletion_token_email(email, token, username):
    """
    Send a Two-Factor Authentication
    (2FA) deletion verification token email to the user.

    This function constructs and sends an
    email containing a 2FA token for account deletion verification.

    Args:
        email (str): The recipient's email address.
        token (str): The generated 2FA token for account deletion verification.

    Returns:
        None
        :param email:
        :param username:
    """
    print(
        f"Sending token: {token} to email: {email} who is {username}"
    )  # Print the token and email for debugging
    msg = Message(
        "2FA Deletion Account Verification",
        sender="intuitivers@gmail.com",
        recipients=[email],
    )

    msg.body = (
        f"Hello {username}!!,\n\n"
        f"We received a request to delete your account. "
        f"To confirm this action, please enter the following "
        f"verification token within the next 2 minutes: {token}.\n\n"
        f"Please enter this token to complete the deletion process. "
        f"If you did not make this request, please ignore this email.\n\n"
        f"For your security, if you did not initiate this "
        f"request, we recommend changing your password immediately "
        f"to prevent unauthorized access to your account.\n\n"
        f"Thank you for using our service!\n"
        f"Best regards,\n"
        f"The AuthFlaskApp Team"
    )
    mail.send(msg)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
def send_account_deletion_confirmation_email(email, username):
    """
    Send an account deletion confirmation email to the user.

    This function constructs and sends an email confirming the successful
    deletion of the user's account. The email includes a personalized greeting
    using the user's username.

    Args:
        email (str): The recipient's email address.
        username (str): The username of the user whose account is being deleted.

    Returns:
        None
    """
    # Sender's email address
    sender_email = "intuitivers@gmail.com"
    # Subject of the confirmation email
    subject = "Account Deletion Confirmation"
    # Recipient's email address
    recipients = [email]

    # Message body with personalized greeting and account deletion details
    message_body = (
        f"Hello {username},\n\n"
        f"We wanted to let you know that your account has been "
        f"successfully deleted. If you did not initiate this action or "
        f"have any concerns, please don't hesitate to reach out to our support "
        f"team immediately.\n\n We appreciate your time with us and thank you for "
        f"being a part of our community. If you ever decide to come back, we'll be "
        f"here to welcome you!\n\n"
        f"Best regards,\n\n"
        f"The AuthFlaskApp Team"
    )

    # Create a Message object with sender, recipients, subject, and body
    msg = Message(subject, sender=sender_email, recipients=recipients)
    msg.body = message_body

    # Send the email
    mail.send(msg)


# WORK AS I NEED: VERSION 2.0 Nov 14 Tuesday
@app.route("/verify_2fa_deletion", methods=["POST"])
def verify_tfa_deletion():
    """
    Handle the verification of
    Two-Factor Authentication (2FA) token for account deletion.

    This route validates the entered
    2FA token against the stored token in the user's session.
    If the tokens match, the user's account is deleted, a confirmation email
    is sent, and the user is redirected to the account_deleted_success.html template.
    If the tokens do not match, an error message is displayed, and the user is redirected
    to the delete_account route.

    Returns:
        str: A rendered template or a redirection response.
    """
    # Get the entered verification code from the form
    entered_token = request.form["verification_code"]
    # Get the stored verification token from the user's session
    stored_token = session.get("verification_token")

    if stored_token and entered_token == stored_token:
        # Token is valid, proceed with account deletion
        user_id = session["user_id"]
        user_email = session["email"]
        username = session["username"]

        # Store user data in the deleted_accounts table
        deletion_reason = request.form.get("deletion_reason")
        deletion_date = date.today()

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Copy user data to deleted_accounts table
                cursor.execute(
                    "INSERT INTO deleted_accounts "
                    "(email, first_name, last_name, country, day,"
                    " month, year, deleted_date, deletion_reason) "
                    "SELECT email, first_name, last_name, "
                    "country, day, month, year, %s, %s FROM accounts WHERE id = %s",
                    (deletion_date, deletion_reason, user_id),
                )

                # Delete the account since 2FA is not enabled and credentials are correct
                cursor.execute(
                    "DELETE FROM accounts WHERE id = %s", (user_id,))
                conn.commit()

        session.clear()

        # Send confirmation email to the user
        send_account_deletion_confirmation_email(user_email, username)

        # Display a success message and render success template
        flash("Your account has been deleted successfully.", "success")
        return render_template("/General/Info/Success/account-deleted-success-.html")
    else:
        # Display an error message for invalid verification code
        flash("Invalid verification code. Please try again.", "error")
        return redirect(url_for("delete_account"))


# CUSTOM ERROR PAGES AND ROUTES ARE WORKING FINE AS I NEED.
# Custom error handler for 400 Bad request Error
@app.errorhandler(400)
def bad_request(error):
    return render_template("ErrorHandler/ClientError/BadRequestError_400.html"), 400


# Custom error handler for 401 Unauthorized Error
@app.errorhandler(401)
def unauthorized(error):
    return render_template("ErrorHandler/ClientError/UnauthorizedError_401.html"), 401


# Custom error handler for 403 Forbidden Error
@app.errorhandler(403)
def forbidden(error):
    return render_template("ErrorHandler/ClientError/ForbiddenError_403.html"), 403


# Custom error handler for 404 Not Found error
@app.errorhandler(404)
def page_not_found(error):
    return render_template("ErrorHandler/ClientError/NotFoundError_404.html"), 404


# Custom error handler for 405 Method Not Allowed error
@app.errorhandler(405)
def method_not_allowed(error):
    return render_template("ErrorHandler/ClientError/MethodNotAllowed_405.html"), 404


# Custom error handler for 408 Request Timeout Error
@app.errorhandler(408)
def request_timeout(error):
    return render_template("ErrorHandler/ClientError/RequestTimeoutError_408.html"), 408


# Custom error handler for 412 Precondition Failed Error
@app.errorhandler(412)
def precondition_failed(error):
    return (
        render_template(
            "ErrorHandler/ClientError/PreconditionFailedError_412.html"),
        412,
    )


# Custom error handler for 415 Unsupported Media Type Error
@app.errorhandler(415)
def unsupported_media_type(error):
    return (
        render_template(
            "ErrorHandler/ClientError/UnsupportedMediaTypeError_415.html"),
        415,
    )


# Custom error handler for 418 I'm a teapot Error (RFC 2324)
@app.errorhandler(418)
def im_a_teapot(error):
    return render_template("ErrorHandler/ClientError/ImATeapotError_418.html"), 418


# Custom error handler for 451 Unavailable For Legal Reasons Error
@app.errorhandler(451)
def unavailable_for_legal_reasons(error):
    return (
        render_template(
            "ErrorHandler/ClientError/UnavailableForLegalReasonsError_451.html"
        ),
        451,
    )


# Custom error handler for 413 Request Entity Too Large error
@app.errorhandler(413)
def request_entity_too_large(error):
    return (
        render_template(
            "ErrorHandler/ClientError/RequestEntityTooLargeError_413.html"),
        413,
    )


# Custom error handler for 429 Too Many Request Error
@app.errorhandler(429)
def too_many_request(error):
    return render_template("ErrorHandler/ClientError/TooManyRequestError_429.html"), 429


# Custom error handler for 500 Internal Server error
@app.errorhandler(500)
def internal_server_error(error):
    return render_template("ErrorHandler/ServerError/InternalServerError_500.html"), 500


# Custom error handler for 501 Not Implemented error
@app.errorhandler(501)
def not_implemented(error):
    return render_template("ErrorHandler/ServerError/NotImplementedError_501.html"), 501


# Custom error handler for 502 Bad Gateway Error
@app.errorhandler(502)
def bad_gateway(error):
    return render_template("ErrorHandler/ServerError/BadGatewayError_502.html"), 502


# Custom error handler for 503 Service Unavailable error
@app.errorhandler(503)
def service_unavailable(error):
    return (
        render_template(
            "ErrorHandler/ServerError/ServiceUnavailableError_503.html"),
        503,
    )


# Custom error handler for 504 Gateway Timeout Error
@app.errorhandler(504)
def gateway_timeout(error):
    return render_template("ErrorHandler/ServerError/GatewayTimeoutError_504.html"), 504


if __name__ == "__main__":
    app.run(debug=True)
