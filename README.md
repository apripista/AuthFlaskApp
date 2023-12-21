###### Read each line carefully, you may need to replace something with your own credentials, up to now the project can run locally. 


###### Remember to replace your email and password with your actual email credentials.
# AuthFlaskApp: Flask User Authentication Application

# NOTE: STILL UNDER IMPROVEMENTS TAKE CARE WITH YOURSELF: RUN IT LOCALLY AND IF CAN PROCEED JUST DO THAT WITH NO ANY EXCUSES
`AuthFlaskApp` is a Is a simple flask web application that is focused on user authentication, it is just to demonstrate the user authentication, created by `Tito M. Joctan` (Perfect-Altruistics) in October 2023. Developed in Python using the Flask web application framework. It Allows users to create accounts, verify their identity, and manage sensitive user data, including password changes, resets, updates, deletions, and changes to email and user profiles.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Database Setup](#database-setup)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features.
### 1: User Authentication.

(i) Registration Process

    Users can access the registration process on the home page.
    Registration requires a valid unique email address, a unique username, and a strong password.
    Password strength requirements include at least 8 characters, one special symbol, one capital letter, one small letter, and one alphanumeric character.
    Flash messages inform users of issues like non-unique username or email, and weak passwords.
    Fields like first name, last name, country, and username are required, with a minimum length of three characters.
    user should also prove that he is not a robot by recaptcha technology
(
ii) Account Activation and Verification Process

    Users receive an account activation email with a verification link.
    The link expires after 10 minutes, and users can request a new link if needed.
    The system checks the validity of the verification token and updates the user's verification status.
    user should also prove that he is not a robot by recaptcha technology

(iii) Login Process

    Users log in with their username and password.
    The system checks if the user is verified and whether 2FA is enabled.
    For 2FA-enabled accounts, a six-digit token is generated and sent to the user's email for verification.

(iv) User Profile Management

    Change Email Address: Users can request to change their email, and a verification link is sent to the new email.
    Change Password: Users can change their password with a strong password check.
    Enable 2FA: Users can activate or deactivate 2FA by providing the correct email and command.
    Delete Account: Users can delete their account, with additional verification steps.

## Getting Started

### Prerequisites

Ensure you have the following installed on your system:

- Python 3.11.4 + or 3.11.x
- Flask 3.0.0
- [Virtual environment](https://docs.python.org/3/tutorial/venv.html) (recommended)

### Installation

1. Clone the repository:

   ```bash
    git clone https://github.com/Perfect-Altruistics/AuthFkaskApp   cd InsipiraHub.git
    cd AuthFkaskApp

## Configuration

### Database Setup

This section outlines the key tables in the database used by InsipiraHub. The application utilizes a relational database `PostgrSQL DATABASE`to manage user accounts, tokens, and deleted account information.

#### Tables

## How to create tables
   need to know how to create tables? click here: [table creation](SQL/sql.txt)
#### 1. accounts

The `accounts` table stores user account information, including details such as email, username, password, and account verification status.

###### structure of table `accounts`:

- `id` (integer): Unique identifier for each user.
- `email` (character varying(255)): User's email address, must be unique and cannot be null.
- `username` (character varying(255)): User's username, must be unique and cannot be null.
- `password` (character varying(255)): Hashed password for user authentication.
- `country` (character varying(255)): User's country.
- `pin` (character varying(4)): Security PIN for additional verification.
- `registration_date` (timestamp without time zone): Timestamp of user registration.
- `verified` (boolean): Indicates if the user's account is verified.
- `profile_picture` (character varying(255)): Path to the user's profile picture.
- `tfa` (character varying(1)): Indicates if Two-Factor Authentication (2FA) is enabled (T) or disabled (F).
- `auth_token` (character varying(6)): Authentication token for various purposes like during account logging in and deletion of 2FA enabled accounts.
- `role` (character varying(10)): User role, default is 'user.' It specifies different levels of permissions user has in the InsipiraHub

##### 2. tokens

The `tokens` table manages various tokens related to user accounts, including verification and password reset tokens.

###### structure of table `tokens`:


- `id` (integer): Unique identifier for each token.
- `account_id` (integer): Foreign key referencing the user's account in the `accounts` table.
- `username` (character varying(255)): User's username, cannot be null.
- `email` (character varying(255)): User's email address, cannot be null.
- `verification_token` (character varying(255)): Token for email verification.
- `verification_sent_time` (timestamp without time zone): Timestamp when the verification token is sent.
- `verification_token_expiration` (timestamp without time zone): Token expiration timestamp for email verification.
- `reset_password_token` (character varying(255)): Token for resetting the user's password.
- `reset_password_token_expiration` (timestamp without time zone): Token expiration timestamp for password reset.
- `verification_token_new` (character varying(255)): New verification token for scenarios like email updates.

##### 3. deleted_accounts

The `deleted_accounts` table stores information about user accounts that have been deleted.

###### structure of table `deleted_accounts`:

- `id` (integer): Unique identifier for each deleted account.
- `email` (character varying(255)): User's email address.
- `first_name` (character varying(255)): First name of the user.
- `last_name` (character varying(255)): Last name of the user.
- `country` (character varying(255)): User's country.
- `day`, `month`, `year` (integer): User's birthdate information.
- `deleted_date` (date): Date when the account was deleted.
- `deletion_reason` (text): Textual description of the reason for deletion.

### Table Documentations
#### 1: Table accounts:
   1. **Password Hashing Algorithm:**

   The algorithm used for hashing passwords is PBKDF2 with SHA-256. The implementation code is as follows:
   ```python
    # DURING USER REGISTRATION:
   # Hash the password using PBKDF2 with SHA-256 before storing it in the database
   hashed_password = generate_password_hash(
       password, method="pbkdf2:sha256", salt_length=8
   ).

    # DURING USER LOG IN:
# check if the password during login match with the stored password
        # stored hashed password is the 6th column in table accounts
        if user and check_password_hash(user[5], password):
            # print(f"User {username} found and password matched.")

# DURING PASSWORD CHANGE:
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
```

#### 2: Table tokens
1. Token expiration policies:
   - verification of registered user email before log in: 
      - The token expiration policy is implemented in the `verify_email` and ` resend_verification` route. Tokens are considered valid for 10 minutes. If a token has expired, an error message is displayed, and the user is redirected to request a new verification token. The relevant code excerpt is as follows:
        ```python
        if token_data:
           # Check if the verification link has expired (valid for 10 minutes)
           verification_sent_time = token_data[
               5
           ]  # Verification_sent_time is in the 6th column
           current_time = datetime.now()

           # Calculate the time difference in minutes
           time_difference = (
               current_time - verification_sent_time).total_seconds() / 60

           if time_difference <= 10:  # the verification link is valid for 10 minutes
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
        ```
        The same logic occur during password reset as it is shown here: 
        ```python
        if request.method == "POST":
            email = request.form["email"]
            
            email = bleach.clean(email)  # sanitize user input: email
            
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
            user = cursor.fetchone()
    
            if user:
                # Check if the user is already verified:
                # user_verified is the 13th column in table accounts
                if user[12]:
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
    
                    # Commit transaction to save changes in the database
                    conn.commit()
    
                    # Send the new verification email
                    email_message = Message(
                        "Email Verification", recipients=[email])
                    server_address = "http://localhost:5000"
                    email_message.body = (
                        f"Click the following link to verify your email: "
                        f"{server_address}/verify/"
                        f"{verification_token}"
                    )
                    mail.send(email_message)
    
                    cursor.close()
        ```
        WHY TOKENS EXPIRE:
      - `Risk Mitigation:`
         - `Lost or Stolen Devices:` In scenarios where tokens are stored on devices (e.g., mobile phones or browsers), if the device is lost or stolen, an attacker could gain unauthorized access. Token expiration helps limit the impact of such incidents.
      - `User Access Management:`
         - `User Lifecycle Management:` Token expiration aligns with the user's lifecycle. For example, if a user's account is disabled or deleted, any active tokens associated with that account become invalid after expiration, reducing the risk of unauthorized access.
      - `Security:`
         - `Reduced Exposure Time:`Tokens, especially those used for authentication, have the potential to be intercepted or stolen. By limiting their validity period, even if a token is compromised, the window of opportunity for an attacker is minimized.
         -  `Dynamic Security Landscape:` Security threats and vulnerabilities evolve over time. A token that was secure at one point might become vulnerable in the future. Regular expiration and renewal help adapt to the changing security landscape.

#### 3: Table deleted_accounts:
1. `Capturing Deletion Reasons:`
    The purpose of capturing deletion reasons is to audit why users delete their accounts. The deleted_accounts table includes a deletion_reason column where administrators can store a textual description of the reason for deletion.
2.  `Deleted_date:` This help administrators to keep track of how log users use our service. It will be used by comparing with `day`, `month` and `year` of registration.
3.  `Country:` Country is recorded to allow us to audit where most users delete their accounts.
4. `email:` How long the same email is used again to create the account.

## Usage

## Contributing

Thank you for considering contributing to Altruistics! Please follow the guidelines below:
### 1: Issues

If you find a bug or have a suggestion, please [open an issue](https://github.com/Perfect-Altruistics/InsipiraHub/issues).

### 2: Pull Requests

1. Fork the repository.
2. Create a new branch for your feature or bug fix: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m 'Add new feature'`.
4. Push to your fork: `git push origin feature-name`.
5. Open a pull request.

### 3: Coding Standards

Thank you for considering contributing to our project! Before making contributions, please familiarize yourself with our [Flask template coding standards](FLASK_TEMPLATE_CODING_STANDARDS.md). and Follow the [coding standards](CODING_STANDARDS.md) to maintain a consistent code style.

### 4: Testing

Ensure that your changes don't break existing functionality. Run tests before submitting a pull request.

### 5: Review Process

The maintainers will review all pull requests. Be patient during the review process.

### 6: Code of Conduct

Please make sure to follow our [Code of Conduct](CODE_OF_CONDUCT.md) and [Contribution Guidelines](CONTRIBUTION_GUIDELINES.md).
Thank you for contributing!.
Happy coding!

## License

This project is licensed under the terms of the [MIT license](./LICENSE).