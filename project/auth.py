import bcrypt
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from . import coll_admin_users


auth = Blueprint('auth', __name__)


@auth.route("/signup", methods=['post', 'get'])
def signup():
    message = ''
    if "email" in session:
        return redirect(url_for("auth.logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")

        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user_found = coll_admin_users.find_one({"name": user})
        email_found = coll_admin_users.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            coll_admin_users.insert_one(user_input)

            user_data = coll_admin_users.find_one({"email": email})
            new_email = user_data['email']

            return render_template('logged_in.html', email=new_email)
    return render_template('index.html')


@auth.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("auth.login"))


@auth.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("auth.logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = coll_admin_users.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('auth.logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("auth.logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@auth.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')


@auth.route("/change_password", methods=["POST", "GET"])
def change_password():
    message = 'Please type the new password'
    if "email" not in session:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        oldpassword = request.form.get("oldpassword")

        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        email = coll_admin_users.find_one({"email": session['email']})
        email_address = email['email']
        oldpswcheck = email['password']
        if not bcrypt.checkpw(oldpassword.encode('utf-8'), oldpswcheck):
            message = "Old password incorrect"
            return render_template('change_password.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('change_password.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {"$set": {'password': hashed}}

            coll_admin_users.update_one({"email": email_address}, user_input)

            message = "Email: {} password successfully changed!".format(email_address)
            return render_template('changed.html', message=message, email=email_address)
    return render_template('change_password.html', message=message)


@auth.route('/login')
def unauthorized():
    return render_template('login.html', message="Please authorize this site for use functions")