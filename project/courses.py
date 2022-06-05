import bcrypt
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from . import coll_admin_users
from bson.json_util import dumps


courses = Blueprint('courses', __name__)


@courses.route("/courses/change", methods=["POST", "GET"])
def change_password():
    message = 'Please type the new password'
    if "email" not in session:
        return redirect(url_for("auth.login"))
    d = coll_admin_users.find_one({"email": "gayratbek.sultonov@gmail.com"})
    if request.method == "POST":
        print(request.form.to_dict())
    # if request.method == "POST":
    #     oldpassword = request.form.get("oldpassword")
    #
    #     password1 = request.form.get("password1")
    #     password2 = request.form.get("password2")
    #
    #     email = coll_admin_users.find_one({"email": session['email']})
    #     email_address = email['email']
    #     oldpswcheck = email['password']
    #     if not bcrypt.checkpw(oldpassword.encode('utf-8'), oldpswcheck):
    #         message = "Old password incorrect"
    #         return render_template('change_password.html', message=message)
    #     if password1 != password2:
    #         message = 'Passwords should match!'
    #         return render_template('change_password.html', message=message)
    #     else:
    #         hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
    #         user_input = {"$set": {'password': hashed}}
    #
    #         coll_admin_users.update_one({"email": email_address}, user_input)
    #
    #         message = "Email: {} password successfully changed!".format(email_address)
    #         return render_template('changed.html', message=message, email=email_address)
    return render_template('courses/change.html', message=message, **d)
