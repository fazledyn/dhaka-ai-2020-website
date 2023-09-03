from flask import Flask, url_for, flash, copy_current_request_context
from flask import render_template, request, session, redirect
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect

from apscheduler.schedulers.background import BackgroundScheduler
from utils.metrics import calculate_image_precision

from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt
from urllib.parse import unquote
from functools import wraps
from os import environ

import pandas as pd
import numpy as np
import MySQLdb as mdb

import asyncio
import threading
import jwt
import datetime
import os

#############################################################
####### - - - - - - - - - CONFIGS - - - - - - - - - - #######

os.environ["TZ"] = "America/Los_Angeles"
app = Flask(__name__)
csrf = CSRFProtect(app)
mail = Mail(app)

#   Flask
app.debug      = environ.get("DEBUG")
app.secret_key = environ.get("SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

#   Mailing
MAIL_USERNAME = environ.get("MAIL_USERNAME")
MAIL_PASSWORD = environ.get("MAIL_PASSWORD")
MAIL_SERVER   = environ.get("MAIL_SERVER")
MAIL_SENDER   = environ.get("MAIL_SENDER")
MAIL_PORT     = environ.get("MAIL_PORT")
#   Database
DB_HOST       = environ.get("DB_HOST")
DB_NAME       = environ.get("DB_NAME")
DB_USERNAME   = environ.get("DB_USERNAME")
DB_PASSWORD   = environ.get("DB_PASSWORD")
#   Utils
MAX_ATTEMPTS = 10

app.config["MAIL_USERNAME"] = MAIL_USERNAME
app.config["MAIL_PASSWORD"] = MAIL_PASSWORD
app.config["MAIL_SERVER"]   = MAIL_SERVER
app.config["MAIL_PORT"]     = int(MAIL_PORT)
app.config["MAIL_USE_TLS"]  = False
app.config["MAIL_USE_SSL"]  = True


####### - - - - - - - - - CONFIGS - - - - - - - - - - #######
#############################################################


#############################################################
###  - - - - - - - - - SCHEDULER TASKS - - - - - - - - -  ###

def daily_reset():
    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)
    conn.query("update Team set DailyLimit=0 where 1=1")
    conn.commit()
    conn.close()

sched = BackgroundScheduler(daemon=True)
sched.add_job(daily_reset, "cron", hour="11")
sched.start()

###  - - - - - - - - SCHEDULER TASKS END - - - - - - - -  ###
#############################################################


#############################################################
###  - - - - - - - RIFAT BHAI"S PART START - - - - - - -  ###
#############################################################

# Numba typed list!
iou_thresholds = []  # numba.typed.List()
for x in [0.5, 0.55, 0.6, 0.65, 0.7, 0.75]:
    iou_thresholds.append(x)

def class_specification_metrics_for_all_images(df_gt, df_pred):
    """This function will iterate over all the Classification labels and calculate precision
    Args:
        gts: (Dataframe) Coordinates of the available ground-truth boxes
        preds: (Dataframe) Coordinates of the predicted boxes,
               sorted by confidence value (descending)

    Return:
        (float)  mAP -mean Average Precision
    """
    final_scores = []
    all_class = df_gt["class"].unique().tolist()
    print(f"Number of classes : {len(all_class)}")

    for gt_class in all_class:
        print(f"Predicted Labels:{gt_class}")

        gt_boxes = df_gt[df_gt["class"] == gt_class][["xmin", "ymin", "w", "h"]].values
        pred_boxes = df_pred[df_pred["class"] == gt_class][["xmin", "ymin", "score", "w", "h"]]
        pred_boxes = pred_boxes.sort_values(by=["score"], ascending=False)
        pred_boxes = pred_boxes[["xmin", "ymin", "w", "h"]].values

        class_precision = calculate_image_precision(gt_boxes, pred_boxes, thresholds=iou_thresholds, form="coco")
        final_scores.append(class_precision)
        print("Class Specific image precision of the Test Images: {0:.4f}".format(class_precision))

    return round(np.mean(final_scores), 4)


def is_unique(s):
    a = s.to_numpy()
    if a[0] == 1024:
        return (a[0] == a).all()
    else:
        return False


def check_format(df):
    if len(df.columns) == 9 and set(["image_id", "height", "width", "class", "score", "xmin", "ymin", "xmax", "ymax"]).issubset(df.columns):
        if is_unique(df["height"]) and is_unique(df["width"]):
            return True
        else:
            return False
    else:
        return False


async def calculate_accuracy(conn, filename, attempts):
    try:
        df_gt = pd.read_csv("gt_values.csv")
        df_gt["w"] = df_gt["xmax"]-df_gt["xmin"]
        df_gt["h"] = df_gt["ymax"]-df_gt["ymin"]
        # predicted values
        df_pred = pd.read_csv(filename)
        df_pred.columns = df_pred.columns.str.strip().str.lower()

        list_A = df_pred["image_id"].unique()
        list_B = df_gt["filename"].unique()

        # and all(item in list_A for item in list_B):
        if check_format(df_pred):
            df_pred["w"] = df_pred["xmax"]-df_pred["xmin"]
            df_pred["h"] = df_pred["ymax"]-df_pred["ymin"]

            # find accuracy here
            accuracy = class_specification_metrics_for_all_images(
                df_gt, df_pred)

            conn.query("insert into Leaderboard2 values (@id, '%s',%s,'%s',(NOW() + INTERVAL 13 HOUR),'%s')" % (session["TeamName"], accuracy, filename, "Correct"))
            conn.query("update Team set DailyLimit=%s where TeamName='%s'" % (attempts+1, session["TeamName"]))
            conn.commit()
            conn.close()
        else:
            accuracy = -1
            conn.query("insert into Leaderboard2 values (@id, '%s',%s,'%s',(NOW() + INTERVAL 13 HOUR),'%s')" % (session["TeamName"], accuracy, filename, "Incorrect"))
            conn.query("update Team set DailyLimit=%s where TeamName='%s'" % (attempts, session["TeamName"]))
            conn.commit()
            conn.close()
    except Exception as ex:
        accuracy = -1
        conn.query("insert into Leaderboard2 values (@id, '%s',%s,'%s',(NOW() + INTERVAL 13 HOUR),'%s')" % (session["TeamName"], accuracy, filename, "Incorrect"))
        conn.query("update Team set DailyLimit=%s where TeamName='%s'" % (attempts, session["TeamName"]))
        conn.commit()
        conn.close()


#############################################################
### - - - - - - - - RIFAT BHAI"S PART END - - - - - - - - ###
#############################################################

#############################################################
### - - - - - - - - TOKEN VALIDATION START - - - - - - - ###
#############################################################

def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = session["Token"]
        if not token:
            return redirect(url_for("login"))

        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        except:
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapped

#############################################################
###  - - - - - - - - TOKEN VALIDATION END - - - - - - - - ###
#############################################################

#############################################################
### - - - - - - - - ASYNC METHODS START - - - - - - - - - ###
#############################################################

def send_async_mail(msg):
    @copy_current_request_context
    def send_mail(Message):
        mail.send(msg)

    mail_sender = threading.Thread(
        name="mail_sender", target=send_mail, args=(msg, ))
    mail_sender.start()


def send_registration_mail(teamname, password, email, email_token):
    subject = "Registration Confirmed for Dhaka AI 2020 Contest"
    html = render_template(
        "email/registered.html",
        teamname=teamname,
        password=password,
        email_token=email_token
    )
    msg = Message(subject=subject, recipients=[email], sender=MAIL_SENDER, html=html)
    send_async_mail(msg=msg)


def send_approval_mail(email):
    subject = "Approval Confirmed for Dhaka AI 2020 Contest"
    html = render_template("email/approved.html")

    msg = Message(subject=subject, recipients=[email], sender=MAIL_SENDER, html=html)
    send_async_mail(msg=msg)

#############################################################
### - - - - - - - - ASYNC METHODS START - - - - - - - - - ###
#############################################################

#############################################################
### - - - - - - - - WEBSITE ROUTE START - - - - - - - - - ###
#############################################################

@app.route("/")
@app.route("/index")
def index():
    # conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
    #                       passwd=DB_PASSWORD, database=DB_NAME)
    # conn.query("SELECT COUNT(*) FROM Team WHERE isAdmin=0;")
    # cursor = conn.store_result()
    # total_team = cursor.fetch_row()[0][0]
    # conn.commit()
    # conn.close()

    return render_template("index.html", total_team=350)


@app.route("/register", methods=["GET", "POST"])
def register():
    session.pop("TeamName", None)  # delete visits

    if request.method == "POST":
        conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)

        TeamName = request.form["teamname"]
        name1 = request.form["name1"]
        name2 = request.form["name2"]
        name3 = request.form["name3"]
        name4 = request.form["name4"]
        name5 = request.form["name5"]
        phone1 = request.form["phone1"]
        phone2 = request.form["phone2"]
        phone3 = request.form["phone3"]
        phone4 = request.form["phone4"]
        phone5 = request.form["phone5"]
        inst1 = request.form["inst1"]
        inst2 = request.form["inst2"]
        inst3 = request.form["inst3"]
        inst4 = request.form["inst4"]
        inst5 = request.form["inst5"]
        email = request.form["email"]
        Password = request.form["password"]
        RePassword = request.form["re-password"]

        TeamName = TeamName.strip()
        Password = Password.strip()

        if TeamName == "" or email == "" or name1 == "" or phone1 == "" or inst1 == "":
            flash("You must enter required information!")
            return redirect(url_for("register"))

        if len(TeamName) > 25:
            flash("Your team name must be 25 characters or shorter!")
            return redirect(url_for("register"))

        if len(email) > 50:
            flash("Your email address must not exceed 50 characters!")
            return redirect(url_for("register"))

        if len(Password) < 8 or len(Password) > 16:
            flash("Password must be between 8-16 characters long!")
            return redirect(url_for("register"))

        if len(name1) > 40 or len(name2) > 40 or len(name3) > 40 or len(name4) > 40 \
                or len(name5) > 40:
            flash("Name of participants must be 40 characters or less!")
            return redirect(url_for("register"))

        if len(phone1) > 20 or len(phone2) > 20 or len(phone3) > 20 or len(phone4) > 20 \
                or len(phone5) > 20:
            flash("Phone numbers of participants must be 20 digits or less!")
            return redirect(url_for("register"))

        if len(inst1) > 50 or len(inst2) > 50 or len(inst3) > 50 \
                or len(inst4) > 50 or len(inst5) > 50:
            flash("Institution name must be within 50 characters or less!")
            return redirect(url_for("register"))

        # Checking whether TeamName is already taken
        conn.query("Select count(*) from Team where TeamName='%s'" % TeamName)
        cursor = conn.store_result()

        # Redirects back to registration page if name already taken or password confirmation does not match
        if (Password != RePassword):
            flash("Passwords do not match. Enter carefully!")
            return redirect(url_for("register"))

        if (cursor.fetch_row()[0][0] > 0):
            flash("There's already a team with same name. Choose another name.")
            return redirect(url_for("register"))

        conn.query("SELECT EmailAddress FROM Team")
        cursor = conn.store_result()
        fetched_email = cursor.fetch_row(maxrows=0)

        email_list = []
        for row in fetched_email:
            email_list += row

        print(email_list)

        if (email in email_list):
            flash("An account with this email already exists!")
            return redirect(url_for("register"))

        email_token = jwt.encode(payload={
            "TeamName": TeamName,
            "Password": Password
        }, key=app.secret_key, algorithm="HS256").decode("utf-8")

        # inserting team into team table, remaining 3 values are 0 by default
        cursor = conn.cursor()
        cursor.execute("Insert into Team values ('%s','%s','%s','%s',0,0,0,0, curdate(), 0)" % (
            TeamName, sha256_crypt.hash(Password), email, email_token))
        conn.commit()
        cursor.close()
        # inserting participants into participant table
        try:
            if (name1 != "" and phone1 != "" and inst1 != ""):
                cursor = conn.cursor()
                cursor.execute("Insert into Participant values (@id, '%s','%s','%s','%s')" %
                               (name1, phone1, inst1, TeamName))
                print("1st member")
                conn.commit()
                cursor.close()

            if (name2 != "" and phone2 != "" and inst2 != ""):
                cursor = conn.cursor()
                cursor.execute("Insert into Participant values (@id, '%s','%s','%s','%s')" %
                               (name2, phone2, inst2, TeamName))
                print("2nd member")
                conn.commit()
                cursor.close()

            if (name3 != "" and phone3 != "" and inst3 != ""):
                cursor = conn.cursor()
                cursor.execute("Insert into Participant values (@id, '%s','%s','%s','%s')" %
                               (name3, phone3, inst3, TeamName))
                print("3rd member")
                conn.commit()
                cursor.close()

            if (name4 != "" and phone4 != "" and inst4 != ""):
                cursor = conn.cursor()
                cursor.execute("Insert into Participant values (@id, '%s','%s','%s','%s')" %
                               (name4, phone4, inst4, TeamName))
                print("4th member")
                conn.commit()
                cursor.close()

            if (name5 != "" and phone5 != "" and inst5 != ""):
                cursor = conn.cursor()
                cursor.execute("Insert into Participant values (@id, '%s','%s','%s','%s')" %
                               (name5, phone5, inst5, TeamName))
                print("5th member")
                conn.commit()
                cursor.close()

            conn.commit()
            conn.close()
        except:
            pass

        send_registration_mail(
            teamname=TeamName, password=Password, email=email, email_token=email_token)
        flash("You've been registered! Check your inbox for confirmation mail. It can take upto 5 minutes to get our confirmation mail.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/email-verification/<email_token>")
def email_verification(email_token):
    print()
    print(email_token)
    print()
    json = jwt.decode(email_token, app.secret_key, algorithms=["HS256"])
    print(json)

    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                          passwd=DB_PASSWORD, database=DB_NAME)
    conn.query("UPDATE Team SET isVerified=1 WHERE EmailToken='%s'" %
               email_token)
    conn.commit()
    conn.close()

    flash("Email verification completed! Now you must wait until we approve your team. After approval, a mail will be sent to you.")
    return redirect(url_for("login"))


"""
@app.route("/success/<title>", methods=["GET", "POST"])
@check_for_token
def success(title):
    return render_template("success.html", value=title)
"""


@app.route("/core-team")
def core_team():
    return render_template("core-team.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.pop("TeamName", None)  # delete visits

    if request.method == "POST":
        conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                              passwd=DB_PASSWORD, database=DB_NAME)
        conn.query("Select * from Team where TeamName='%s' and isApproved=1" %
                   request.form["username"])
        cursor = conn.store_result()
        res = cursor.fetch_row()
        conn.close()

        if res != None and res != ():

            if (res[0][0] == request.form["username"] and sha256_crypt.verify(request.form["password"], res[0][1]) and res[0][9] == 1):
                token = jwt.encode(
                    {
                        "user": request.form["username"],
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
                    }, app.secret_key, algorithm="HS256"
                )
                session["TeamName"] = request.form["username"]
                session["Token"] = token
                return redirect(url_for("dashboard"))

            elif (res[0][9] == 0):
                flash("Sorry, your team is not qualified for round 2.")
                return redirect(url_for("login"))

            else:
                flash("Make sure you have entered credentials correctly!")
                return redirect(url_for("login"))

        else:
            flash("It looks like your team doesn't exist. If you think there has been a problem, let us know.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout", methods=["GET"])
@check_for_token
def logout():
    session.pop("TeamName", None)  # delete visits
    return redirect(url_for("login"))


@app.route("/upload")
@check_for_token
def upload():
    if "TeamName" not in session:
        return redirect(url_for("login"))
    return render_template("upload.html")


@app.route("/uploaded", methods=["GET", "POST"])
@check_for_token
def uploaded():
    if "TeamName" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                              passwd=DB_PASSWORD, database=DB_NAME)

        conn.query("Select * from Team where TeamName='%s'" %
                   session["TeamName"])
        cursor = conn.store_result()
        res = cursor.fetch_row()
        attempts = res[0][7]

        if attempts == MAX_ATTEMPTS:
            flash("You have already attempted 10 times today ! Come next day.")
            return redirect(url_for("upload"))

        f = request.files["file"]
        filename = secure_filename(f.filename)
        f.save(filename)

        asyncio.run(calculate_accuracy(conn, filename, attempts))

        flash("Your submission is being processed. Check dashboard after a while.")
        return redirect(url_for("upload"))

    return redirect(url_for("upload"))


@app.route("/rules")
def rules():
    return render_template("rules.html")


@app.route("/posters")
def posters():
    return render_template("posters.html")


###########################################
#        leaderboard (1st round)          #
###########################################

@app.route("/leaderboard")
def leaderboard():
    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                          passwd=DB_PASSWORD, database=DB_NAME)

    conn.query("select TeamName, accuracy, min(SubmissionTime) as SubmissionTime from Leaderboard where (TeamName, accuracy) in (select TeamName, max(accuracy) from Leaderboard group by TeamName)  group by TeamName, accuracy order by accuracy desc")
    cursor = conn.store_result()
    results = []
    team_count = cursor.num_rows()

    for i in range(team_count):
        results.append(list(cursor.fetch_row()[0]))

    inst = []
    for i in range(team_count):
        teamname = results[i][0]
        conn.query(
            "SELECT Institution FROM Participant WHERE TeamName='%s' LIMIT 1" % teamname)
        cursor = conn.store_result()
        results[i].append(cursor.fetch_row()[0][0])

    conn.close()
    return render_template("leaderboard.html", result=results)


###########################################
#        leaderboard (2nd round)          #
###########################################

@app.route("/leaderboard2")
def leaderboard2():
    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                          passwd=DB_PASSWORD, database=DB_NAME)

    conn.query("select TeamName, accuracy, min(SubmissionTime) as SubmissionTime from Leaderboard2 where (TeamName, accuracy) in (select TeamName, max(accuracy) from Leaderboard2 group by TeamName)  group by TeamName, accuracy order by accuracy desc")
    cursor = conn.store_result()
    results = []
    team_count = cursor.num_rows()

    for i in range(team_count):
        results.append(list(cursor.fetch_row()[0]))

    for i in range(team_count):
        teamname = results[i][0]
        conn.query(
            "SELECT Institution FROM Participant WHERE TeamName='%s' LIMIT 1" % teamname)
        cursor = conn.store_result()
        results[i].append(cursor.fetch_row()[0][0])

    conn.close()
    return render_template("leaderboard2.html", result=results)


@app.route("/approve/<TeamName>")
@check_for_token
def approve(TeamName):
    print("----------------------------------------------")
    print(TeamName)
    TeamName = unquote(TeamName)

    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                          passwd=DB_PASSWORD, database=DB_NAME)
    conn.query("Update Team set isApproved=1 where TeamName='%s'" % TeamName)
    conn.query("SELECT EmailAddress FROM Team WHERE TeamName='%s'" % TeamName)

    cursor = conn.store_result()
    email = cursor.fetch_row()[0][0]
    print(email)

    conn.commit()
    conn.close()

    send_approval_mail(email=email)
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@check_for_token
def dashboard():
    if "TeamName" in session:
        team = session["TeamName"]
        unverified = None
        conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME,
                              passwd=DB_PASSWORD, database=DB_NAME)

        if (session["TeamName"] == "admin"):
            user_type = "admin"
            conn.query("select * from Team where isApproved=0")
            cursor = conn.store_result()
            unverified = []
            for i in range(cursor.num_rows()):
                unverified.append(cursor.fetch_row()[0])
            conn.close()
            return render_template("dashboard.html", user_type=user_type, team=team, result=unverified)

        else:
            user_type = "team"
            submissions = []
            conn.query(
                "SELECT * FROM Leaderboard2 WHERE TeamName='%s' ORDER BY SubmissionTime DESC" % team)
            cursor = conn.store_result()
            submissions = cursor.fetch_row(maxrows=0)

            conn.query("SELECT * FROM Participant WHERE TeamName='%s'" % team)
            cursor = conn.store_result()
            team_info = cursor.fetch_row(maxrows=0)

            conn.query("SELECT DailyLimit FROM Team WHERE TeamName='%s'" % team)
            cursor = conn.store_result()
            daily_limit = cursor.fetch_row()[0][0]

            return render_template("dashboard.html", user_type=user_type, team=team, submissions=submissions, team_info=team_info, daily_limit=daily_limit)

    return redirect(url_for("index"))


@app.route("/team-details/<teamname>")
@check_for_token
def team_details(teamname):

    print(teamname)
    teamname = unquote(teamname)
    print(teamname)

    if "TeamName" in session:

        if (session["TeamName"] == "admin"):
            user_type = session["TeamName"]
            conn = mdb.Connection(
                host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)

            conn.query(
                "SELECT TeamName, EmailAddress, isVerified FROM Team WHERE TeamName='%s'" % teamname)
            cursor = conn.store_result()
            team_info = cursor.fetch_row()

            conn.query(
                "SELECT * FROM Participant WHERE TeamName='%s'" % teamname)
            cursor = conn.store_result()

            member_info = []
            for i in range(cursor.num_rows()):
                member_info.append(cursor.fetch_row()[0])

            conn.commit()
            conn.close()

            return render_template("team-details.html", user_type=user_type, team_info=team_info, member_info=member_info)

        else:
            flash("You are not authorized to access this page yet")
            return redirect(url_for("index"))

    flash("You must login first !")
    return redirect(url_for("login"))


#############################################################
### - - - - - - - - - ERROR HANDLERS - - - - - - - - - -  ###
#############################################################

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")

@app.errorhandler(500)
def internal_error(e):
    return "Internal server error."


#############################################################
###  - - - - - - - - WEBSITE ROUTE END - - - - - - - - -  ###
#############################################################


if __name__ == "__main__":
    app.run()
    # for mobile testing, allows devices on same network to access site
    """app.run(host="0.0.0.0")"""
