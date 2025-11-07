from flask_mail import Message

def send_login_email(mail, email, username):
    msg = Message(
        subject="Welcome Back!",
        sender="chaitanya.singh@gammaedge.io",
        recipients=[email],
        body=f"Hello {username},\n\nWelcome back! You have successfully logged in."
    )
    mail.send(msg)
