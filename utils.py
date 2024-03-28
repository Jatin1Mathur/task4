

from model import db, User
def add_user(email, first_name, last_name, phone_no, password):
    new_user = User(email=email, first_name=first_name, last_name=last_name,
                       phone_number=phone_no, password=password)
    db.session.add(new_user)
    db.session.commit()
    return new_user


def delete_user(user):
        db.session.delete(user)
        db.session.commit() 


def com_changes():
    db.session.commit()