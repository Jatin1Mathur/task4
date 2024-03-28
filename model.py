from flask_sqlalchemy import SQLAlchemy

db=SQLAlchemy()

class User(db.Model):
    __tablename__ = 'User'

    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), unique=True, nullable=False)
    last_name = db.Column(db.String(250),  nullable=False)
    phone_no = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(100),  nullable=False)
    password = db.Column(db.String(100), nullable=False)
    
    
    
    def _init_(self, email_id, first_name, last_name, phone_number,password):
            self.email_id = email_id
            self.first_name = first_name
            self.last_name = last_name
            self.phone_number = phone_number
            self.password = password