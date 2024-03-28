from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_migrate import Migrate
from model import User,db
from utils import add_user, delete_user, com_changes
import base64
import os
from config import Basedir
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
migrate = Migrate(app, db)

password_reset_tokens = {}


@app.route("/register", methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_no = data.get('phone_no')
    password = data.get('password')
    if not all([email, first_name, last_name, phone_no, password]):
        return jsonify({'error': 'All fields need to be provided'}), 400
    if User.query.filter_by(email=email).first() or User.query.filter_by(phone_no=phone_no).first():
        return jsonify({'error': 'User with this email or phone number already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, first_name=first_name, last_name=last_name,
                    phone_no=phone_no, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone_no = data.get('phone_no')
    password = data.get('password')
    user = User.query.filter_by(phone_no=phone_no).first()
    if not user:
        return jsonify({'message': 'User not found'})
    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity={'first_name': user.first_name, 'last_name': user.last_name, 'email': user.email, 'phone_no': user.phone_no})
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/retrieve/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'user_id': user.user_id, 'first_name': user.first_name, 'last_name': user.last_name, 'phone_no': user.phone_no, 'email': user.email}), 200
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route("/update/<int:user_id>", methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.json
    user.email = data.get('email', user.email)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.phone_no = data.get('phone_no', user.phone_no)
    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

@app.route("/delete/<int:user_id>", methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route("/change_password", methods=['POST'])
@jwt_required()
def change_password():
    current_user = get_jwt_identity()
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if new_password != old_password:
        return jsonify({'message': 'Please check your password'})
    user = User.query.filter_by(email=current_user['email']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if not bcrypt.check_password_hash(user.password, old_password):
        return jsonify({'message': 'Incorrect old password'}), 400
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200

@app.route('/forget', methods=['POST'])
def forget_password():
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    reset_token = base64.b64encode(email.encode('utf-8')).decode('utf-8')
    password_reset_tokens[reset_token] = email
    reset_link = f'http://127.0.0.1:5000/reset/{reset_token}'
    send_reset_password_email(email, reset_link)
    return jsonify({'message': 'Reset password link sent to your email'}), 200


def send_reset_password_email(user_email, reset_link):
    msg = Message('Password Reset Link', sender='your_email@gmail.com', recipients=[user_email])
    msg.body = f'Hello,\n\nYour reset link is: {reset_link}'
    mail.send(msg)


@app.route('/reset/<reset_token>', methods=['POST'])
def reset(reset_token):
    data = request.json
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    if new_password != confirm_password:
        return jsonify({'message': 'Please check your password'})
    
    email = password_reset_tokens.get(reset_token)
    email = base64.b64decode(reset_token).decode('utf-8')
    if not email:
        return jsonify({'message': 'Invalid or expired token. Please request a new password reset.'})
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid or expired token. Please request a new password reset.'})
    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    del password_reset_tokens[reset_token]
    return jsonify({'message': 'Password reset successful'})


if __name__ == '__main__':
    app.run(debug=True)
