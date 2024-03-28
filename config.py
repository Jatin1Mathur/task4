from dotenv import load_dotenv
import os
load_dotenv()
def Basedir(app):
   app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
   app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
   app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
   app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
   app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
   app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')
   app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')