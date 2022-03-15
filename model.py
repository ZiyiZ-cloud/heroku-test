
from sqlalchemy import true
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()

bcrypt = Bcrypt()


def connect_db(app):
    db.app = app
    db.init_app(app)
    
class User(db.Model):
    
    __tablename__ = 'users'
    
    username = db.Column(db.String(20), nullable=False, unique=True, primary_key=True)
    
    password = db.Column(db.Text, nullable=False)
    
    email = db.Column(db.String(50), nullable=False, unique=True)
    
    first_name = db.Column(db.String(30), nullable=False)
    
    last_name = db.Column(db.String(30), nullable=False)
    
    likes = db.relationship('Likes', backref='user', cascade='all,delete')
    
    
    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """Register a user, hashing their password."""

        hashed = bcrypt.generate_password_hash(password)
        hashed_utf8 = hashed.decode("utf8")
        user = cls(
            username=username,
            password=hashed_utf8,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Validate that user exists & password is correct.

        Return user if valid; else return False.
        """

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return False    
        


class Likes(db.Model):

    __tablename__ = 'likes' 

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_username = db.Column(
        db.String,
        db.ForeignKey('users.username')
    )

    pet_id = db.Column(
        db.String
    )