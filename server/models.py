from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy.exc import IntegrityError

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-recipes.user', '-_password_hash',) # for RecursionError: maximum recursion depth exceeded in comparison

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable = False, unique = True)
    _password_hash = db.Column(db.String) #, nullable = False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', back_populates="user", cascade='all, delete-orphan') 
    # recipes = db.relationship('Recipe', backref='user')

    @hybrid_property
    def password_hash(self):
        #raise AttributeError
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    # __table_args__ = (
    #     db.CheckConstraint('length(instructions) >= 50'), # Solution alternative approach
    # )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable = False)
    instructions = db.Column(db.String, nullable = False) # db.CheckConstraint('LENGTH(instructions) > 50'), nullable = False)
    minutes_to_complete = db.Column(db.Integer)

    # Foreign key to store the user id
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationship mapping the recipes to related user
    user = db.relationship('User', back_populates="recipes") # is this uneeded? Solution not have

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'

    @validates('instructions')
    def validates_instructions(self,key,instructions):
        if len(instructions) < 50:
            #raise ValueError('instructions content is at least 50 characters')
            raise IntegrityError('instructions content is at least 50 characters') # Need to fx hi
        return instructions


if __name__ == "__main__":
    print("Hello, World!")

    username = 'ashketchum',
    password = 'pikachu',
    bio = '''I wanna be the very best
                        Like no one ever was
                        To catch them is my real test
                        To train them is my cause
                        I will travel across the land
                        Searching far and wide
                        Teach Pokémon to understand
                        The power that's inside''',
    image_url= 'https://cdn.vox-cdn.com/thumbor/I3GEucLDPT6sRdISXmY_Yh8IzDw=/0x0:1920x1080/1820x1024/filters:focal(960x540:961x541)/cdn.vox-cdn.com/uploads/chorus_asset/file/24185682/Ash_Ketchum_World_Champion_Screenshot_4.jpg'
    
    new_user = User(username = username,
                            image_url = image_url,
                            bio = bio)
    new_user.password_hash = password
    prinnt(new_user)

    # try:
    #     db.session.add(new_user)
    #     db.session.commit()

    #     user = User.query.filter(User.username == username).first() # so that have user id too
    #     session['user_id'] = user.id # saving use session
    #     return user.to_dict(), 201