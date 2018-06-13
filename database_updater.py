from database_setup import User, Base, Item, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


engine = create_engine('sqlite:///itemscatalog.db',
                       connect_args={'check_same_thread': False})

Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()
user1 = User(
    name='Ganesh',
    email='ganesh123@gmail.com',
    picture='data:image/jpeg;base64hg'
)
session.add(user1)
session.commit()

category1 = Category(
    name='restaurent1',
    user=user1
)
session.add(category1)
session.commit()

item1 = Item(
    name='biryani',
    description='the delicious food item!',
    category=category1,
    user=user1
)
session.add(item1)
session.commit()

item2 = Item(
    name='dum-biryani',
    description='the food item!',
    category=category1,
    user=user1
)
session.add(item2)
session.commit()

print('updated')
