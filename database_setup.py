#!/usr/bin/env python3
# Module to set up database.
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# create a table with name user


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

# create a table with name category


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

# for a json file
    @property
    def serialize(self):

        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id
        }


# create a table with name item
class Item(Base):
    __tablename__ = "item"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

# for json
    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id,
            'category_id': self.category_id
        }


engine = create_engine('sqlite:///itemscatalog.db')
Base.metadata.create_all(engine)
