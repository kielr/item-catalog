from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# Create Item Table
class Item(Base):
    __tablename__ = 'item'

    # Columns
    item_id = Column(Integer, primary_key=True)
    item_name = Column(String(128), nullable=False)
    item_desc = Column(String(256))
    item_price = Column(String(16))

    # Provide a way for calling code to read from this table.
    def get(self):
        return {
            'item_id': self.item_id,
            'item_name': self.item_name,
            'item_desc': self.item_desc,
            'item_price': self.item_price
        }


# Create User Table
class User(Base):
    __tablename__ = 'user'

    # Columns
    user_id = Column(Integer, primary_key=True)
    user_name = Column(String(128), nullable=False)
    user_email = Column(String(128), nullable=False)
    user_thumb = Column(String(256))

    # Provide a way for calling code to read from this table.
    def get(self):
        return {
            'user_id': self.user_id,
            'user_name': self.user_name,
            'user_email': self.user_email,
            'user_thumb': self.user_thumb
        }


# Create ItemCategory Table
class ItemCategory(Base):
    __tablename__ = 'item_category'

    # Columns
    column_id = Column(Integer, primary_key=True)
    column_name = Column(String(128), nullable=False)
    column_user = relationship(User)
    column_user_id = Column(Integer, ForeignKey('user.user_id'))

Base.metadata.create_all(create_engine('sqlite:///itemcatalog.db'))