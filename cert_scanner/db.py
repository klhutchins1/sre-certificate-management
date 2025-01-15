from sqlalchemy import create_engine
from cert_scanner.models import Base

def init_db():
    """Initialize the database and create tables"""
    engine = create_engine('sqlite:///certificates.db')
    Base.metadata.create_all(engine)
    return engine

if __name__ == "__main__":
    init_db() 