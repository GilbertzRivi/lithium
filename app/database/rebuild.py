import os
import subprocess
from datetime import datetime
import sys
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

# Get environment variables for database configuration
POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST")
POSTGRES_PORT = os.getenv("POSTGRES_PORT")
POSTGRES_DB = os.getenv("POSTGRES_DB")

# Database URL
DATABASE_URL = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Timestamp for dumping
timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
dump_file = f"./database/dumps/{timestamp}-dump.sql"

# SQLAlchemy setup
engine: AsyncEngine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=sessionmaker)


def dump_database():
    """Dump the current state of the database."""
    try:
        dump_command = [
            "pg_dump",
            "-h",
            POSTGRES_HOST,
            "-p",
            POSTGRES_PORT,
            "-U",
            POSTGRES_USER,
            "-F",
            "c",
            "-f",
            dump_file,
            POSTGRES_DB,
        ]
        subprocess.run(dump_command, check=True, env={"PGPASSWORD": POSTGRES_PASSWORD})
        print(f"Database dumped to {dump_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error dumping the database: {e}")
        sys.exit(1)


def drop_database():
    """Drop the current database."""
    try:
        drop_command = [
            "dropdb",
            "-h",
            POSTGRES_HOST,
            "-p",
            POSTGRES_PORT,
            "-U",
            POSTGRES_USER,
            POSTGRES_DB,
        ]
        subprocess.run(drop_command, check=True, env={"PGPASSWORD": POSTGRES_PASSWORD})
        print(f"Database {POSTGRES_DB} dropped successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error dropping the database: {e}")
        sys.exit(1)


def create_database():
    """Create a new database."""
    try:
        create_command = [
            "createdb",
            "-h",
            POSTGRES_HOST,
            "-p",
            POSTGRES_PORT,
            "-U",
            POSTGRES_USER,
            POSTGRES_DB,
        ]
        subprocess.run(
            create_command, check=True, env={"PGPASSWORD": POSTGRES_PASSWORD}
        )
        print(f"Database {POSTGRES_DB} created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating the database: {e}")
        sys.exit(1)


async def create_tables():
    """Create all tables and relations using SQLAlchemy models."""
    async with engine.begin() as conn:
        print("Creating tables...")
        await conn.run_sync(Base.metadata.create_all)
        print("Tables created successfully.")


if __name__ == "__main__":
    dump_database()
    drop_database()
    create_database()

    # Create tables and relations using models.py
    import asyncio

    asyncio.run(create_tables())
