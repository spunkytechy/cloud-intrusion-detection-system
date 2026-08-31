"""Check connectivity to the configured PostgreSQL database."""

from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


load_dotenv(Path(__file__).with_name(".env"))


def main() -> None:
    import os

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set in .env")

    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            database, server_version = connection.execute(
                text("SELECT current_database(), version()")
            ).one()
            print(f"Connected to PostgreSQL database: {database}")
            print(f"Server: {server_version}")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()