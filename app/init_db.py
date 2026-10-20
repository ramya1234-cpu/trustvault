
from app.database import engine
from app.models import Base


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("TrustVault database tables created successfully.")

    print("\nTables:")
    for table_name in Base.metadata.tables:
        print(f"- {table_name}")


if __name__ == "__main__":
    main()
