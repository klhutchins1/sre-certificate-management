"""
Schema management for IMS.

Handles:
- Schema creation
- Migration
- Validation
"""

from datetime import datetime
import json
import logging
import sys

from sqlalchemy import inspect, text
from ..models import Base
from ..settings import Settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('streamlit_runner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def update_database_schema(engine):
    """
    Update database schema to include new tables and columns.
    
    This function performs the following operations:
    1. Inspects existing database schema
    2. Compares with defined models
    3. Creates missing tables
    4. Adds missing columns to existing tables
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if update successful, False otherwise
        
    Note:
        This operation is non-destructive and preserves existing data
    """
    try:
        logger.info("Checking for missing tables and columns...")
        try:
            inspector = inspect(engine)
            existing_tables = inspector.get_table_names()
        except Exception as e:
            logger.error(f"Failed to inspect database: {str(e)}")
            return False
        
        # Get all table names from our models
        model_tables = set(Base.metadata.tables.keys())
        
        # Find and create missing tables
        missing_tables = model_tables - set(existing_tables)
        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            for table_name in missing_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(engine)
        
        # Update existing tables with missing columns
        for table_name in existing_tables:
            if table_name in Base.metadata.tables:
                model_columns = {c.name: c for c in Base.metadata.tables[table_name].columns}
                try:
                    existing_columns = {c['name']: c for c in inspector.get_columns(table_name)}
                    # Validate table structure
                    for col_name, col_info in existing_columns.items():
                        if col_name not in model_columns:
                            logger.error(f"Invalid column {col_name} in table {table_name}")
                            return False
                except Exception as e:
                    logger.error(f"Failed to get columns for table {table_name}: {str(e)}")
                    return False
                
                # Add missing columns
                missing_columns = set(model_columns.keys()) - set(existing_columns.keys())
                if missing_columns:
                    logger.info(f"Adding missing columns to {table_name}: {missing_columns}")
                    try:
                        with engine.begin() as connection:
                            for column_name in missing_columns:
                                column = model_columns[column_name]
                                nullable = 'NOT NULL' if not column.nullable else ''
                                
                                # Handle default values
                                default = ''
                                if column.server_default is not None:
                                    default = f"DEFAULT {column.server_default.arg}"
                                elif column.default is not None:
                                    if isinstance(column.default.arg, str):
                                        default = f"DEFAULT '{column.default.arg}'"
                                    else:
                                        default = f"DEFAULT {column.default.arg}"
                                
                                # For SQLite, we need to handle NOT NULL with DEFAULT in a specific way
                                if not column.nullable and default:
                                    # First add the column without NOT NULL
                                    sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {default}"
                                    connection.execute(text(sql.strip()))
                                    
                                    # Then update any NULL values with the default
                                    sql = f"UPDATE {table_name} SET {column_name} = {column.server_default.arg} WHERE {column_name} IS NULL"
                                    connection.execute(text(sql.strip()))
                                else:
                                    sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {nullable} {default}"
                                    connection.execute(text(sql.strip()))
                    except Exception as e:
                        logger.error(f"Failed to add columns to table {table_name}: {str(e)}")
                        return False
        
        logger.info("Database schema updated successfully")
        return True
            
    except Exception as e:
        logger.error(f"Failed to update database schema: {str(e)}")
        return False


def migrate_database(engine):
    """Perform database migrations to update schema."""
    try:
        inspector = inspect(engine)
        current_time = datetime.now().isoformat()
        
        # Create new tables if they don't exist
        if 'ignored_domains' not in inspector.get_table_names():
            logger.info("Creating ignored_domains table")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE ignored_domains (
                        id INTEGER PRIMARY KEY,
                        pattern TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT
                    )
                """))
                conn.commit()
        
        if 'ignored_certificates' not in inspector.get_table_names():
            logger.info("Creating ignored_certificates table")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE ignored_certificates (
                        id INTEGER PRIMARY KEY,
                        pattern TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT
                    )
                """))
                conn.commit()
        
        # Check if domain_dns_records table needs updating
        if 'domain_dns_records' in inspector.get_table_names():
            # Check if we need to update the unique constraint
            constraints = inspector.get_unique_constraints('domain_dns_records')
            needs_update = True
            for constraint in constraints:
                if 'value' in constraint['column_names']:
                    needs_update = False
                    break
            
            if needs_update:
                logger.info("Updating domain_dns_records table with new unique constraint")
                with engine.connect() as conn:
                    # Create new table with updated constraint
                    conn.execute(text("""
                        CREATE TABLE domain_dns_records_new (
                            id INTEGER PRIMARY KEY,
                            domain_id INTEGER REFERENCES domains(id),
                            record_type VARCHAR NOT NULL,
                            name VARCHAR NOT NULL,
                            value VARCHAR NOT NULL,
                            ttl INTEGER DEFAULT 3600,
                            priority INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE (domain_id, record_type, name, value)
                        )
                    """))
                    
                    # Copy existing data
                    conn.execute(text("""
                        INSERT INTO domain_dns_records_new
                        SELECT DISTINCT id, domain_id, record_type, name, value, ttl, priority, created_at, updated_at
                        FROM domain_dns_records
                    """))
                    
                    # Drop old table
                    conn.execute(text("DROP TABLE domain_dns_records"))
                    
                    # Rename new table
                    conn.execute(text("ALTER TABLE domain_dns_records_new RENAME TO domain_dns_records"))
                    
                    conn.commit()
                    logger.info("Successfully updated domain_dns_records table")
        
        # Check if certificates table exists and perform existing migrations
        if 'certificates' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('certificates')]
            
            # Add chain_valid column if it doesn't exist
            if 'chain_valid' not in columns:
                logger.info("Adding chain_valid column to certificates table")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN chain_valid BOOLEAN DEFAULT FALSE"))
                    conn.commit()
            
            # Add created_at column if it doesn't exist
            if 'created_at' not in columns:
                logger.info("Adding created_at column to certificates table")
                with engine.connect() as conn:
                    # Add column with NULL default first
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN created_at DATETIME"))
                    # Then update with current timestamp
                    conn.execute(text(f"UPDATE certificates SET created_at = '{current_time}' WHERE created_at IS NULL"))
                    conn.commit()
            
            # Add updated_at column if it doesn't exist
            if 'updated_at' not in columns:
                logger.info("Adding updated_at column to certificates table")
                with engine.connect() as conn:
                    # Add column with NULL default first
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN updated_at DATETIME"))
                    # Then update with current timestamp
                    conn.execute(text(f"UPDATE certificates SET updated_at = '{current_time}' WHERE updated_at IS NULL"))
                    conn.commit()
            
            # Add sans_scanned column if it doesn't exist
            if 'sans_scanned' not in columns:
                logger.info("Adding sans_scanned column to certificates table")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN sans_scanned BOOLEAN DEFAULT FALSE"))
                    conn.commit()
            
            # Handle JSON field migration
            with engine.connect() as conn:
                # Get all certificates
                result = conn.execute(text("SELECT id, issuer, subject, san FROM certificates"))
                for row in result:
                    try:
                        # Convert string fields to JSON if they're not already
                        issuer = row.issuer
                        subject = row.subject
                        san = row.san
                        
                        # Convert issuer
                        if issuer and not issuer.startswith('{'):
                            try:
                                issuer_dict = eval(issuer)
                                issuer = json.dumps(issuer_dict)
                            except:
                                logger.warning(f"Invalid issuer data for certificate {row.id}: {issuer}")
                                issuer = json.dumps({})
                        
                        # Convert subject
                        if subject and not subject.startswith('{'):
                            try:
                                subject_dict = eval(subject)
                                subject = json.dumps(subject_dict)
                            except:
                                logger.warning(f"Invalid subject data for certificate {row.id}: {subject}")
                                subject = json.dumps({})
                        
                        # Convert SAN
                        if san and not san.startswith('['):
                            try:
                                san_list = eval(san)
                                san = json.dumps(san_list if isinstance(san_list, list) else [])
                            except:
                                logger.warning(f"Invalid SAN data for certificate {row.id}: {san}")
                                san = json.dumps([])
                        
                        # Update the record
                        conn.execute(
                            text("UPDATE certificates SET issuer = :issuer, subject = :subject, san = :san WHERE id = :id"),
                            {"id": row.id, "issuer": issuer, "subject": subject, "san": san}
                        )
                    except Exception as e:
                        logger.error(f"Error migrating certificate {row.id}: {str(e)}")
                        raise
                
                conn.commit()
        
        logger.info("Database migration completed successfully")
    except Exception as e:
        logger.error(f"Failed to migrate database: {str(e)}")
        raise

def sync_default_ignore_patterns(engine):
    """Synchronize default ignore patterns from settings to database."""
    logger.info("Synchronizing default ignore patterns")
    try:
        from ..settings import Settings
        from ..models import IgnoredDomain, IgnoredCertificate
        from sqlalchemy.orm import Session, scoped_session, sessionmaker
        import warnings
        from sqlalchemy import exc as sa_exc
        
        settings = Settings()
        
        # Temporarily filter out SQLAlchemy warnings for transaction state
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', 
                                  category=sa_exc.SAWarning,
                                  message='.*connection that is already in a transaction.*')
            
            # Create a scoped session factory with explicit connection control
            session_factory = sessionmaker(bind=engine,
                                          expire_on_commit=False,
                                          autoflush=True)
            session = scoped_session(session_factory)()
            
            try:
                # Begin a new transaction
                session.begin()
                
                # Sync domain patterns
                default_domain_patterns = settings.get("ignore_lists.domains.default_patterns", [])
                for pattern in default_domain_patterns:
                    if not pattern or not isinstance(pattern, str) or not pattern.strip():
                        continue  # Skip invalid patterns
                    existing = session.query(IgnoredDomain).filter_by(pattern=pattern).first()
                    if not existing:
                        session.add(IgnoredDomain(pattern=pattern.strip(), reason="Default configuration pattern"))
                
                # Sync certificate patterns
                default_cert_patterns = settings.get("ignore_lists.certificates.default_patterns", [])
                for pattern in default_cert_patterns:
                    if not pattern or not isinstance(pattern, str) or not pattern.strip():
                        continue  # Skip invalid patterns
                    existing = session.query(IgnoredCertificate).filter_by(pattern=pattern).first()
                    if not existing:
                        session.add(IgnoredCertificate(pattern=pattern.strip(), reason="Default configuration pattern"))
                
                # Commit the transaction
                session.commit()
                logger.info("Successfully synchronized default ignore patterns")
                
            except Exception as e:
                # Rollback the transaction on error
                session.rollback()
                raise e
            finally:
                # Always close the session
                session.close()
                
    except Exception as e:
        logger.error(f"Failed to sync default ignore patterns: {str(e)}")
        raise


def reset_database(engine):
    """
    Reset the database by dropping and recreating all tables.
    
    WARNING: This operation will delete all data in the database.
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if reset successful, False otherwise
    """
    try:
        logger.info("Dropping all tables...")
        Base.metadata.drop_all(engine)
        logger.info("Creating new tables...")
        Base.metadata.create_all(engine)
        logger.info("Database reset completed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to reset database: {str(e)}")
        return False

# Alias for compatibility
update_schema = update_database_schema

# --- MIGRATION UTILITY: Add proxied and proxy_info columns to certificates table ---
def migrate_add_proxy_fields_to_certificates(db_path='data/certificates.db'):
    """
    Adds 'proxied' (BOOLEAN) and 'proxy_info' (TEXT) columns to the certificates table if they do not exist.
    Usage: from infra_mgmt.db.schema import migrate_add_proxy_fields_to_certificates; migrate_add_proxy_fields_to_certificates()
    """
    import sqlite3
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Check and add 'proxied' column
    cur.execute("PRAGMA table_info(certificates)")
    columns = [row[1] for row in cur.fetchall()]
    if 'proxied' not in columns:
        cur.execute("ALTER TABLE certificates ADD COLUMN proxied BOOLEAN DEFAULT 0")
        print("Added 'proxied' column to certificates table.")
    else:
        print("'proxied' column already exists.")
    # Check and add 'proxy_info' column
    cur.execute("PRAGMA table_info(certificates)")
    columns = [row[1] for row in cur.fetchall()]
    if 'proxy_info' not in columns:
        cur.execute("ALTER TABLE certificates ADD COLUMN proxy_info TEXT")
        print("Added 'proxy_info' column to certificates table.")
    else:
        print("'proxy_info' column already exists.")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Migrate: Add proxied and proxy_info columns to certificates table.")
    parser.add_argument('--db', type=str, default='data/certificates.db', help='Path to the SQLite database file')
    args = parser.parse_args()
    migrate_add_proxy_fields_to_certificates(args.db)
    print("Migration complete.")

