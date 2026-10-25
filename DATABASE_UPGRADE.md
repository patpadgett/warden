# Database Upgrade Guide: Scaling Warden

Warden comes pre-configured with SQLite for "Zero-Config" ease of use. While highly performant for most homelab scenarios, you may wish to migrate to a more robust database for higher concurrency, better reliability, or cluster deployment.

## Recommended: PostgreSQL

For production environments, we recommend **PostgreSQL**. It provides the best balance of performance, reliability, and compatibility with the Python async ecosystem.

### Why PostgreSQL?
- **True Concurrency**: Unlike SQLite, which uses a database-level lock for writes, PostgreSQL allows concurrent writes to different rows/tables.
- **Advanced Indexing**: Better support for complex queries and larger datasets.
- **Reliability**: ACID compliance and robust write-ahead logging (WAL).
- **Ecosystem**: Extensive tooling for backups, monitoring, and management.

### How to Migrate (Proposed Architecture)

To support a swap from SQLite to PostgreSQL, Warden is designed around a `Database` abstraction. To implement this swap:

1. **Install Dependencies**:
   Add `asyncpg` and `SQLAlchemy` (with async support) to your environment.

2. **Implement a PostgresDatabase Class**:
   Create a new class that implements the same interface as `warden.db.Database`. 
   - Use `SQLAlchemy`'s `AsyncSession` for connection management.
   - Replace raw SQLite dialect queries with SQLAlchemy's Core expression language for cross-dialect compatibility.

3. **Update Configuration**:
   Add a `database` section to `warden.yaml`:
   ```yaml
   database:
     type: postgres
     url: postgresql+asyncpg://user:pass@localhost:5432/warden
   ```

4. **Update App Factory**:
   Modify `warden.main.create_app` to instantiate the correct database class based on the configuration.

### Other Options
- **MySQL/MariaDB**: Possible via `aiomysql`, but generally less favored in the modern Python async stack than PostgreSQL.
- **CockroachDB**: Use if you need a distributed, globally scalable database (fully compatible with the PostgreSQL wire protocol).
