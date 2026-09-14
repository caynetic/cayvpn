import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from cayvpn.config import Settings
from cayvpn.db import Database
from cayvpn.models import EgressProfile, IngressEndpoint, ManagedNode


class DatabaseInitializationTests(unittest.TestCase):
    def test_defaults_wait_for_an_existing_writer_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.create_schema()

            blocking_connection = database.engine.connect()
            blocking_session = Session(
                bind=blocking_connection,
                expire_on_commit=False,
            )
            blocking_connection.exec_driver_sql("BEGIN IMMEDIATE")
            blocking_session.add(
                ManagedNode(id=1, install_state="unverified")
            )
            blocking_session.flush()

            contender = Database(settings)
            initialization_started = Event()

            def note_initialization_statement(
                _connection,
                _cursor,
                statement,
                _parameters,
                _context,
                _executemany,
            ):
                normalized = " ".join(statement.upper().split())
                if (
                    normalized == "BEGIN IMMEDIATE"
                    or "FROM MANAGED_NODES" in normalized
                ):
                    initialization_started.set()

            event.listen(
                contender.engine,
                "before_cursor_execute",
                note_initialization_statement,
            )

            try:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        contender.initialize_defaults,
                        settings,
                    )
                    reached_database = initialization_started.wait(timeout=3)
                    blocking_connection.commit()
                    self.assertTrue(
                        reached_database,
                        "The competing initializer never reached the database",
                    )
                    future.result(timeout=10)
            finally:
                if blocking_connection.in_transaction():
                    blocking_connection.rollback()
                blocking_session.close()
                blocking_connection.close()
                contender.close()

            with database.session() as session:
                self.assertEqual(
                    len(session.scalars(select(ManagedNode)).all()),
                    1,
                )
                self.assertEqual(
                    len(session.scalars(select(IngressEndpoint)).all()),
                    3,
                )
                self.assertEqual(
                    len(session.scalars(select(EgressProfile)).all()),
                    1,
                )
            database.close()


if __name__ == "__main__":
    unittest.main()
