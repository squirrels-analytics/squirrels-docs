from typing import Any
from squirrels.arguments import ConnectionsArgs
from squirrels.connections import ConnectionProperties, ConnectionTypeEnum


def main(connections: dict[str, ConnectionProperties | Any], sqrl: ConnectionsArgs) -> None:
    """
    Define sqlalchemy engines by adding them to the "connections" dictionary
    """
    ## SQLAlchemy URL for a connection engine
    conn_str: str = sqrl.env_vars["SQLITE_URI"].format(project_path=sqrl.project_path)

    ## Assigning names to connection engines
    connections["default"] = ConnectionProperties(
        label="SQLite Expenses Database", 
        type=ConnectionTypeEnum.SQLALCHEMY, 
        uri=conn_str
    )
    