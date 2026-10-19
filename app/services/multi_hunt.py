"""One rule, every client: a hunt per client, never a hunt across clients.

The data of two clients is never mixed. Running the same rule for several clients therefore means one separate hunt for each
client, on that client's own active connections, and one result line for each. A client without an active connection is
reported as skipped, and a client whose hunt fails does not stop the others."""
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional, Sequence


@dataclass
class ClientHunt:
    client_id: object
    client_name: str
    status: str                      # completed | failed | skipped
    hunt_id: Optional[object] = None
    total_hits: int = 0
    note: Optional[str] = None


async def hunt_every_client(
    clients: Sequence,                                              # objects with .id and .name
    connections_of: Callable[[object], Awaitable[List]],           # client id -> ids of its active connections
    run: Callable[[object, List], Awaitable[object]],              # (client id, connection ids) -> hunt (id, status, total_hits, error)
) -> List[ClientHunt]:
    results: List[ClientHunt] = []
    for client in clients:
        connections = await connections_of(client.id)
        if not connections:
            results.append(ClientHunt(client.id, client.name, "skipped", note="no active SIEM connection"))
            continue
        try:
            hunt = await run(client.id, connections)
        except Exception as e:                                      # one client failing must not hide the others
            results.append(ClientHunt(client.id, client.name, "failed", note=str(e)[:300]))
            continue
        results.append(ClientHunt(client.id, client.name, hunt.status, hunt.id, hunt.total_hits, getattr(hunt, "error", None)))
    return results
