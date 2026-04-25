import threading
import logging
import memory
from stem.descriptor import remote

__all__ = ["TorTrafficHandle"]

log = logging.getLogger(__name__)

_TOR_CONSENSUS_TIMEOUT = 15.0  # wall-clock cap for consensus download

class TorTrafficHandle():

    def __init__(self):
        if not memory.tor_nodes:
            self.get_consensus_data()

    def get_consensus_data(self) -> None:
        log.info("Downloading Tor consensus (timeout=%.0fs)", _TOR_CONSENSUS_TIMEOUT)
        exc_box: list = []

        def _fetch() -> None:
            try:
                for desc in remote.get_consensus().run():
                    memory.tor_nodes.append((desc.address, desc.or_port))
            except Exception as exc:
                exc_box.append(exc)

        t = threading.Thread(target=_fetch, daemon=True)
        t.start()
        t.join(timeout=_TOR_CONSENSUS_TIMEOUT)

        if t.is_alive():
            log.warning("Tor consensus download timed out — Tor detection disabled for this session")
        elif exc_box:
            log.warning("Unable to retrieve Tor consensus: %s", exc_box[0])
        else:
            log.info("Tor consensus: %d nodes loaded", len(memory.tor_nodes))

    def tor_traffic_detection(self) -> None:
        if memory.tor_nodes:
            for session in memory.packet_db:
                current_session = session.split("/")
                if current_session[2].isdigit() and (current_session[1], int(current_session[2])) in memory.tor_nodes:
                    memory.possible_tor_traffic.append(session)

