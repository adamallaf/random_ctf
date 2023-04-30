import requests
import socket

from requests import adapters
from urllib3.poolmanager import PoolManager


class InterfaceAdapter(adapters.HTTPAdapter):
    def __init__(self, **kwargs):
        self.iface = kwargs.pop('iface', None)
        super(InterfaceAdapter, self).__init__(**kwargs)

    def _socket_options(self):
        if self.iface is None:
            return []
        return [(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface)]

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            socket_options=self._socket_options()
        )


def session_for_iface(iface: str) -> requests.Session:
    session = requests.Session()
    for prefix in ('http://', 'https://'):
        session.mount(prefix, InterfaceAdapter(iface=iface.encode()))
    return session


def main():
    s = session_for_iface("tun0")
    #print(s.get("https://ifconfig.me").text)

    locations = []
    url = f"http://{0.0.0.0}:{0}/"
    res = s.get(url, allow_redirects=False)
    print(res.text)
    print(res.headers)
    locations.append(res.headers.get("Location")[len(url):])

    for i in range(500):
        res = s.get(url + locations[-1], allow_redirects=False)
        print(res.headers)
        print(res.text)
        if "Location" not in res.headers.keys():
            break
        locations.append(res.headers.get("Location", "")[len(url):])

    get_flag = False
    flag = ""
    for loc in locations:
        if "ETSCTF" in loc:
            get_flag = True
        if get_flag:
            flag += loc
    print(locations)
    print("-" * 40, end="\n\n")
    print(flag)


if __name__ == "__main__":
    main()
