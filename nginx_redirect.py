import re
import requests
import socket
import time

from requests import adapters
from urllib3.poolmanager import PoolManager


url_pattern = re.compile(r"http://([0-9a-zA-Z\.]+):(\d{4})(/.+)?")


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
    ip = "0.0.0.0"
    url = f"http://{ip}:{0}/"
    res = s.get(url, allow_redirects=False)
    print(res.text)
    print(res.headers)
    locations.append(res.headers.get("Location"))

    headers = {"Host": ip}

    flagsss = []
    new_location = res.headers.get("Location")[len(url):]
    while res.status_code != 200:
        res = s.get(url + new_location, headers=headers, allow_redirects=False)
        print(res.headers)
        print(res.text)
        _location = res.headers.get("Location")
        if "Location" not in res.headers.keys():
#            print("Location Break", res.text, res.status_code, res.headers)
            break
        __re = url_pattern.findall(_location)[0]
        new_location = __re[2] if len(__re) == 3 else '/'
        new_host = __re[0]
        new_port = __re[1]
        headers["Host"] = new_host
        url = f"http://{ip}:{new_port}"
        if new_host != ip:
            flag_part = new_host
            print(flag_part)
            flagsss.append(flag_part)
        if "ETSCTF_" in res.text:
            print("ETSCTF_ Break", res.text, res.status_code, res.headers)
            break
        locations.append(_location)

    with open("flag_parts.txt", "w") as f:
        for flag__ in flagsss:
            f.write(flag__ + '\n')

    with open("all_locations.txt", "w") as f:
        for loc in locations:
            f.write(loc + '\n')

    final_flag = 'ETSCTF_' + ''.join(flagsss)
    redirect_flag = res.text[res.text.find("ETSCTF_"):res.text.find("ETSCTF_") + 40]

    print("-" * 40, end="\n\n")
    print(f"Final flag:\n{final_flag}\n")
    print(f"Last redirect flag:\n{redirect_flag}\n")


if __name__ == "__main__":
    main()
