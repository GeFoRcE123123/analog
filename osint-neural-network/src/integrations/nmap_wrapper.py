import nmap
from typing import Dict, Any, List


class NmapWrapper:
    """
    Упрощенная обертка для выполнения Nmap сканирования.
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_host(self, target: str, arguments: str = "-sV -T4") -> Dict[str, Any]:
        """Запуск сканирования хоста."""
        result = self.scanner.scan(hosts=target, arguments=arguments)
        return result

    def list_open_ports(self, scan_result: Dict[str, Any]) -> Dict[str, List[int]]:
        """Извлечение открытых портов из результата сканирования."""
        open_ports = {}
        for host, data in scan_result.get('scan', {}).items():
            ports = []
            for proto in data.get('tcp', {}):
                if data['tcp'][proto].get('state') == 'open':
                    ports.append(proto)
            open_ports[host] = sorted(ports)
        return open_ports
