from semiautorecon.plugins import PortScan
from semiautorecon.config import config

class VulnPortScan(PortScan):

        def __init__(self):
                super().__init__()
                self.name = 'nmap vulners script'
                self.description = 'Execute an Nmap script named vulners to find known vulnerabilities.'
                self.type = 'tcp'
                self.tags = ['default', 'default-port-scan', 'tcp']
                self.priority = 0

        async def run(self, target):
                if target.ports: # Don't run this plugin if there are custom ports.
                        return []

                if config['proxychains']:
                        traceroute_os = ''
                else:
                        traceroute_os = ' -A --osscan-guess'

                process, stdout, stderr = await target.execute('nmap {nmap_extra} -sV --script vuln' + traceroute_os + ' -oN "{scandir}/nmap_vuln.txt" -oX "{scandir}/xml/nmap_vuln.xml" {address}', blocking=False)
                services = await target.extract_services(stdout)
                await process.wait()
                return services
