load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', 'decode', 'encode')
load('net', 'ip_address')
load('http', http_get='get')
load('uuid', 'new_uuid')

# Base API URL and pagination settings
INFOBLOX_API_URL = 'https://csp.infoblox.com/api'
PAGE_LIMIT = 1000

# Helper to build a NetworkInterface object

def build_network_interface(ips, mac=None):
    ip4s, ip6s = [], []
    for ip in ips[:99]:
        addr = ip_address(ip)
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)
    if mac:
        return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)

# Build ImportAsset objects from IPAM address list

def build_ipam_assets(addresses):
    assets = []
    for rec in addresses:
        addr = rec.get('address')
        if not addr:
            continue
        raw_mac = rec.get('hwaddr') or ''
        mac = raw_mac if raw_mac else None
        ni = build_network_interface([addr], mac=mac)

        dhcp = rec.get('dhcp_info') or {}
        names = rec.get('names') or []
        hostnames = [n.get('name') for n in names if n.get('name')]

        assets.append(
            ImportAsset(
                id=str(rec.get('id') or new_uuid()),
                hostnames=hostnames,
                networkInterfaces=[ni],
                customAttributes={
                    'protocol':     rec.get('protocol'),
                    'parent':       rec.get('parent'),
                    'usage':        rec.get('usage') or [],
                    'tags':         rec.get('tags') or {},
                    'created_at':   rec.get('created_at'),
                    'updated_at':   rec.get('updated_at'),
                    'comment':      rec.get('comment'),
                    'host':         rec.get('host'),
                    'interface':    rec.get('interface'),
                    'range':        rec.get('range'),
                    'space':        rec.get('space'),
                    'state':        rec.get('state'),
                    'disable_dhcp': dhcp.get('disable_dhcp'),
                    'dhcp_start':   dhcp.get('start'),
                    'dhcp_end':     dhcp.get('end'),
                    'dhcp_type':    dhcp.get('lease_type'),
                    'compartment_id': rec.get('compartment_id'),
                    'discovery_attrs': rec.get('discovery_attrs') or {},
                    'discovery_metadata': rec.get('discovery_metadata') or {},
                    'external_keys': rec.get('external_keys') or {},
                    'hwaddr': rec.get('hwaddr'),
                    'names': rec.get('names') or [],
                    # full DHCP fields:
                    'dhcp_client_hostname':   dhcp.get('client_hostname'),
                    'dhcp_client_hwaddr':     dhcp.get('client_hwaddr'),
                    'dhcp_client_id':         dhcp.get('client_id'),
                    'dhcp_preferred_lifetime': dhcp.get('preferred_lifetime'),
                    'dhcp_remain':            dhcp.get('remain'),
                    'dhcp_state':             dhcp.get('state'),
                    'dhcp_state_ts':          dhcp.get('state_ts'),
                    'dhcp_fingerprint':       dhcp.get('fingerprint'),
                    'dhcp_iaid':              dhcp.get('iaid'),
                                }
            )
        )
    return assets

# Main entrypoint with pagination

def main(**kwargs):
    token = kwargs.get('access_secret') or ''
    if not token:
        print('Missing Infoblox API token')
        return None

    offset = 0
    all_records = []
    while True:
        url = '{}/ddi/v1/ipam/address?_limit={}&_offset={}'.format(
            INFOBLOX_API_URL, PAGE_LIMIT, offset
        )
        resp = http_get(url, headers={
            'Content-Type': 'application/json',
            'Authorization': 'Token ' + token
        })
        if resp.status_code != 200:
            print('IPAM fetch error', resp.status_code)
            return None
        page = decode(resp.body).get('results', [])
        if not page:
            break
        all_records.extend(page)
        if len(page) < PAGE_LIMIT:
            break
        offset += PAGE_LIMIT
    return build_ipam_assets(all_records)