"""Small Huawei Cloud DNS adapter; all cloud calls stay outside the database lock."""

import ipaddress

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import (
    CreateRecordSetRequest, CreateRecordSetRequestBody, DnsClient,
    ListPublicZonesRequest, ListRecordSetsByZoneRequest,
    UpdateRecordSetReq, UpdateRecordSetRequest,
)
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion


def record_type(ip):
    return "A" if ipaddress.ip_address(ip).version == 4 else "AAAA"


def client_for(ak, sk, region):
    return (DnsClient.new_builder()
            .with_credentials(BasicCredentials(ak, sk))
            .with_region(DnsRegion.value_of(region)).build())


def _pages(call, request, field):
    marker = None
    seen = set()
    while True:
        request.limit = 500
        request.marker = marker
        response = call(request)
        items = getattr(response, field) or []
        yield from items
        if len(items) < 500:
            return
        next_marker = items[-1].id
        if not next_marker or next_marker in seen:
            return
        seen.add(next_marker)
        marker = next_marker


def set_record(ak, sk, region, domain, target, kind=None):
    """Return (previous values, action). Never choose an ambiguous line-specific record."""
    client = client_for(ak, sk, region)
    fqdn = domain.rstrip(".").lower() + "."
    kind = kind or record_type(target)
    value = target.rstrip(".").lower() + "." if kind == "CNAME" else target
    zones = [z for z in _pages(client.list_public_zones, ListPublicZonesRequest(), "zones")
             if fqdn == z.name.lower() or fqdn.endswith("." + z.name.lower())]
    if not zones:
        raise ValueError("当前账号中未找到该域名所属的公网域名")
    zone = max(zones, key=lambda z: len(z.name))
    request = ListRecordSetsByZoneRequest(zone_id=zone.id)
    relevant = [r for r in _pages(client.list_record_sets_by_zone, request, "recordsets")
                if r.name.lower() == fqdn and r.type in ("A", "AAAA", "CNAME")]
    matches = [r for r in relevant if r.type == kind]
    if len(matches) > 1:
        raise ValueError("此域名存在多条相同类型的解析线路，请先在 DNS 控制台处理")
    if kind == "CNAME" and len(relevant) > len(matches):
        if len(relevant) != 1 or matches:
            raise ValueError("此域名存在其他 A/AAAA 记录，无法安全切换为 CNAME")
        matches = relevant
    if kind in ("A", "AAAA") and any(r.type == "CNAME" for r in relevant):
        if len(relevant) != 1:
            raise ValueError("此域名存在多条解析记录，无法安全切换记录类型")
        matches = relevant
    if matches:
        old = ", ".join(matches[0].records or [])
        if matches[0].type == kind and [str(v).lower().rstrip(".") for v in (matches[0].records or [])] == [value.lower().rstrip(".")]:
            return old, "unchanged"
        update = UpdateRecordSetRequest(zone_id=zone.id, recordset_id=matches[0].id)
        update.body = UpdateRecordSetReq(name=fqdn, type=kind,
                                         ttl=matches[0].ttl or 300, records=[value])
        client.update_record_set(update)
        return old, "updated"
    create = CreateRecordSetRequest(zone_id=zone.id)
    create.body = CreateRecordSetRequestBody(name=fqdn, type=kind, ttl=300, records=[value])
    client.create_record_set(create)
    return "—", "created"
