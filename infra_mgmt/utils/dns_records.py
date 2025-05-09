import dns.resolver
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from infra_mgmt.models import DomainDNSRecord, IgnoredDomain
from infra_mgmt.utils.ignore_list import IgnoreListUtil

class DNSRecordUtil:
    """
    Utility class for DNS record fetching and processing.
    """
    @staticmethod
    def get_dns_records(domain: str, resolver_config: dict = None) -> List[Dict]:
        """
        Fetch DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA).
        Args:
            domain (str): Domain to query
            resolver_config (dict, optional): Resolver settings (timeout, nameservers, etc)
        Returns:
            List[dict]: List of DNS record dicts
        """
        logger = logging.getLogger(__name__)
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        records = []
        resolver = dns.resolver.Resolver()
        if resolver_config:
            if 'timeout' in resolver_config:
                resolver.timeout = resolver_config['timeout']
                resolver.lifetime = resolver_config['timeout']
            if 'nameservers' in resolver_config:
                resolver.nameservers = resolver_config['nameservers']
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    record = {
                        'type': record_type,
                        'name': domain,
                        'value': str(rdata).rstrip('.'),
                        'ttl': answers.ttl
                    }
                    if record_type == 'MX':
                        record['priority'] = rdata.preference
                    elif record_type == 'SOA':
                        record['primary_ns'] = str(rdata.mname).rstrip('.')
                        record['email'] = str(rdata.rname).rstrip('.')
                        record['serial'] = rdata.serial
                        record['refresh'] = rdata.refresh
                        record['retry'] = rdata.retry
                        record['expire'] = rdata.expire
                        record['minimum'] = rdata.minimum
                    records.append(record)
                    logger.info(f"[DNS] Found {record_type} record for {domain}: {str(rdata)}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                logger.debug(f"[DNS] No {record_type} records found for {domain}")
                continue
            except dns.resolver.NoNameservers:
                logger.warning(f"[DNS] No nameservers could provide an answer for {record_type} records")
                continue
            except dns.resolver.Timeout:
                logger.warning(f"[DNS] Timeout querying {record_type} records for {domain}")
                continue
            except Exception as e:
                logger.exception(f"[DNS] Unexpected error querying {record_type} records for {domain}: {str(e)}")
                continue
        if not records:
            logger.warning(f"[DNS] No DNS records found for {domain}")
        else:
            logger.info(f"[DNS] Found {len(records)} total records for {domain}")
        return records

    @staticmethod
    def process_dns_records(session, domain_obj, dns_records: List[Dict], scan_queue: Optional[Set[Tuple[str, int]]] = None, port: int = 443):
        """
        Process DNS records for a domain and update the database. Optionally add CNAMEs to scan queue.
        Args:
            session: SQLAlchemy session
            domain_obj: Domain SQLAlchemy object
            dns_records (List[dict]): List of DNS record dicts
            scan_queue (Optional[set]): Optional scan queue to add CNAMEs
            port (int): Port for new scan targets
        """
        logger = logging.getLogger(__name__)
        if not dns_records:
            return
        logger.info(f"[DNS] Processing {len(dns_records)} DNS records for {domain_obj.domain_name}")
        existing_records = session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
        existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
        updated_records = set()
        for record in dns_records:
            record_key = (record['type'], record['name'], record['value'])
            updated_records.add(record_key)
            # CNAME scan queue logic
            if record['type'] == 'CNAME' and scan_queue is not None:
                cname_target = record['value'].rstrip('.')
                is_ignored, reason = IgnoreListUtil.is_domain_ignored(session, cname_target)
                if is_ignored:
                    logger.info(f"[SCAN] Skipping CNAME target {cname_target} - {reason}")
                else:
                    scan_queue.add((cname_target, port))
                    logger.info(f"[SCAN] Added CNAME target to queue: {cname_target}:{port}")
            if record_key in existing_map:
                # Update existing record
                existing_record = existing_map[record_key]
                existing_record.ttl = record['ttl']
                existing_record.priority = record.get('priority')
                existing_record.updated_at = datetime.now()
                logger.debug(f"[DNS] Updated record: {record_key}")
            else:
                # Add new record
                dns_record = DomainDNSRecord(
                    domain_id=domain_obj.id,
                    record_type=record['type'],
                    name=record['name'],
                    value=record['value'],
                    ttl=record['ttl'],
                    priority=record.get('priority'),
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(dns_record)
                logger.debug(f"[DNS] Added new record: {record_key}")
        # Remove old records
        for key, record in existing_map.items():
            if key not in updated_records:
                session.delete(record)
                logger.debug(f"[DNS] Removed old record: {key}")
        session.flush()
        logger.info(f"[DNS] Successfully processed {len(dns_records)} records for {domain_obj.domain_name}") 