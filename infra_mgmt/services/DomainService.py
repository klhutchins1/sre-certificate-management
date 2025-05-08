from datetime import datetime
from collections import defaultdict
from ..models import Domain, IgnoredDomain
from sqlalchemy.exc import SQLAlchemyError

class VirtualDomain:
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.registrar = None
        self.registration_date = None
        self.expiration_date = None
        self.owner = None
        self.is_active = True
        self.updated_at = datetime.now()
        self.certificates = []
        self.dns_records = []

class DomainService:
    @staticmethod
    def get_domain_hierarchy(domains):
        root_domains_dict = {}
        domain_tree = defaultdict(list)
        all_domain_names = {domain.domain_name for domain in domains}
        def get_parent_domain(domain_name):
            parts = domain_name.split('.')
            if len(parts) > 2:
                return '.'.join(parts[1:])
            return None
        potential_parents = set()
        for domain in domains:
            parent = get_parent_domain(domain.domain_name)
            if parent:
                potential_parents.add(parent)
        for domain in domains:
            parent_name = get_parent_domain(domain.domain_name)
            if parent_name:
                if parent_name in all_domain_names:
                    domain_tree[parent_name].append(domain)
                else:
                    if parent_name in potential_parents:
                        domain_tree[parent_name].append(domain)
                    else:
                        root_domains_dict[domain.domain_name] = domain
            else:
                root_domains_dict[domain.domain_name] = domain
        for parent_name in potential_parents:
            if parent_name not in all_domain_names and domain_tree[parent_name]:
                root_domains_dict[parent_name] = None
        for parent_name in domain_tree:
            domain_tree[parent_name].sort(key=lambda d: d.domain_name)
        root_domains = sorted(
            [d for d in root_domains_dict.values() if d is not None],
            key=lambda d: d.domain_name
        )
        virtual_roots = sorted(
            [name for name, d in root_domains_dict.items() if d is None]
        )
        for name in virtual_roots:
            root_domains.append(VirtualDomain(name))
        return root_domains, domain_tree

    @staticmethod
    def get_root_domain_info(domain_name, domains):
        parts = domain_name.split('.')
        if len(parts) > 2:
            root_name = '.'.join(parts[-2:])
            root_domain = next((d for d in domains if d.domain_name == root_name), None)
            return root_domain
        return None

    @staticmethod
    def delete_domain(session, domain):
        try:
            session.delete(domain)
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def add_to_ignore_list(session, domain_name):
        try:
            existing = session.query(IgnoredDomain).filter_by(pattern=domain_name).first()
            if existing:
                return {'success': False, 'error': f"Domain '{domain_name}' is already in the ignore list"}
            ignored = IgnoredDomain(
                pattern=domain_name,
                reason=f"Added from domain view",
                created_at=datetime.now()
            )
            session.add(ignored)
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
