"""
Tests for enhanced change tracking functionality with edit/delete capabilities.
"""
import pytest
from datetime import datetime, timedelta, date
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, CertificateTracking
from infra_mgmt.services.CertificateService import CertificateService
import json

@pytest.fixture
def engine():
    """Create a SQLite in-memory database"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine):
    """Create a new database session for a test"""
    with Session(engine) as session:
        yield session

@pytest.fixture
def certificate(session):
    """Create a test certificate"""
    cert = Certificate(
        serial_number="test_serial_123",
        thumbprint="test_thumbprint_456",
        common_name="example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=90),
        issuer=json.dumps({"commonName": "Test CA"}),
        subject=json.dumps({"commonName": "example.com"})
    )
    session.add(cert)
    session.commit()
    return cert

@pytest.fixture
def tracking_entry(session, certificate):
    """Create a test tracking entry"""
    entry = CertificateTracking(
        certificate_id=certificate.id,
        change_number="CHG001234",
        planned_change_date=datetime.now() + timedelta(days=30),
        status="Pending",
        notes="Initial certificate renewal",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(entry)
    session.commit()
    return entry

class TestChangeTrackingService:
    """Test the enhanced CertificateService methods for tracking entries."""
    
    def test_update_tracking_entry_success(self, session, tracking_entry):
        """Test successful tracking entry update."""
        service = CertificateService()
        
        new_change_number = "CHG005678"
        new_planned_date = datetime.now() + timedelta(days=45)
        new_status = "In Progress"
        new_notes = "Updated renewal plan - extended timeline"
        
        result = service.update_tracking_entry(
            tracking_entry.id, tracking_entry.certificate_id, new_change_number, new_planned_date,
            new_status, new_notes, session
        )
        
        assert result['success'] is True
        
        # Verify the entry was updated
        session.refresh(tracking_entry)
        assert tracking_entry.change_number == new_change_number
        assert tracking_entry.planned_change_date == new_planned_date
        assert tracking_entry.status == new_status
        assert tracking_entry.notes == new_notes
        assert tracking_entry.updated_at > tracking_entry.created_at
    
    def test_update_tracking_entry_not_found(self, session):
        """Test update_tracking_entry when entry doesn't exist."""
        service = CertificateService()
        
        result = service.update_tracking_entry(
            99999, None, "CHG001", datetime.now(), "Pending", "Test notes", session
        )
        
        assert result['success'] is False
        assert "Tracking entry not found" in result['error']
    
    def test_update_tracking_entry_with_none_values(self, session, tracking_entry):
        """Test updating tracking entry with None values for optional fields."""
        service = CertificateService()
        
        result = service.update_tracking_entry(
            tracking_entry.id, tracking_entry.certificate_id, "CHG009999", None, "Completed", None, session
        )
        
        assert result['success'] is True
        
        # Verify the entry was updated
        session.refresh(tracking_entry)
        assert tracking_entry.change_number == "CHG009999"
        assert tracking_entry.planned_change_date is None
        assert tracking_entry.status == "Completed"
        assert tracking_entry.notes is None
    
    def test_delete_tracking_entry_success(self, session, tracking_entry):
        """Test successful tracking entry deletion."""
        service = CertificateService()
        entry_id = tracking_entry.id
        
        result = service.delete_tracking_entry(entry_id, session)
        
        assert result['success'] is True
        
        # Verify the entry was deleted
        deleted_entry = session.query(CertificateTracking).filter_by(id=entry_id).first()
        assert deleted_entry is None
    
    def test_delete_tracking_entry_not_found(self, session):
        """Test delete_tracking_entry when entry doesn't exist."""
        service = CertificateService()
        
        result = service.delete_tracking_entry(99999, session)
        
        assert result['success'] is False
        assert "Tracking entry not found" in result['error']
    
    def test_multiple_tracking_entries_management(self, session, certificate):
        """Test managing multiple tracking entries for a certificate."""
        service = CertificateService()
        
        # Create multiple tracking entries
        entry1 = CertificateTracking(
            certificate_id=certificate.id,
            change_number="CHG001",
            planned_change_date=datetime.now() + timedelta(days=30),
            status="Pending",
            notes="First renewal attempt"
        )
        entry2 = CertificateTracking(
            certificate_id=certificate.id,
            change_number="CHG002",
            planned_change_date=datetime.now() + timedelta(days=60),
            status="Pending",
            notes="Backup renewal plan"
        )
        session.add_all([entry1, entry2])
        session.commit()
        
        # Update first entry
        result1 = service.update_tracking_entry(
            entry1.id, entry1.certificate_id, "CHG001_UPDATED", datetime.now() + timedelta(days=35),
            "In Progress", "Updated first attempt", session
        )
        assert result1['success'] is True
        
        # Delete second entry
        result2 = service.delete_tracking_entry(entry2.id, session)
        assert result2['success'] is True
        
        # Verify only first entry remains and is updated
        remaining_entries = session.query(CertificateTracking).filter_by(
            certificate_id=certificate.id
        ).all()
        assert len(remaining_entries) == 1
        assert remaining_entries[0].change_number == "CHG001_UPDATED"
        assert remaining_entries[0].status == "In Progress"

class TestChangeTrackingDataIntegrity:
    """Test data integrity and relationships in change tracking."""
    
    def test_tracking_entry_relationship_preserved(self, session, certificate, tracking_entry):
        """Test that certificate relationship is preserved during updates."""
        service = CertificateService()
        
        # Update the tracking entry
        result = service.update_tracking_entry(
            tracking_entry.id, tracking_entry.certificate_id, "CHG_UPDATED", datetime.now(), "Completed", "Done", session
        )
        
        assert result['success'] is True
        
        # Verify relationship is still intact
        session.refresh(tracking_entry)
        assert tracking_entry.certificate_id == certificate.id
        assert tracking_entry.certificate == certificate
    
    def test_cascade_behavior_on_certificate_deletion(self, session, certificate, tracking_entry):
        """Test that tracking entries are properly handled when certificate is deleted."""
        cert_id = certificate.id
        entry_id = tracking_entry.id
        
        # Delete the certificate
        session.delete(certificate)
        session.commit()
        
        # Verify tracking entry is also deleted (cascade delete)
        deleted_entry = session.query(CertificateTracking).filter_by(id=entry_id).first()
        assert deleted_entry is None
    
    def test_tracking_entry_audit_trail(self, session, tracking_entry):
        """Test that audit trail (created_at, updated_at) is properly maintained."""
        service = CertificateService()
        original_created_at = tracking_entry.created_at
        original_updated_at = tracking_entry.updated_at
        
        # Wait a moment to ensure timestamp difference
        import time
        time.sleep(0.01)
        
        # Update the entry
        result = service.update_tracking_entry(
            tracking_entry.id, tracking_entry.certificate_id, "CHG_AUDIT_TEST", datetime.now(), "Updated", "Audit test", session
        )
        
        assert result['success'] is True
        
        # Verify audit trail
        session.refresh(tracking_entry)
        assert tracking_entry.created_at == original_created_at  # Should not change
        assert tracking_entry.updated_at > original_updated_at  # Should be updated

class TestChangeTrackingEdgeCases:
    """Test edge cases and error conditions in change tracking."""
    
    def test_update_tracking_entry_with_invalid_status(self, session, tracking_entry):
        """Test updating tracking entry with various status values."""
        service = CertificateService()
        
        # Test with valid statuses
        valid_statuses = ["Pending", "In Progress", "Completed", "Cancelled", "On Hold"]
        for status in valid_statuses:
            result = service.update_tracking_entry(
                tracking_entry.id, tracking_entry.certificate_id, f"CHG_{status}", datetime.now(), status, f"Status: {status}", session
            )
            assert result['success'] is True
            
            session.refresh(tracking_entry)
            assert tracking_entry.status == status
    
    def test_update_tracking_entry_with_long_text(self, session, tracking_entry):
        """Test updating tracking entry with long text fields."""
        service = CertificateService()
        
        long_change_number = "CHG" + "X" * 100  # Very long change number
        long_notes = "This is a very long note. " * 100  # Very long notes
        
        result = service.update_tracking_entry(
            tracking_entry.id, tracking_entry.certificate_id, long_change_number, datetime.now(), "Pending", long_notes, session
        )
        
        # Should succeed (assuming database can handle the length)
        assert result['success'] is True
        
        session.refresh(tracking_entry)
        assert tracking_entry.change_number == long_change_number
        assert tracking_entry.notes == long_notes
    
    def test_concurrent_tracking_entry_updates(self, session, certificate):
        """Test handling of concurrent updates to tracking entries."""
        service = CertificateService()
        
        # Create a tracking entry
        entry = CertificateTracking(
            certificate_id=certificate.id,
            change_number="CHG_CONCURRENT",
            planned_change_date=datetime.now(),
            status="Pending",
            notes="Concurrent test"
        )
        session.add(entry)
        session.commit()
        
        # Simulate concurrent updates (in real scenario, this would be different sessions)
        result1 = service.update_tracking_entry(
            entry.id, entry.certificate_id, "CHG_UPDATE1", datetime.now(), "In Progress", "Update 1", session
        )
        assert result1['success'] is True
        
        # Second update should also succeed (last one wins)
        result2 = service.update_tracking_entry(
            entry.id, entry.certificate_id, "CHG_UPDATE2", datetime.now(), "Completed", "Update 2", session
        )
        assert result2['success'] is True
        
        # Verify final state
        session.refresh(entry)
        assert entry.change_number == "CHG_UPDATE2"
        assert entry.status == "Completed"
        assert entry.notes == "Update 2"
