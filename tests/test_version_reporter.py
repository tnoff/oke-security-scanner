"""Tests for version reporting functionality."""

from datetime import datetime, timezone, timedelta
from src.version_reporter import VersionReporter
from src.registry_client import ImageVersion


class TestVersionReporter:
    """Test cases for VersionReporter class."""

    def test_format_update_entry_both_semver(self):
        """Test formatting when both current and latest are semver."""
        current = ImageVersion(tag='1.0.0', major=1, minor=0, patch=0, is_semver=True)
        latest = ImageVersion(tag='1.2.3', major=1, minor=2, patch=3, is_semver=True)

        result = {
            'image': 'myregistry/myapp:1.0.0',
            'update_info': {
                'current': current,
                'latest': latest,
                'is_major_update': False,
                'major_diff': 0,
                'minor_diff': 2,
                'patch_diff': 3,
            }
        }

        lines = VersionReporter._format_update_entry(result)

        assert 'Image:   myregistry/myapp:1.0.0' in lines
        assert 'Current: 1.0.0 (tag: 1.0.0)' in lines
        assert 'Latest:  1.2.3 (tag: 1.2.3)' in lines
        assert 'Change:  +2 minor, +3 patch' in lines

    def test_format_update_entry_both_non_semver(self):
        """Test formatting when both current and latest are commit hashes."""
        current_date = datetime.now(timezone.utc) - timedelta(days=10)
        latest_date = datetime.now(timezone.utc) - timedelta(days=2)

        current = ImageVersion(tag='abc123', is_semver=False, created_at=current_date)
        latest = ImageVersion(tag='def456', is_semver=False, created_at=latest_date)

        result = {
            'image': 'myregistry/myapp:abc123',
            'update_info': {
                'current': current,
                'latest': latest,
                'is_major_update': False,
                'major_diff': 0,
                'minor_diff': 0,
                'patch_diff': 0,
            }
        }

        lines = VersionReporter._format_update_entry(result)

        assert 'Image:   myregistry/myapp:abc123' in lines
        assert 'Current: abc123' in lines
        assert 'Latest:  def456' in lines
        assert 'Age:     Current is 10 days old, latest is 2 days old' in lines
        assert 'Change:  Update is 8 days newer' in lines

    def test_format_update_entry_non_semver_to_semver_with_alternate(self):
        """Test formatting when current is commit hash, latest is semver with alternate tag."""
        current_date = datetime.now(timezone.utc) - timedelta(days=10)
        latest_date = datetime.now(timezone.utc) - timedelta(days=2)

        current = ImageVersion(tag='abc123', is_semver=False, created_at=current_date)
        latest = ImageVersion(tag='1.0.0', major=1, minor=0, patch=0, is_semver=True, created_at=latest_date)

        result = {
            'image': 'myregistry/myapp:abc123',
            'update_info': {
                'current': current,
                'latest': latest,
                'alternate_tag': 'def456',  # Commit hash corresponding to v1.0.0
                'is_major_update': False,
                'major_diff': 0,
                'minor_diff': 0,
                'patch_diff': 0,
            }
        }

        lines = VersionReporter._format_update_entry(result)

        assert 'Image:   myregistry/myapp:abc123' in lines
        assert 'Current: abc123' in lines
        assert 'Latest:  def456 (version 1.0.0)' in lines
        assert 'Age:     Current is 10 days old, latest is 2 days old' in lines

    def test_format_update_entry_non_semver_to_semver_without_alternate(self):
        """Test formatting when current is commit hash, latest is semver without alternate tag."""
        current_date = datetime.now(timezone.utc) - timedelta(days=10)
        latest_date = datetime.now(timezone.utc) - timedelta(days=2)

        current = ImageVersion(tag='abc123', is_semver=False, created_at=current_date)
        latest = ImageVersion(tag='1.0.0', major=1, minor=0, patch=0, is_semver=True, created_at=latest_date)

        result = {
            'image': 'myregistry/myapp:abc123',
            'update_info': {
                'current': current,
                'latest': latest,
                'alternate_tag': None,  # No matching commit hash found
                'is_major_update': False,
                'major_diff': 0,
                'minor_diff': 0,
                'patch_diff': 0,
            }
        }

        lines = VersionReporter._format_update_entry(result)

        assert 'Image:   myregistry/myapp:abc123' in lines
        assert 'Current: abc123' in lines
        assert 'Latest:  1.0.0 (version 1.0.0)' in lines
        assert 'Age:     Current is 10 days old, latest is 2 days old' in lines

    def test_generate_report_with_updates(self):
        """Test generating full report with multiple updates."""
        current = ImageVersion(tag='1.0.0', major=1, minor=0, patch=0, is_semver=True)
        latest = ImageVersion(tag='2.0.0', major=2, minor=0, patch=0, is_semver=True)

        update_results = [
            {
                'image': 'myregistry/app1:1.0.0',
                'update_info': {
                    'current': current,
                    'latest': latest,
                    'is_major_update': True,
                    'major_diff': 1,
                    'minor_diff': 0,
                    'patch_diff': 0,
                }
            }
        ]

        report = VersionReporter.generate_report(update_results)

        assert 'Image Version Update Report' in report
        assert 'Total images with updates available: 1' in report
        assert 'MAJOR updates: 1' in report
        assert 'MAJOR VERSION UPDATES' in report

    def test_generate_report_no_updates(self):
        """Test generating report when no updates available."""
        report = VersionReporter.generate_report([])

        assert 'No version updates found' in report

    def test_log_summary(self):
        """Test log_summary doesn't crash with various inputs."""
        current = ImageVersion(tag='1.0.0', major=1, minor=0, patch=0, is_semver=True)
        latest = ImageVersion(tag='1.1.0', major=1, minor=1, patch=0, is_semver=True)

        update_results = [
            {
                'image': 'myregistry/app1:1.0.0',
                'update_info': {
                    'current': current,
                    'latest': latest,
                    'is_major_update': False,
                    'major_diff': 0,
                    'minor_diff': 1,
                    'patch_diff': 0,
                }
            }
        ]

        # Should not raise any exceptions
        VersionReporter.log_summary(update_results)
        VersionReporter.log_summary([])


class TestCleanupReporter:
    """Test cases for CleanupReporter class."""

    def test_generate_report_with_recommendations(self):
        """Test generating cleanup report with recommendations."""
        from src.version_reporter import CleanupReporter

        cleanup_recommendations = {
            'test.ocir.io/namespace/myapp': {
                'registry': 'test.ocir.io',
                'repository': 'namespace/myapp',
                'tags_in_use': ['abc123', 'def456'],
                'tags_to_keep': ['ghi789', 'jkl012'],
                'tags_to_delete': [
                    {'tag': 'old123', 'created_at': datetime(2024, 1, 1, tzinfo=timezone.utc), 'age_days': 365},
                    {'tag': 'old456', 'created_at': datetime(2024, 2, 1, tzinfo=timezone.utc), 'age_days': 335},
                ],
                'total_deletable': 2
            }
        }

        report = CleanupReporter.generate_report(cleanup_recommendations)

        assert 'OCIR Image Cleanup Recommendations' in report
        assert 'Total repositories with cleanup candidates: 1' in report
        assert 'Total deletable tags across all repositories: 2' in report
        assert 'namespace/myapp' in report
        assert 'Tags in use (will keep):        2' in report
        assert 'Recent tags to keep:            2' in report
        assert 'Old tags recommended for deletion: 2' in report

    def test_generate_report_no_recommendations(self):
        """Test generating cleanup report when no recommendations."""
        from src.version_reporter import CleanupReporter

        report = CleanupReporter.generate_report({})

        assert 'No OCIR cleanup recommendations' in report

    def test_log_summary(self):
        """Test log_summary doesn't crash."""
        from src.version_reporter import CleanupReporter

        cleanup_recommendations = {
            'test.ocir.io/namespace/myapp': {
                'registry': 'test.ocir.io',
                'repository': 'namespace/myapp',
                'tags_in_use': ['abc123'],
                'tags_to_keep': ['ghi789'],
                'tags_to_delete': [
                    {'tag': 'old123', 'created_at': datetime(2024, 1, 1, tzinfo=timezone.utc), 'age_days': 365},
                ],
                'total_deletable': 1
            }
        }

        # Should not raise any exceptions
        CleanupReporter.log_summary(cleanup_recommendations)
        CleanupReporter.log_summary({})
