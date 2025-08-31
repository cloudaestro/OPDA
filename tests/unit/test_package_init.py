"""Test package initialization and metadata."""


import opda


def test_package_metadata() -> None:
    """Test that package metadata is correctly defined."""
    assert hasattr(opda, "__version__")
    assert hasattr(opda, "__author__")
    assert hasattr(opda, "__email__")
    assert hasattr(opda, "__description__")

    # Version should be a string
    assert isinstance(opda.__version__, str)
    assert len(opda.__version__) > 0

    # Author and email should be strings
    assert isinstance(opda.__author__, str)
    assert isinstance(opda.__email__, str)
    assert isinstance(opda.__description__, str)

    # Email should contain @ symbol
    assert "@" in opda.__email__


def test_version_format() -> None:
    """Test that version follows semantic versioning format."""
    version = opda.__version__

    # Should be either X.Y.Z or X.Y.Z-dev
    parts = version.replace("-dev", "").split(".")
    assert len(parts) == 3

    # Each part should be numeric
    for part in parts:
        assert part.isdigit()


def test_package_imports() -> None:
    """Test that main package can be imported without errors."""
    # This test passes if no ImportError is raised
    import opda
    import opda.analysis
    import opda.cli
    import opda.client
    import opda.config
    import opda.models
    import opda.policies
    import opda.remediation
    import opda.reports
    import opda.storage
    import opda.utils

    # All imports should succeed
    assert opda is not None
