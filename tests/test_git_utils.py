import pytest

from vulnforge.git_utils import validate_commit


def test_validate_commit_accepts_hex():
    assert validate_commit("0123456789abcdef") == "0123456789abcdef"


@pytest.mark.parametrize("value", ["main", "HEAD", "a;b", "A" * 65, ""])
def test_validate_commit_rejects_non_hex(value):
    with pytest.raises(ValueError):
        validate_commit(value)
