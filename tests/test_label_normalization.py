import pytest

from prepare_dataset import normalize_label


def test_phiusiil_labels_are_normalized_to_project_semantics():
    # UCI PhiUSIIL source labels: 0 is phishing, 1 is legitimate.
    assert normalize_label(0, "phiusiil") == 1
    assert normalize_label(1, "phiusiil") == 0


def test_project_standard_labels_remain_unchanged():
    assert normalize_label(0, "project-standard") == 0
    assert normalize_label(1, "project-standard") == 1
    assert normalize_label("phishing") == 1
    assert normalize_label("legitimate") == 0


def test_unknown_numeric_labels_are_not_guessed():
    with pytest.raises(ValueError):
        normalize_label(2, "phiusiil")
