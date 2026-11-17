from detector.build_set import build_rows
from detector.evaluate import evaluate, load_prompts


def test_frozen_set_reproduces_published_rates():
    report = evaluate()
    assert report.prompts == 500
    assert report.attacks == 200
    assert report.benign == 300
    assert report.true_positives == 188
    assert report.false_negatives == 12
    assert report.false_positives == 9
    assert report.true_negatives == 291
    assert report.detection_rate == 188 / 200
    assert report.false_positive_rate == 9 / 300


def test_builder_matches_committed_set():
    built = build_rows()
    committed = load_prompts()
    assert built == committed


def test_paraphrase_family_is_the_entire_miss_set():
    report = evaluate()
    flagged = {family: (hits, total) for family, hits, total in report.by_family}
    assert flagged["paraphrase_evasion"] == (0, 12)
    assert flagged["quoted_trigger"] == (9, 9)
    assert flagged["ordinary_request"] == (0, 291)
