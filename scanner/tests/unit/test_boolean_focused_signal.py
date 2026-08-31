"""Diff-focused boolean-SQLi signal.

Blind boolean-SQLi confidence is diluted when the differing result is a tiny
fraction of a large page: whole-page similarity reads ~1.0 for both the TRUE and
FALSE responses (the DVWA report showed true_sim=1.00 vs false_sim=0.99, ~1%
apart). focused_boolean_signal strips the shared page chrome and measures the
TRUE-vs-FALSE similarity of only the region that varies, giving the adjudicator
a non-diluted discriminator. It is additive evidence and does not change
detection.
"""
from app.core.verification.response_analyzer import ResponseAnalyzer


class TestFocusedBooleanSignal:
    def test_amplifies_small_middle_difference(self):
        # Realistic varied page chrome (the content-defined chunker is built for
        # real markup, not runs of one character).
        head = "".join(f"<li><a href='/page{i}'>Menu item {i}</a></li>" for i in range(1000))
        tail = "".join(f"<footer id='f{i}'>Section {i} footer text</footer>" for i in range(1000))
        true_body = head + "<div class='result'>USER RECORD: alice (id=1) found</div>" + tail
        false_body = head + tail  # FALSE condition returns no record

        sig = ResponseAnalyzer.focused_boolean_signal(true_body, false_body)

        # The result region differs completely, so the focused similarity is low...
        assert sig["focused_true_vs_false_sim"] < 0.6
        assert sig["varying_fraction"] < 0.02
        # ...even though whole-page similarity masks it as near-identical - the
        # dilution the focused signal exists to defeat.
        whole = ResponseAnalyzer.calculate_similarity(true_body, false_body)
        assert whole > 0.85
        assert sig["focused_true_vs_false_sim"] < whole

    def test_identical_bodies_score_one_with_no_varying_region(self):
        body = "X" * 2000
        sig = ResponseAnalyzer.focused_boolean_signal(body, body)
        assert sig["focused_true_vs_false_sim"] == 1.0
        assert sig["varying_region_chars"] == 0

    def test_empty_bodies_are_safe(self):
        sig = ResponseAnalyzer.focused_boolean_signal("", "")
        assert sig["focused_true_vs_false_sim"] == 1.0
        assert sig["page_chars"] == 0
