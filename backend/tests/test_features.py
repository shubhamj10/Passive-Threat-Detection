import math

from app.enclave.features.beacon import beacon_features
from app.enclave.features.common import char_entropy, entropy_from_counts, split_domain
from app.enclave.features.dns import BigramModel, dns_features


def test_entropy():
    assert entropy_from_counts([1, 1, 1, 1]) == 2.0
    assert entropy_from_counts([5]) == 0.0
    assert math.isclose(char_entropy("abab"), 1.0)


def test_split_domain():
    assert split_domain("a.b.shop.example") == ("shop.example", "shop", "a.b")
    assert split_domain("shop.example") == ("shop.example", "shop", "")


def test_beacon_periodic_vs_random():
    periodic = beacon_features([i * 30.0 for i in range(20)], [500] * 20, [4] * 20)
    assert periodic["interval_cv"] < 0.01 and periodic["periodicity"] == 1.0
    noisy = beacon_features([0, 1, 2, 50, 51, 140, 141, 300, 301, 302], [100, 9000, 50, 700, 80, 60, 5000, 30, 20, 10],
                            [1] * 10)
    assert noisy["interval_cv"] > 1.0 and noisy["size_cv"] > 1.0


def test_dns_random_names_score_low_bigram():
    bg = BigramModel.fit(["weather", "newsportal", "shopnorth", "cloudstore", "mapservice", "photohub"] * 10)
    benign = dns_features([("www.newsportal.example", "A", "NOERROR")], bg)
    dga = dns_features([("xqzkvjwpqtrmz.example", "A", "NXDOMAIN")], bg)
    assert dga["sld_bigram_ll"] < benign["sld_bigram_ll"]
    assert dga["nx_ratio"] == 1.0


def test_dns_tunnel_features():
    bg = BigramModel.fit(["weather"])
    qs = [(f"{'mzxw6ytboi' * 5}{i}.s{i}.sync-relay.example", "TXT", "NOERROR") for i in range(20)]
    f = dns_features(qs, bg)
    assert f["max_label_len"] >= 50 and f["txt_ratio"] == 1.0 and f["unique_ratio"] == 1.0
