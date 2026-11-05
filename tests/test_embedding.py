from viper.rag.embedding import PrefixEmbedder


class Recorder:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.seen += texts
        return [[0.0] for _ in texts]


def test_prefix_is_prepended_to_every_text() -> None:
    inner = Recorder()
    PrefixEmbedder(inner, "search_query: ").embed(["a", "b"])
    assert inner.seen == ["search_query: a", "search_query: b"]


def test_empty_prefix_leaves_text_unchanged() -> None:
    inner = Recorder()
    PrefixEmbedder(inner).embed(["a"])
    assert inner.seen == ["a"]
