"""User-level train / validation / test split.

Whole users are assigned to one split, so no person's behaviour appears on both sides, and insiders are spread
proportionally over the splits (stratified). Only CERT users are ever split: synthetic supplement users are never
part of the held-out CERT test set.
"""
import numpy as np
import pandas as pd

SPLITS = ("train", "validation", "test")


def split_users(entity_ids: list[str], insider_entities: set[str], *, test_fraction: float = 0.30,
                validation_fraction: float = 0.15, seed: int = 42) -> pd.DataFrame:
    if not 0 < test_fraction < 1 or not 0 <= validation_fraction < 1 or test_fraction + validation_fraction >= 1:
        raise ValueError("test_fraction and validation_fraction must be fractions that leave room for training")
    rng = np.random.default_rng(seed)
    rows = []
    for group_is_insider in (True, False):
        members = sorted(e for e in set(entity_ids) if (e in insider_entities) == group_is_insider)
        rng.shuffle(members)
        n_test = round(len(members) * test_fraction)
        n_val = round(len(members) * validation_fraction)
        for i, entity in enumerate(members):
            split = "test" if i < n_test else "validation" if i < n_test + n_val else "train"
            rows.append({"entity_id": entity, "split": split, "is_insider": group_is_insider})
    return pd.DataFrame(rows).sort_values("entity_id").reset_index(drop=True)
