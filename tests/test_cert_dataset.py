"""CERT dataset preparation: validation, mapping, labels, leakage guards, splits and the synthetic supplement.

The tests build a tiny release in CERT's file layout; they never need the real download.
"""
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml.cert import leakage, prepare as prep, synthetic
from ml.cert.labels import apply_labels, load_answer_events, load_incidents
from ml.cert.schema import (
    EVENT_COLUMNS,
    LABEL_AMBIGUOUS,
    LABEL_BENIGN,
    LABEL_MALICIOUS,
    MODEL_INPUT_COLUMNS,
    SOURCE_CERT,
    SOURCE_SYNTHETIC,
    DatasetError,
)
from ml.cert.split import split_users
from ml.cert.validate import locate_release, validate_answers, validate_release

USERS = [f"AAA{i:04d}" for i in range(1, 13)]          # AAA0001 is the insider, AAA0002 a colleague
INSIDER, COLLEAGUE = USERS[0], USERS[1]


def _id(kind: str, n: int) -> str:
    return "{" + f"{kind[:1].upper()}{n % 10}{n % 7}{n % 5}-{n:08d}-{n * 7919 % 10**8:08d}" + "}"


def _write(path: Path, header: str, rows: list[str]) -> None:
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


@pytest.fixture()
def release(tmp_path):
    """A miniature CERT r4.2-style release plus answer key. Returns (source_dir, answers_dir, ids)."""
    src = tmp_path / "r4.2"
    src.mkdir()
    ids: dict[str, str] = {}
    logon, device, http, email, files = [], [], [], [], []
    n = 0
    for u_index, user in enumerate(USERS):
        pc = f"PC-{1000 + u_index}"
        for day in range(4, 18):                        # 14 days, Jan 2010
            n += 1
            logon.append(f"{_id('l', n)},01/{day:02d}/2010 08:{u_index:02d}:00,{user},{pc},Logon")
            ids[f"logon-{user}-{day}"] = _id("l", n)
            n += 1
            files.append(f"{_id('f', n)},01/{day:02d}/2010 09:{u_index:02d}:00,{user},{pc},DOC{n}.pdf,25-50-44-46 some text content")
            ids[f"file-{user}-{day}"] = _id("f", n)
            n += 1
            http.append(f"{_id('h', n)},01/{day:02d}/2010 10:{u_index:02d}:00,{user},{pc},http://www.News.example/a/b?x=1,page words")
            ids[f"http-{user}-{day}"] = _id("h", n)
            n += 1
            email.append(f"{_id('e', n)},01/{day:02d}/2010 11:{u_index:02d}:00,{user},{pc},boss@dtaa.com;ext@partner.example,,cc@dtaa.com,"
                         f"{user.lower()}@dtaa.com,{20000 + n},1,body words")
            ids[f"email-{user}-{day}"] = _id("e", n)
            n += 1
            logon.append(f"{_id('l', n)},01/{day:02d}/2010 17:{u_index:02d}:00,{user},{pc},Logoff")
    for day, (hh, act) in {10: (22, "Connect"), 11: (1, "Disconnect")}.items():       # the insider's removable-media use
        n += 1
        device.append(f"{_id('d', n)},01/{day:02d}/2010 {hh:02d}:05:00,{INSIDER},PC-1000,{act}")
        ids[f"device-{act}"] = _id("d", n)
    _write(src / "logon.csv", "id,date,user,pc,activity", logon)
    _write(src / "device.csv", "id,date,user,pc,activity", device)
    _write(src / "http.csv", "id,date,user,pc,url,content", http)
    _write(src / "email.csv", "id,date,user,pc,to,cc,bcc,from,size,attachments,content", email)
    _write(src / "file.csv", "id,date,user,pc,filename,content", files)
    (src / "LDAP").mkdir()
    _write(src / "LDAP" / "2009-12.csv", "employee_name,user_id,email,role,business_unit,functional_unit,department,team,supervisor",
           [f"Person {u},{u},{u.lower()}@dtaa.com,Analyst,1,2 - Research,2 - Software,3 - Dev,Boss Name" for u in USERS])
    _write(src / "LDAP" / "2010-01.csv", "employee_name,user_id,email,role,business_unit,functional_unit,department,team,supervisor",
           [f"Person {u},{u},{u.lower()}@dtaa.com,{'ITAdmin' if u == INSIDER else 'Analyst'},1,2 - Research,2 - Software,3 - Dev,Boss Name"
            for u in USERS[:-1]])

    ans = tmp_path / "answers"
    (ans / "r4.2-1").mkdir(parents=True)
    _write(ans / "insiders.csv", "dataset,scenario,details,user,start,end",
           [f"4.2,1,r4.2-1-{INSIDER}.csv,{INSIDER},01/10/2010 22:00:00,01/11/2010 02:00:00"])
    listed = [
        f"device,{ids['device-Connect']},01/10/2010 22:05:00,{INSIDER},PC-1000,Connect",
        f"device,{ids['device-Disconnect']},01/11/2010 01:05:00,{INSIDER},PC-1000,Disconnect",
        f"logon,{ids[f'logon-{COLLEAGUE}-10']},01/10/2010 08:01:00,{COLLEAGUE},PC-1001,Logon",     # ambiguous: another account
        "http,{ZZZZ-00000000-00000000},01/10/2010 23:00:00," + INSIDER + ",PC-1000,http://leak.example/x,words, with, commas",  # not in data
    ]
    (ans / "r4.2-1" / f"r4.2-1-{INSIDER}.csv").write_text("\n".join(listed) + "\n", encoding="utf-8")
    return src, ans, ids


def _prepared(release, tmp_path, **kwargs):
    src, ans, ids = release
    out = tmp_path / "out"
    report = prep.prepare(src, out, answers=ans, **kwargs)
    return out, report, ids


# ------------------------------------------------------------------------------------- validation
def test_missing_required_file_gives_a_helpful_error(release):
    src, _, _ = release
    (src / "logon.csv").unlink()
    with pytest.raises(DatasetError, match=r"logon\.csv not found"):
        validate_release(src).raise_if_failed()


def test_missing_optional_source_is_skipped_with_a_warning(release):
    src, _, _ = release
    (src / "http.csv").unlink()
    report = validate_release(src)
    assert report.ok and "http" in report.sources_missing and any("http.csv" in w for w in report.warnings)


def test_missing_columns_are_named(release):
    src, _, _ = release
    (src / "device.csv").write_text("id,date,user\nx,01/01/2010 00:00:00,u\n", encoding="utf-8")
    with pytest.raises(DatasetError) as err:
        validate_release(src).raise_if_failed()
    assert "device.csv" in str(err.value) and "'pc'" in str(err.value) and "'activity'" in str(err.value)


def test_header_only_and_garbled_files_are_rejected(release):
    src, _, _ = release
    (src / "file.csv").write_text("id,date,user,pc,filename,content\n", encoding="utf-8")
    (src / "email.csv").write_bytes(b"")
    errors = " ".join(validate_release(src).errors)
    assert "no rows" in errors and "email.csv" in errors


def test_mostly_unparseable_timestamps_fail_validation_but_a_few_only_warn(release):
    src, _, _ = release
    (src / "device.csv").write_text("id,date,user,pc,activity\n" + "\n".join(f"{{D{i}}},not-a-date,u,p,Connect" for i in range(5)) + "\n",
                                    encoding="utf-8")
    assert any("do not match" in e for e in validate_release(src).errors)


def test_locate_release_accepts_parent_directory_and_rejects_missing_paths(release, tmp_path):
    src, _, _ = release
    assert locate_release(src.parent) == src
    with pytest.raises(DatasetError, match="does not exist"):
        locate_release(tmp_path / "nope")
    archive = tmp_path / "x.tar.bz2"
    archive.write_bytes(b"x")
    with pytest.raises(DatasetError, match="not a directory"):
        locate_release(archive)


def test_answer_key_validation(release, tmp_path):
    _, ans, _ = release
    assert validate_answers(ans) == ans
    with pytest.raises(DatasetError, match="does not exist"):
        validate_answers(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(DatasetError, match="insiders.csv not found"):
        validate_answers(empty)


def test_corrupt_archive_is_reported_not_crashed(tmp_path):
    bad = tmp_path / "r4.2.tar.bz2"
    bad.write_bytes(b"BZh91AY&SY not really a bzip2 stream")
    with pytest.raises(DatasetError, match="Could not extract"):
        prep.extract_archive(bad, tmp_path / "dest")


# ------------------------------------------------------------------------------------- mapping, timestamps, duplicates
def test_events_are_mapped_to_the_canonical_schema(release, tmp_path):
    out, report, ids = _prepared(release, tmp_path)
    logon = pd.read_csv(out / "events_logon.csv.gz")
    assert list(logon.columns) == list(EVENT_COLUMNS)
    assert set(logon["event_type"]) == {"logon", "logoff"} and (logon["source"] == SOURCE_CERT).all() and not logon["is_synthetic"].any()
    device = pd.read_csv(out / "events_device.csv.gz")
    assert set(device["event_type"]) == {"device_connect", "device_disconnect"} and device["removable_media"].all()
    http = pd.read_csv(out / "events_http.csv.gz")
    assert set(http["destination"]) == {"news.example"} and set(http["event_type"]) == {"web_visit"}      # host only, no path
    email = pd.read_csv(out / "events_email.csv.gz")
    assert (email["recipient_count"] == 3).all() and (email["external_recipient_count"] == 1).all()      # partner.example only
    assert set(email["attachment_count"]) == {1.0} and email["bytes"].min() >= 20000
    assert "partner.example" in email["destination"].iloc[0]
    files = pd.read_csv(out / "events_file.csv.gz")
    assert files["resource"].str.endswith(".pdf").all() and files["bytes"].isna().all()                  # size is not in the source
    assert set(files["event_type"]) == {"file_copy_removable"} and files["removable_media"].all()        # file.csv = copies to USB
    assert logon["auth_result"].isna().all()                                                             # not invented
    for name in ("content", "url", "filename", "user", "pc", "to"):
        assert name not in logon.columns and name not in http.columns


def test_timestamps_are_parsed_unchanged_and_bad_ones_rejected(release, tmp_path):
    src, ans, _ = release
    with open(src / "device.csv", "a", encoding="utf-8") as fh:
        fh.write("{BAD1-00000001-00000001},13/45/2010 99:99:99,AAA0005,PC-1,Connect\n{BAD2-00000002-00000002},,AAA0005,PC-1,Connect\n")
    out, report, _ = _prepared(release, tmp_path)
    stats = report["sources"]["device"]
    assert stats["rejected_bad_timestamp"] == 1 and stats["rejected_missing_fields"] == 1 and stats["rows_written"] == 2
    device = pd.read_csv(out / "events_device.csv.gz")
    assert device["timestamp_utc"].tolist() == ["2010-01-10T22:05:00+00:00", "2010-01-11T01:05:00+00:00"]
    assert "organisation's local clock" in json.loads((out / "dataset_report.json").read_text())["caveats"][1]


def test_rows_with_missing_ids_users_or_unknown_activity_are_rejected(release, tmp_path):
    src, _, _ = release
    with open(src / "logon.csv", "a", encoding="utf-8") as fh:
        fh.write(",01/05/2010 08:00:00,AAA0003,PC-9,Logon\n{X-1-1},01/05/2010 08:00:00,,PC-9,Logon\n{X-2-2},01/05/2010 08:00:00,AAA0003,PC-9,Reboot\n")
    _, report, _ = _prepared(release, tmp_path)
    stats = report["sources"]["logon"]
    assert stats["rejected_missing_fields"] == 2 and stats["rejected_unknown_activity"] == 1


def test_duplicate_events_are_dropped_within_and_across_chunks(release, tmp_path):
    src, _, _ = release
    lines = (src / "file.csv").read_text(encoding="utf-8").splitlines()
    (src / "file.csv").write_text("\n".join(lines + [lines[1], lines[2], lines[1]]) + "\n", encoding="utf-8")      # repeated far apart
    out, report, _ = _prepared(release, tmp_path, chunk_rows=7)
    stats = report["sources"]["file"]
    assert stats["duplicates_dropped"] == 3 and stats["rows_written"] == stats["rows_read"] - 3
    files = pd.read_csv(out / "events_file.csv.gz")
    assert not files["event_id"].duplicated().any()


def test_originals_are_never_modified_and_out_dir_cannot_be_inside_the_source(release, tmp_path):
    src, ans, _ = release
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in src.glob("*.csv")}
    _prepared(release, tmp_path)
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in src.glob("*.csv")}
    with pytest.raises(DatasetError, match="inside the original dataset"):
        prep.prepare(src, src / "processed", answers=ans)


def test_prepare_without_logon_or_unknown_source_fails_clearly(release, tmp_path):
    src, _, _ = release
    with pytest.raises(DatasetError, match="Unknown source"):
        prep.prepare(src, tmp_path / "o1", sources=["logon", "dns"])
    with pytest.raises(DatasetError, match="logon.csv is required"):
        prep.prepare(src, tmp_path / "o2", sources=["http"])


# ------------------------------------------------------------------------------------- labels
def test_labels_follow_the_answer_key_exactly(release, tmp_path):
    out, report, ids = _prepared(release, tmp_path)
    labels = pd.read_csv(out / "labels.csv").set_index("event_id")
    assert labels.loc[ids["device-Connect"], "label"] == 1 and labels.loc[ids["device-Connect"], "label_basis"] == LABEL_MALICIOUS
    assert labels.loc[ids["device-Disconnect"], "label"] == 1
    colleague = ids[f"logon-{COLLEAGUE}-10"]
    assert pd.isna(labels.loc[colleague, "label"]) and labels.loc[colleague, "label_basis"] == LABEL_AMBIGUOUS
    # the insider's other activity is NOT labelled malicious just because the user is an insider
    assert ids[f"file-{INSIDER}-10"] not in labels.index and ids[f"logon-{INSIDER}-10"] not in labels.index
    info = report["labels"]
    assert info["events_listed"] == 4 and info["events_matched_in_data"] == 3 and info["events_unmatched"] == 1
    assert info["labelled_malicious"] == 2 and info["ambiguous_excluded_from_metrics"] == 1
    assert info["malicious_events_outside_incident_window"] == 0 and info["by_scenario"][1]["insiders"] == 1


def test_apply_labels_treats_unlisted_events_as_benign_and_ambiguous_as_missing(release):
    _, ans, ids = release
    answers = load_answer_events(ans)
    labels = answers[["event_id", "label", "label_basis"]]
    result = apply_labels(pd.Series([ids["device-Connect"], ids[f"logon-{COLLEAGUE}-10"], ids[f"file-{INSIDER}-10"]]), labels)
    assert result["label"].tolist()[0] == 1.0 and pd.isna(result["label"].tolist()[1]) and result["label"].tolist()[2] == 0.0
    assert result["label_basis"].tolist() == [LABEL_MALICIOUS, LABEL_AMBIGUOUS, LABEL_BENIGN]


def test_malformed_answer_key_is_reported(release):
    _, ans, _ = release
    (ans / "r4.2-1" / f"r4.2-1-{INSIDER}.csv").write_text("this is not an observable row\n", encoding="utf-8")
    with pytest.raises(DatasetError, match="malformed"):
        load_answer_events(ans)
    (ans / "r4.2-1" / f"r4.2-1-{INSIDER}.csv").unlink()
    with pytest.raises(DatasetError, match="not found"):
        load_answer_events(ans)


def test_duplicate_answer_listings_are_counted_once(release):
    _, ans, ids = release
    path = ans / "r4.2-1" / f"r4.2-1-{INSIDER}.csv"
    path.write_text(path.read_text(encoding="utf-8") + path.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
    answers = load_answer_events(ans)
    assert answers["event_id"].is_unique and answers.attrs["duplicate_listings"] == 1
    assert [i.user for i in load_incidents(ans)] == [INSIDER]


# ------------------------------------------------------------------------------------- leakage and splits
def test_ldap_context_keeps_role_and_department_only(release, tmp_path):
    out, report, _ = _prepared(release, tmp_path)
    attributes = pd.read_csv(out / "entity_attributes.csv")
    assert list(attributes.columns) == ["entity_id", "role", "business_unit", "functional_unit", "department", "team", "snapshot"]
    assert len(attributes) == len(USERS) and set(attributes["snapshot"]) == {"2009-12", "2010-01"}      # latest snapshot wins
    insider_entity = prep.entity_for(INSIDER)
    assert attributes.set_index("entity_id").loc[insider_entity, "role"] == "ITAdmin"
    text = (out / "entity_attributes.csv").read_text()
    assert "Person" not in text and "@dtaa.com" not in text and "Boss" not in text and "AAA00" not in text
    assert any("scenario-3 insider is a system administrator" in c for c in report["caveats"])
    assert any("dense needles" in c for c in report["caveats"])


def test_event_files_contain_no_labels_or_raw_user_ids(release, tmp_path):
    out, _, _ = _prepared(release, tmp_path)
    for kind in ("logon", "device", "http", "email", "file"):
        events = pd.read_csv(out / f"events_{kind}.csv.gz")
        assert not {"label", "label_basis", "scenario", "insider_user", "user", "user_id"} & set(events.columns)
        assert not events["entity_id"].astype(str).str.contains("AAA00").any()
    identity = pd.read_csv(out / "identity_map.csv")
    assert set(identity["user_id"]) == set(USERS) and identity["entity_id"].str.startswith("E").all()
    assert set(pd.read_csv(out / "eval_metadata.csv").columns) >= {"scenario", "insider_user", "incident_file"}   # stored apart from events


def test_model_input_view_and_feature_name_guard():
    columns = list(MODEL_INPUT_COLUMNS)
    leakage.assert_no_leakage(columns)
    leakage.assert_no_leakage(["files_per_day", "after_hours_logon_rate", "external_email_bytes"])
    for bad in ("label", "scenario", "insider_user", "incident_file", "user_id", "entity_id", "split", "is_synthetic", "answer_key",
                "is_malicious_flag", "ground_truth_score"):
        with pytest.raises(leakage.LeakageError):
            leakage.assert_no_leakage(columns + [bad])
    events = pd.DataFrame({c: [1] for c in EVENT_COLUMNS})
    view = leakage.model_input_view(events)
    assert list(view.columns) == columns and not {"event_id", "entity_id", "source", "is_synthetic"} & set(view.columns)


def test_future_events_and_cross_entity_history_are_excluded():
    events = pd.DataFrame({"timestamp_utc": ["2010-01-01T08:00:00+00:00", "2010-01-02T08:00:00+00:00", "2010-01-03T08:00:00+00:00"],
                           "entity_id": ["a", "a", "b"]})
    history = leakage.history_before(events, "2010-01-02T08:00:00+00:00", "a")
    assert history["timestamp_utc"].tolist() == ["2010-01-01T08:00:00+00:00"]          # strictly earlier, same entity
    assert len(leakage.history_before(events, "2010-01-04T00:00:00+00:00")) == 3


def test_user_split_is_disjoint_stratified_and_deterministic(release, tmp_path):
    out, _, _ = _prepared(release, tmp_path)
    splits = pd.read_csv(out / "splits.csv")
    leakage.assert_disjoint_users(splits)
    assert len(splits) == len(USERS) and set(splits["split"]) <= {"train", "validation", "test"}
    again = split_users(list(splits["entity_id"]), set(splits.loc[splits["is_insider"], "entity_id"]), seed=42)
    assert again.equals(splits)
    assert not again.equals(split_users(list(splits["entity_id"]), set(splits.loc[splits["is_insider"], "entity_id"]), seed=7))
    entities = [f"E{i}" for i in range(100)]
    insiders = set(entities[:20])
    result = split_users(entities, insiders, test_fraction=0.3, validation_fraction=0.1, seed=1)
    for split, expected in (("test", 6), ("validation", 2)):                         # insiders are spread proportionally
        assert result[(result["split"] == split) & result["is_insider"]].shape[0] == expected
    with pytest.raises(ValueError):
        split_users(entities, insiders, test_fraction=0.8, validation_fraction=0.3)
    with pytest.raises(leakage.LeakageError):
        leakage.assert_disjoint_users(pd.DataFrame({"entity_id": ["a", "a"], "split": ["train", "test"]}))


def test_profile_uses_only_benign_train_users(release, tmp_path):
    out, _, _ = _prepared(release, tmp_path)
    profile = json.loads((out / "cert_profile.json").read_text())
    assert "train-split users only" in profile["basis"] and "logon" in profile["hour_of_day"]
    assert abs(sum(profile["hour_of_day"]["logon"]) - 1) < 1e-3 and profile["per_user_day"]["file_copy_removable"]["mean"] >= 1
    assert "email_size_bytes" in profile


def test_sampled_run_keeps_every_insider_and_flags_prevalence(release, tmp_path):
    out, report, _ = _prepared(release, tmp_path, sample_users=4)
    assert report["users"] == 4 and report["insiders_in_population"] == 1
    assert any("NOT representative" in c for c in report["caveats"])
    assert INSIDER in set(pd.read_csv(out / "identity_map.csv")["user_id"])


def test_without_an_answer_key_no_labels_are_produced(release, tmp_path):
    src, _, _ = release
    report = prep.prepare(src, tmp_path / "unlabelled")
    assert not (tmp_path / "unlabelled" / "labels.csv").exists()
    assert any("no supervised metric" in c for c in report["caveats"]) and report["labels"] == {"answer_key_supplied": False}


# ------------------------------------------------------------------------------------- synthetic supplement
@pytest.fixture(scope="module")
def synthetic_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("syn")
    manifest = synthetic.generate(out, synthetic.SyntheticConfig(seed=42, n_users=40, days=45))
    return out, manifest


def test_synthetic_events_are_tagged_separate_and_reproducible(synthetic_run, tmp_path):
    out, manifest = synthetic_run
    events = pd.read_csv(out / "events_synthetic_test.csv.gz")
    assert list(events.columns) == list(EVENT_COLUMNS)
    assert (events["source"] == SOURCE_SYNTHETIC).all() and events["is_synthetic"].all() and events["event_id"].str.startswith("SYN-").all()
    assert manifest["event_count"] == len(events) and manifest["seed"] == 42 and manifest["seed_mode"].startswith("fixed")
    again = synthetic.generate(tmp_path / "again", synthetic.SyntheticConfig(seed=42, n_users=40, days=45))
    assert again["event_count"] == manifest["event_count"]
    pd.testing.assert_frame_equal(events, pd.read_csv(tmp_path / "again" / "events_synthetic_test.csv.gz"))
    other = synthetic.generate(tmp_path / "other", synthetic.SyntheticConfig(seed=43, n_users=40, days=45))
    assert other["event_count"] != manifest["event_count"]


def test_random_seed_mode_records_the_seed_it_used(tmp_path):
    first = synthetic.generate(tmp_path / "a", synthetic.SyntheticConfig(n_users=10, days=20), random_seed=True)
    second = synthetic.generate(tmp_path / "b", synthetic.SyntheticConfig(n_users=10, days=20), random_seed=True)
    assert first["seed_mode"].startswith("random") and first["seed"] != second["seed"]
    assert json.loads((tmp_path / "a" / "manifest.json").read_text())["seed"] == first["seed"]


def test_synthetic_scenarios_cover_threats_lookalikes_noise_and_missing_values(synthetic_run):
    out, manifest = synthetic_run
    scenarios = manifest["scenarios"]
    kinds = {name: s["kind"] for name, s in scenarios.items()}
    assert {"gradual_data_collection", "bulk_export", "unusual_external_transfer", "removable_media_exfiltration", "account_misuse",
            "multi_stage_sequence"} <= {n for n, k in kinds.items() if k == "threat"}
    assert {"legit_large_transfer", "approved_odd_hours", "frequent_authorised_access", "routine_removable_media"} <= {
        n for n, k in kinds.items() if k == "benign_lookalike"}
    assert all(s["reason"] and s["events"] > 0 for s in scenarios.values())
    events = pd.read_csv(out / "events_synthetic_test.csv.gz")
    labels = pd.read_csv(out / "labels.csv")
    meta = pd.read_csv(out / "eval_metadata.csv")
    threat_ids = set(meta[meta["scenario"].map(kinds) == "threat"]["event_id"])
    lookalike_ids = set(meta[meta["scenario"].map(kinds) == "benign_lookalike"]["event_id"])
    assert set(labels["event_id"]) <= threat_ids and not set(labels["event_id"]) & lookalike_ids
    assert len(labels) < 0.2 * len(events)                                           # mostly benign background
    assert events["host"].isna().any() and events["bytes"].isna().sum() > 0 and (events["auth_result"] == "failure").any()   # noise
    assert events["removable_media"].any() and (events["event_type"] == "email_send").any()


def test_synthetic_manifest_documents_parameters_and_policy(synthetic_run):
    _, manifest = synthetic_run
    assert {"seed", "config", "event_count", "scenarios", "behaviour_profile", "policy", "naming", "notice"} <= set(manifest)
    assert "never be added to the held-out CERT test set" in manifest["policy"] and manifest["config"]["n_users"] == 40


def test_synthetic_uses_no_real_looking_destinations_or_names(synthetic_run):
    out, _ = synthetic_run
    events = pd.read_csv(out / "events_synthetic_test.csv.gz")
    domains = set(";".join(events["destination"].dropna()).split(";")) - {""}
    assert domains and all(d.endswith((".example", ".invalid")) for d in domains)
    identity = pd.read_csv(out / "identity_map.csv")
    assert identity["user_id"].str.startswith("SYN-U").all() and events["host"].dropna().str.startswith("SYNPC-").all()


def test_synthetic_profile_from_cert_changes_behaviour(tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"basis": "test profile", "hour_of_day": {"logon": [0.0] * 8 + [1.0] + [0.0] * 15},
                                   "per_user_day": {"file_access": {"mean": 40.0}, "web_visit": {"mean": 1.0}, "email_send": {"mean": 1.0}},
                                   "email_size_bytes": {"0.5": 1000, "0.9": 2000, "0.99": 3000}}), encoding="utf-8")
    manifest = synthetic.generate(tmp_path / "p", synthetic.SyntheticConfig(seed=1, n_users=10, days=14, threat_fraction=0, lookalike_fraction=0),
                                  profile_path=profile)
    events = pd.read_csv(tmp_path / "p" / "events_synthetic_test.csv.gz")
    assert "test profile" in manifest["behaviour_profile"]
    assert (events["event_type"] == "file_access").sum() > 10 * (events["event_type"] == "web_visit").sum() and manifest["malicious_event_count"] == 0


def test_synthetic_data_can_never_enter_the_cert_test_set(release, tmp_path, synthetic_run):
    out, _, _ = _prepared(release, tmp_path)
    cert = pd.read_csv(out / "events_logon.csv.gz")
    leakage.assert_cert_only(cert)
    mixed = pd.concat([cert, pd.read_csv(synthetic_run[0] / "events_synthetic_test.csv.gz")])
    with pytest.raises(leakage.LeakageError, match="Synthetic events"):
        leakage.assert_cert_only(mixed)
    with pytest.raises(leakage.LeakageError, match="sources other than"):
        leakage.assert_cert_only(mixed.assign(is_synthetic=False))
    assert not set(cert["event_id"]) & set(pd.read_csv(synthetic_run[0] / "events_synthetic_test.csv.gz")["event_id"])
    assert np.isin(cert["entity_id"].unique(), pd.read_csv(synthetic_run[0] / "identity_map.csv")["entity_id"]).sum() == 0
