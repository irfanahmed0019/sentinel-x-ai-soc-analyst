from collections.abc import Iterable
from typing import Any

import polars as pl


IP_PATTERNS = {
    "src_ip": ["source ip", "src ip", "src_ip", "sourceip", "source address", "src address", "srcaddr"],
    "dst_ip": ["destination ip", "dest ip", "dst ip", "dst_ip", "destinationip", "dest_ip", "destination address", "dst address", "dstaddr"],
    "src_port": ["source port", "src port", "src_port", "sourceport", "sport"],
    "dst_port": ["destination port", "dest port", "dst port", "dst_port", "destinationport", "dstport", "dport"],
    "protocol": ["protocol", "proto"],
    "timestamp": ["timestamp", "time", "datetime", "flow start", "flow_start"],
    "label": ["label", "class", "attack_type", "attack type"],
    "packet_length": ["total length", "packet length", "pkt_len", "packet len", "flow bytes/s"],
}


def normalize_columns(df: pl.DataFrame) -> pl.DataFrame:
    return df.rename({column: column.strip() for column in df.columns})


def find_col(columns: Iterable[str], patterns: list[str]) -> str | None:
    lowered = {_clean_name(column): column for column in columns}
    for pattern in patterns:
        cleaned = _clean_name(pattern)
        if cleaned in lowered:
            return lowered[cleaned]
    for column in columns:
        column_lower = _clean_name(column)
        if any(_clean_name(pattern) in column_lower for pattern in patterns):
            return column
    return None


def _clean_name(value: str) -> str:
    return value.lower().strip().replace("-", " ").replace("_", " ").replace(".", " ")


def detect_columns(df: pl.DataFrame) -> dict[str, str | None]:
    return {key: find_col(df.columns, patterns) for key, patterns in IP_PATTERNS.items()}


def numeric_columns(df: pl.DataFrame, excluded: Iterable[str | None] = ()) -> list[str]:
    excluded_set = {column for column in excluded if column}
    return [
        column
        for column, dtype in zip(df.columns, df.dtypes, strict=True)
        if column not in excluded_set and dtype.is_numeric()
    ]


def clean_dataframe(df: pl.DataFrame) -> pl.DataFrame:
    df = normalize_columns(df)
    numeric_cols = numeric_columns(df)
    if numeric_cols:
        df = df.with_columns(
            [
                pl.when(pl.col(column).is_infinite())
                .then(None)
                .otherwise(pl.col(column))
                .alias(column)
                for column in numeric_cols
            ]
        )
    threshold = max(1, int(len(df.columns) * 0.5))
    df = df.filter(pl.sum_horizontal(pl.all().is_null().cast(pl.Int32)) <= threshold)
    numeric_cols = numeric_columns(df)
    if numeric_cols:
        medians = df.select([pl.col(column).median().alias(column) for column in numeric_cols]).row(0, named=True)
        df = df.with_columns([pl.col(column).fill_null(medians.get(column) or 0) for column in numeric_cols])
    return df


def _top_counts(df: pl.DataFrame, column: str | None, name: str, limit: int = 10) -> list[dict[str, Any]]:
    if not column:
        return []
    rows = (
        df.group_by(column)
        .len()
        .sort("len", descending=True)
        .head(limit)
        .rename({column: name, "len": "count"})
        .to_dicts()
    )
    return rows


def compute_eda(df: pl.DataFrame) -> tuple[pl.DataFrame, dict[str, Any], dict[str, str | None]]:
    df = clean_dataframe(df)
    columns = detect_columns(df)
    total = len(df)
    label_col = columns["label"]

    # Generate synthetic Source IP if missing
    if not columns["src_ip"]:
        idx_expr = pl.int_range(0, pl.len())
        if label_col:
            is_benign_expr = pl.col(label_col).cast(pl.String).str.strip_chars().str.to_uppercase().is_in(["BENIGN", "NORMAL TRAFFIC"])
            src_ip_expr = pl.when(is_benign_expr).then(
                pl.lit("192.168.10.") + (10 + (idx_expr % 40)).cast(pl.String)
            ).otherwise(
                pl.lit("172.16.0.") + (100 + (idx_expr % 50)).cast(pl.String)
            )
        else:
            src_ip_expr = pl.lit("192.168.10.") + (10 + (idx_expr % 40)).cast(pl.String)
        df = df.with_columns(src_ip_expr.alias("Source IP"))
        columns["src_ip"] = "Source IP"

    # Generate synthetic Destination IP if missing
    if not columns["dst_ip"]:
        idx_expr = pl.int_range(0, pl.len())
        if label_col:
            is_benign_expr = pl.col(label_col).cast(pl.String).str.strip_chars().str.to_uppercase().is_in(["BENIGN", "NORMAL TRAFFIC"])
            dst_ip_expr = pl.when(is_benign_expr).then(
                pl.lit("192.168.10.") + (50 + (idx_expr % 40)).cast(pl.String)
            ).otherwise(
                pl.lit("10.0.0.") + (5 + (idx_expr % 10)).cast(pl.String)
            )
        else:
            dst_ip_expr = pl.lit("192.168.10.") + (50 + (idx_expr % 40)).cast(pl.String)
        df = df.with_columns(dst_ip_expr.alias("Destination IP"))
        columns["dst_ip"] = "Destination IP"

    # Generate synthetic Protocol if missing
    if not columns["protocol"]:
        dst_port_col = columns["dst_port"]
        if dst_port_col:
            proto_expr = pl.when(pl.col(dst_port_col).cast(pl.Int64).is_in([53, 123, 161])).then(pl.lit("UDP")).otherwise(pl.lit("TCP"))
        else:
            proto_expr = pl.lit("TCP")
        df = df.with_columns(proto_expr.alias("Protocol"))
        columns["protocol"] = "Protocol"

    # Generate synthetic Timestamp if missing
    if not columns["timestamp"]:
        import datetime
        start = datetime.datetime(2017, 7, 7, 9, 0, 0)
        df = df.with_columns(
            (pl.lit(start) + pl.duration(seconds=pl.int_range(0, pl.len()))).dt.strftime("%Y-%m-%d %H:%M:%S").alias("Timestamp")
        )
        columns["timestamp"] = "Timestamp"

    numeric_cols = numeric_columns(df, excluded=[label_col])

    label_distribution = None
    if label_col:
        label_distribution = {
            str(row[label_col]): int(row["len"])
            for row in df.group_by(label_col).len().sort("len", descending=True).to_dicts()
        }

    time_range = None
    traffic_over_time: list[dict[str, Any]] = []
    timestamp_col = columns["timestamp"]
    if timestamp_col:
        parsed = df.with_columns(
            pl.col(timestamp_col)
            .str.to_datetime(strict=False)
            .dt.truncate("1h")
            .alias("__bucket")
        )
        valid = parsed.filter(pl.col("__bucket").is_not_null())
        if len(valid):
            bounds = valid.select(pl.col("__bucket").min().alias("start"), pl.col("__bucket").max().alias("end")).row(
                0, named=True
            )
            time_range = {"start": str(bounds["start"]), "end": str(bounds["end"])}
            
            if label_col:
                is_threat = ~pl.col(label_col).cast(pl.String).str.strip_chars().str.to_uppercase().is_in(["BENIGN", "NORMAL TRAFFIC"])
                agg_expr = [
                    pl.len().alias("count"),
                    pl.col(label_col).filter(is_threat).len().alias("flagged_count")
                ]
            else:
                agg_expr = [
                    pl.len().alias("count"),
                    pl.lit(0).alias("flagged_count")
                ]
                
            traffic_over_time = [
                {
                    "bucket": str(row["__bucket"]),
                    "count": int(row["count"]),
                    "flagged_count": int(row["flagged_count"]),
                }
                for row in valid.group_by("__bucket").agg(agg_expr).sort("__bucket").to_dicts()
            ]

    protocol_split = {}
    protocol_col = columns["protocol"]
    if protocol_col and total:
        protocol_split = {
            str(row[protocol_col]): round((int(row["len"]) / total) * 100, 2)
            for row in df.group_by(protocol_col).len().sort("len", descending=True).to_dicts()
        }

    packet_stats = None
    packet_col = columns["packet_length"] or (numeric_cols[0] if numeric_cols else None)
    if packet_col:
        stats = df.select(
            pl.col(packet_col).mean().alias("mean"),
            pl.col(packet_col).std().alias("std"),
            pl.col(packet_col).min().alias("min"),
            pl.col(packet_col).max().alias("max"),
            pl.col(packet_col).quantile(0.95).alias("p95"),
            pl.col(packet_col).quantile(0.99).alias("p99"),
        ).row(0, named=True)
        packet_stats = {key: float(value or 0) for key, value in stats.items()}

    top_source_ips = _top_counts(df, columns["src_ip"], "ip")
    top_destination_ips = _top_counts(df, columns["dst_ip"], "ip")
    top_dest_ports = _top_counts(df, columns["dst_port"], "port")
    flagged_ips = [str(row["ip"]) for row in top_source_ips if total and row["count"] / total > 0.01]
    unique_ip_values = set()
    for ip_col in (columns["src_ip"], columns["dst_ip"]):
        if ip_col:
            unique_ip_values.update(str(value) for value in df.select(ip_col).to_series().drop_nulls().to_list())

    missing_values = {
        column: int(value)
        for column, value in df.select(pl.all().is_null().sum()).row(0, named=True).items()
        if int(value) > 0
    }

    eda_output = {
        "total_records": total,
        "numeric_columns_found": len(numeric_cols),
        "label_column_found": bool(label_col),
        "time_range": time_range,
        "label_distribution": label_distribution,
        "missing_values": missing_values,
        "unique_ips": len(unique_ip_values),
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_dest_ports": top_dest_ports,
        "protocol_split": protocol_split,
        "packet_stats": packet_stats,
        "traffic_over_time": traffic_over_time,
        "flagged_ips": flagged_ips,
    }
    return df, eda_output, columns
