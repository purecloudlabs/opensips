#!/usr/bin/env python3
"""
Render a PNG timeline of tracing events from tracing_events.log.

The plot arranges events chronologically from top to bottom and groups them
into vertical lanes by their `(group, id)` pair (all `tcp_chunk` events share a
single lane). Each event is drawn as a node showing its event name (and the id
for the first event in that lane). All key/value pairs from the `data` field
except `parent_ids` are rendered beside the node, with dialog and transaction
lanes only exposing the data for their first event. Nodes on the same lane are
connected in a vertical sequence.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
LANE_SPACING = 3.6


import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg", force=True)
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch
    from matplotlib import colors as mcolors, cm
    from matplotlib.collections import LineCollection
except ImportError as exc:  # pragma: no cover - dependency guard
    print(
        "[error] matplotlib is required for this script. "
        "Install it with `pip install matplotlib`.",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


@dataclass
class EventRecord:
    index: int
    timestamp: int
    datetime: Optional[str]
    group: str
    event: str
    identifier: str
    parents: Dict[str, str]
    line_number: int
    data: Dict[str, Any] = field(default_factory=dict)
    label_lines: List[str] = field(default_factory=list)
    position: Optional[Tuple[float, float]] = None
    parent: Optional["EventRecord"] = None
    extent_right: float = 0.0
    extent_top: float = 0.0
    extent_bottom: float = 0.0
    lane_label: str = ""
    lane_index: int = 0
    lane_key: Optional[Tuple[str, str]] = None
    lane_position: float = 0.0
    parent_group_lane_index: Optional[int] = None
    visual_height: float = 0.0


def build_label_lines(event: EventRecord) -> List[str]:
    return [event.event] if event.event else []


def normalized_event_id(event: EventRecord) -> str:
    if event.group == "tcp_chunk":
        return "__tcp_chunk__"
    if event.group == "udp":
        # For UDP, create bidirectional flow identifier (sorted endpoints)
        src = event.data.get("src", "")
        dst = event.data.get("dst", "")
        if src and dst:
            # Sort endpoints to ensure A<->B and B<->A map to the same identifier
            endpoints = sorted([src, dst])
            return f"{endpoints[0]}<->{endpoints[1]}"
        return "__udp__"
    if event.group == "script":
        # All script function calls share the same lane
        return "__script_functions__"
    if event.identifier:
        return event.identifier
    return f"auto-{event.index}"


def resolve_lane_identity(event: EventRecord) -> Tuple[str, str]:
    lane_group = event.group
    lane_identifier = normalized_event_id(event)

    if event.group == "tcp_chunk":
        connection_id = event.parents.get("tcp_connection")
        if connection_id:
            lane_group = "tcp_connection"
            lane_identifier = connection_id

    # For UDP events, group them by bidirectional flow (src<->dst)
    if event.group == "udp":
        src = event.data.get("src", "")
        dst = event.data.get("dst", "")
        if src and dst:
            # Sort endpoints to ensure bidirectional grouping
            endpoints = sorted([src, dst])
            lane_group = "udp"
            lane_identifier = f"{endpoints[0]}<->{endpoints[1]}"

    # All script function calls share a single lane
    if event.group == "script":
        lane_group = "script"
        lane_identifier = "__script_functions__"

    return lane_group, lane_identifier


def stringify_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except TypeError:
            return str(value)
    return str(value)


def format_data_lines(data: Any, skip_keys: Optional[List[str]] = None) -> List[str]:
    return []


def parse_log(path: Path) -> List[EventRecord]:
    events: List[EventRecord] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                ts_part, json_part = line.split("|", 1)
                payload = json.loads(json_part)
            except (ValueError, json.JSONDecodeError) as exc:
                print(
                    f"[warn] skipping malformed line {line_number}: {exc}",
                    file=sys.stderr,
                )
                continue

            timestamp = int(payload.get("timestamp", ts_part))
            events.append(
                EventRecord(
                    index=len(events),
                    timestamp=timestamp,
                    datetime=payload.get("datetime"),
                    group=payload.get("group", "unknown"),
                    event=payload.get("event", "unknown"),
                    identifier=str(payload.get("id", "")),
                    parents=payload.get("parent_ids") or {},
                    line_number=line_number,
                    data={
                        key: value
                        for key, value in (payload.get("data") or {}).items()
                        if key != "parent_ids"
                    },
                )
            )

            event = events[-1]
            event.label_lines = build_label_lines(event)

    events.sort(key=lambda item: (item.timestamp, item.line_number))
    return events


def assign_positions(events: List[EventRecord]) -> List[str]:
    group_to_ids: "OrderedDict[str, OrderedDict[str, str]]" = OrderedDict()
    lane_lookup: Dict[str, Dict[str, int]] = defaultdict(dict)

    for event in events:
        lane_group, lane_id = resolve_lane_identity(event)
        if lane_group not in group_to_ids:
            group_to_ids[lane_group] = OrderedDict()
        if lane_id not in group_to_ids[lane_group]:
            display_label = f"{lane_group} [{lane_id}]"
            group_to_ids[lane_group][lane_id] = display_label

    lane_labels: List[str] = []
    lane_map: Dict[Tuple[str, str], int] = {}

    for lane_group, identifiers in group_to_ids.items():
        if not identifiers:
            continue
        for lane_id, display_label in identifiers.items():
            lane_index = len(lane_labels)
            lane_map[(lane_group, lane_id)] = lane_index
            lane_labels.append(display_label)
            lane_lookup[lane_group][lane_id] = lane_index

    lane_spacing = LANE_SPACING
    char_width = 0.11
    label_padding = 1.2
    base_gap = 0.45
    line_height = 0.8
    current_y = 0.0

    for event in events:
        lane_group, lane_id = resolve_lane_identity(event)
        lane_index = lane_map[(lane_group, lane_id)]
        event.lane_index = lane_index
        event.lane_label = lane_labels[lane_index]
        event.lane_key = (lane_group, lane_id)
        lane_lookup[event.group][normalized_event_id(event)] = lane_index
        # Also register by actual event identifier for parent lookups
        if event.identifier:
            lane_lookup[event.group][event.identifier] = lane_index
        x_position = float(lane_index) * lane_spacing

        line_count = len(event.label_lines or []) or 1
        content_height = max(1, line_count) * line_height
        y_position = current_y + content_height / 2.0
        event.lane_position = x_position
        event.position = (x_position, y_position)

        label_chars = max(
            [len(event.lane_label) + 2] + [len(line) for line in (event.label_lines or [])]
        )
        event.extent_right = x_position + label_chars * char_width + label_padding
        half_height = max(content_height / 2.0, 0.38)
        event.extent_top = y_position - half_height
        event.extent_bottom = y_position + half_height

        next_gap = base_gap
        current_y = event.extent_bottom + next_gap

        event.parent_group_lane_index = None
        if event.parents:
            for parent_group, parent_identifier in event.parents.items():
                parent_lane_index = lane_lookup.get(parent_group, {}).get(parent_identifier)
                if parent_lane_index is not None:
                    event.parent_group_lane_index = parent_lane_index
                    break

    return lane_labels


def link_parents(events: Iterable[EventRecord]) -> None:
    return None


def pick_figure_size(
    events: List[EventRecord],
    lane_labels: List[str],
    width: Optional[float],
    height: Optional[float],
) -> Tuple[float, float]:
    max_extent = max((event.extent_right for event in events), default=3.5)
    lane_count = max(len(lane_labels), 1)
    max_bottom = max(
        (event.extent_bottom for event in events),
        default=(len(events) or 1) * 2.0,
    )
    min_top = min(
        (event.extent_top for event in events),
        default=0.0,
    )
    vertical_span = max(1.0, max_bottom - min_top)

    if width is None:
        base_width = lane_count * 1.8 + 3.5
        width = max(7.5, min(100.0, max(base_width, max_extent * 0.15 + 4.0)))

    if height is None:
        base_height = vertical_span * 0.22 + 3.2
        height = max(7.0, min(110.0, base_height))

    return width, height


def render(
    events: List[EventRecord],
    lane_labels: List[str],
    output_path: Path,
    width: Optional[float],
    height: Optional[float],
    dpi: int,
) -> None:
    figure_width, figure_height = pick_figure_size(events, lane_labels, width, height)

    fig, ax = plt.subplots(figsize=(figure_width, figure_height), dpi=dpi)

    cmap = plt.get_cmap("tab20")
    group_order: "OrderedDict[str, int]" = OrderedDict()
    for event in events:
        if event.group not in group_order:
            group_order[event.group] = len(group_order)
    group_colors: Dict[str, str] = {}
    for group, index in group_order.items():
        if group == "tcp_connection":
            group_colors[group] = "#0d2a5d"  # darker blue for connections
        elif group == "tcp_chunk":
            group_colors[group] = "#17becf"  # light blue
        elif group == "udp":
            group_colors[group] = "#2ca02c"  # green for UDP
        elif group == "rest":
            group_colors[group] = "#d62728"  # red for REST events
        elif group == "script":
            group_colors[group] = "#9467bd"  # purple for script function calls
        elif group == "dialog":
            group_colors[group] = "#ff7f0e"  # orange for dialogs
        else:
            group_colors[group] = cmap(index % cmap.N)

    by_lane: Dict[int, List[EventRecord]] = defaultdict(list)
    lane_x_positions: Dict[int, float] = {}
    lane_colors: Dict[int, str] = {}
    lane_groups: Dict[int, str] = {}
    for event in events:
        by_lane[event.lane_index].append(event)
        if event.position:
            lane_x_positions[event.lane_index] = event.position[0]

    for lane_index, lane_events in by_lane.items():
        if not lane_events:
            continue
        lane_group, _ = resolve_lane_identity(lane_events[0])
        lane_colors[lane_index] = group_colors.get(lane_group, "#444444")
        lane_groups[lane_index] = lane_group

    def lighten_rgba(rgba: Tuple[float, float, float, float], amount: float = 0.3) -> Tuple[float, float, float, float]:
        r, g, b, a = rgba
        return (
            r + (1.0 - r) * amount,
            g + (1.0 - g) * amount,
            b + (1.0 - b) * amount,
            a,
        )

    sorted_for_time = sorted(
        [event for event in events if event.position],
        key=lambda item: (item.timestamp, item.line_number),
    )
    time_segments: List[Tuple[float, float, float]] = []
    for current, nxt in zip(sorted_for_time, sorted_for_time[1:]):
        delta = max(nxt.timestamp - current.timestamp, 0)
        time_segments.append((current.extent_top, current.extent_bottom, delta))
    if sorted_for_time:
        last_event_for_time = sorted_for_time[-1]
        time_segments.append((last_event_for_time.extent_top, last_event_for_time.extent_bottom, 0.0))

    def lighten_rgba(rgba: Tuple[float, float, float, float], amount: float = 0.3) -> Tuple[float, float, float, float]:
        r, g, b, a = rgba
        return (
            r + (1.0 - r) * amount,
            g + (1.0 - g) * amount,
            b + (1.0 - b) * amount,
            a,
        )

    sorted_for_time = sorted(
        [event for event in events if event.position],
        key=lambda item: (item.timestamp, item.line_number),
    )
    time_segments: List[Tuple[float, float, float]] = []
    for current, nxt in zip(sorted_for_time, sorted_for_time[1:]):
        delta_time = max(nxt.timestamp - current.timestamp, 0)
        time_segments.append((current.extent_top, current.extent_bottom, delta_time))
    if sorted_for_time:
        last_event_time = sorted_for_time[-1]
        time_segments.append((last_event_time.extent_top, last_event_time.extent_bottom, 0.0))

    segment_infos: List[Tuple[int, EventRecord, EventRecord, float]] = []
    for lane_index, lane_events in by_lane.items():
        lane_events.sort(key=lambda item: (item.timestamp, item.line_number))
        for left, right in zip(lane_events, lane_events[1:]):
            if left.position and right.position:
                duration = max(right.timestamp - left.timestamp, 0)
                segment_infos.append((lane_index, left, right, duration))

    for lane_index, lane_events in by_lane.items():
        lane_events.sort(key=lambda item: (item.timestamp, item.line_number))
        color = lane_colors.get(lane_index, "#444444")
        for left, right in zip(lane_events, lane_events[1:]):
            if left.position and right.position:
                ax.plot(
                    [left.position[0], right.position[0]],
                    [left.position[1], right.position[1]],
                    color=color,
                    linewidth=1.6,
                    zorder=1,
                    alpha=0.8,
                )

    previous_event: Optional[EventRecord] = None
    y_tick_positions: List[float] = []
    y_tick_labels: List[str] = []
    seen_tick_labels: set = set()
    drawn_arrows: Set[Tuple[int, int, int, str]] = set()
    first_lane_info_shown: Set[Tuple[str, str]] = set()

    def parent_is_tcp_connection(event: EventRecord) -> bool:
        if event.parent_group_lane_index is not None:
            if lane_groups.get(event.parent_group_lane_index) == "tcp_connection":
                return True
        if event.parents and "tcp_connection" in event.parents:
            return True
        return False

    def parent_is_udp_flow(event: EventRecord) -> bool:
        if event.parent_group_lane_index is not None:
            if lane_groups.get(event.parent_group_lane_index) == "udp":
                return True
        if event.parents and "udp" in event.parents:
            return True
        return False

    def parent_is_script(event: EventRecord) -> bool:
        if event.parent_group_lane_index is not None:
            if lane_groups.get(event.parent_group_lane_index) == "script":
                return True
        if event.parents and "script" in event.parents:
            return True
        return False

    def collect_event_extras(event: EventRecord) -> List[str]:
        extras: List[str] = []
        # For UDP events, show the correlation ID
        if event.group == "udp":
            if event.identifier:
                extras.append(str(event.identifier))
        # For tcp_chunk or read/write events (but not UDP which is already handled)
        elif event.group == "tcp_chunk" or event.event in {"read", "write"}:
            extras.append(str(event.identifier))
        if event.event == "worker_pickup":
            pid = event.data.get("pid") or event.identifier
            extras.append(f"pid: {pid}")
        if event.event in {"disconnect", "disconnected"}:
            reason = event.data.get("reason")
            if reason:
                extras.append(str(reason))
        # Add response code for REST request_complete events
        if event.group == "rest" and event.event == "request_complete":
            response_code = event.data.get("response_code")
            if response_code:
                extras.append(f"code: {response_code}")
        # For script function calls, show the function name, caller, and depth
        if event.group == "script":
            func = event.data.get("function")
            caller = event.data.get("caller")
            depth = event.data.get("depth")
            if caller and func:
                extras.append(f"{caller} → {func}")
            elif func:
                extras.append(func)
            if depth is not None:
                extras.append(f"depth: {depth}")
        return extras

    def collect_lane_extras(event: EventRecord) -> List[str]:
        extras: List[str] = []
        if event.group == "transaction":
            branch = event.data.get("branch")
            cseq = event.data.get("cseq")
            if branch:
                extras.append(f"branch: {branch}")
            if cseq:
                extras.append(f"cseq: {cseq}")
        elif event.group == "dialog":
            callid = event.data.get("callid")
            if callid:
                extras.append(f"callid: {callid}")
        elif event.group == "tcp_connection":
            src = event.data.get("src")
            dst = event.data.get("dst")
            if src and dst:
                extras.append(f"{src} → {dst}")
            else:
                if src:
                    extras.append(f"src: {src}")
                if dst:
                    extras.append(f"dst: {dst}")
        elif event.group == "udp":
            # For UDP events, show the direction (src → dst)
            src = event.data.get("src")
            dst = event.data.get("dst")
            if src and dst:
                extras.append(f"{src} → {dst}")
        elif event.group == "rest":
            # For REST events, show method and URL for request_start, method, URL, response code and response_len for request_complete
            method = event.data.get("method")
            if event.event == "request_start":
                if method:
                    extras.append(f"method: {method}")
                url = event.data.get("url")
                if url:
                    extras.append(f"url: {url}")
            elif event.event == "request_complete":
                if method:
                    extras.append(f"method: {method}")
                url = event.data.get("url")
                if url:
                    extras.append(f"url: {url}")
                response_code = event.data.get("response_code")
                if response_code:
                    extras.append(f"code: {response_code}")
                response_len = event.data.get("response_len")
                if response_len:
                    extras.append(f"response_len: {response_len}")
        elif event.group == "script":
            # Script events show all info in collect_event_extras, skip here to avoid duplication
            pass
        return extras

    def draw_lane_arrow(
        source_idx: int,
        dest_idx: int,
        y_pos: float,
        event_idx: int,
        tag: str,
        label_text: Optional[str] = None,
    ) -> None:
        if source_idx == dest_idx:
            return
        arrow_key = (source_idx, dest_idx, event_idx, tag)
        if arrow_key in drawn_arrows:
            return
        source_x = lane_x_positions.get(source_idx)
        dest_x = lane_x_positions.get(dest_idx)
        if source_x is None or dest_x is None or source_x == dest_x:
            return

        direction = 1 if dest_x > source_x else -1
        target_x = dest_x - direction * 0.25

        source_color = lighten_rgba(mcolors.to_rgba(lane_colors.get(source_idx, "#999999")), amount=0.4)
        dest_color = lighten_rgba(mcolors.to_rgba(lane_colors.get(dest_idx, "#999999")), amount=0.4)

        x_vals = np.linspace(source_x, target_x, 16)
        y_vals = np.full_like(x_vals, y_pos)
        segments = np.stack(
            [
                np.column_stack([x_vals[:-1], y_vals[:-1]]),
                np.column_stack([x_vals[1:], y_vals[1:]]),
            ],
            axis=1,
        )
        t_vals = np.linspace(0.0, 1.0, len(segments))
        gradient_colors = [
            (
                source_color[0] * (1 - t) + dest_color[0] * t,
                source_color[1] * (1 - t) + dest_color[1] * t,
                source_color[2] * (1 - t) + dest_color[2] * t,
                max(source_color[3], dest_color[3]),
            )
            for t in t_vals
        ]

        lc = LineCollection(
            segments,
            colors=gradient_colors,
            linewidths=1.0,
            linestyles="--",
            zorder=0,
        )
        ax.add_collection(lc)

        if label_text:
            text_x = (source_x + target_x) / 2.0
            ax.text(
                text_x,
                y_pos - 0.35,
                label_text,
                fontsize=7,
                color=dest_color,
                ha="center",
                va="center",
                zorder=0,
            )

        arrow = FancyArrowPatch(
            (x_vals[-2], y_pos),
            (dest_x, y_pos),
            arrowstyle="-|>",
            color=dest_color,
            linewidth=1.0,
            mutation_scale=10,
            linestyle="--",
            shrinkA=0,
            shrinkB=0,
            zorder=0,
        )
        arrow.set_linestyle("--")
        ax.add_patch(arrow)

        tick_half_height = 0.5
        ax.plot(
            [source_x, source_x],
            [y_pos - tick_half_height, y_pos + tick_half_height],
            color=source_color,
            linewidth=0.9,
            zorder=0,
        )

        drawn_arrows.add(arrow_key)

    for event in events:
        if not event.position:
            continue

        color = group_colors.get(event.group, "#444444")
        ax.scatter(
            event.position[0],
            event.position[1],
            s=110,
            color=color,
            edgecolors="black",
            linewidths=0.6,
            zorder=3,
        )

        if not event.label_lines:
            event.label_lines = build_label_lines(event)

        fallback_text = event.event or ""
        extras: List[str] = collect_event_extras(event)

        lane_info_key = (event.group, normalized_event_id(event))
        lane_extras = collect_lane_extras(event)
        if lane_extras and lane_info_key not in first_lane_info_shown:
            first_lane_info_shown.add(lane_info_key)
            extras.extend(lane_extras)

        if extras:
            info_text = ", ".join(extras)
            fallback_text = f"{fallback_text} ({info_text})" if fallback_text else f"({info_text})"
        has_metadata = "(" in fallback_text and fallback_text.endswith(")")
        if has_metadata:
            paren_index = fallback_text.find("(")
            primary_text = fallback_text[:paren_index].rstrip()
            meta_text = fallback_text[paren_index:]
            if primary_text:
                primary_offset = 8
                meta_offset = primary_offset + len(primary_text) * 4.2 + 6
                ax.annotate(
                    primary_text,
                    xy=event.position,
                    xytext=(primary_offset, 0),
                    textcoords="offset points",
                    ha="left",
                    va="center",
                    fontsize=8,
                    color="#222222",
                    zorder=4,
                )
                ax.annotate(
                    meta_text,
                    xy=event.position,
                    xytext=(meta_offset, 0),
                    textcoords="offset points",
                    ha="left",
                    va="center",
                    fontsize=8,
                    color="#555555",
                    zorder=4,
                )
            else:
                ax.annotate(
                    meta_text,
                    xy=event.position,
                    xytext=(8, 0),
                    textcoords="offset points",
                    ha="left",
                    va="center",
                    fontsize=8,
                    color="#555555",
                    zorder=4,
                )
        else:
            ax.annotate(
                fallback_text,
                xy=event.position,
                xytext=(8, 0),
                textcoords="offset points",
                ha="left",
                va="center",
                fontsize=8,
                color="#222222",
                zorder=4,
            )

        if event.position:
            tick_label = event.datetime or str(event.timestamp)
            if tick_label not in seen_tick_labels:
                y_tick_positions.append(event.position[1])
                y_tick_labels.append(tick_label)
                seen_tick_labels.add(tick_label)

        arrow_y = event.position[1] - 0.45

        if previous_event is not None and previous_event.lane_index != event.lane_index:
            prev_lane_group, _ = resolve_lane_identity(previous_event)
            curr_lane_group, _ = resolve_lane_identity(event)
            if {prev_lane_group, curr_lane_group} <= {"tcp_connection", "tcp_chunk"}:
                previous_event = event
                continue
            if {prev_lane_group, curr_lane_group} <= {"udp"}:
                previous_event = event
                continue
            # Don't draw arrows from transaction to transaction
            if {prev_lane_group, curr_lane_group} <= {"transaction"}:
                previous_event = event
                continue
            # Don't draw arrows between script events (they're on same lane)
            if {prev_lane_group, curr_lane_group} <= {"script"}:
                previous_event = event
                continue
            if not event.parents or event.group in {"tcp_chunk", "udp"}:
                previous_event = event
                continue
            label = None
            if event.group in {"transaction", "dialog"}:
                code = event.data.get("code")
                method = event.data.get("method")
                parts = []
                if method:
                    parts.append(str(method))
                # Check if this is the first event in this lane (new timeline for transaction)
                lane_info_key = (event.group, normalized_event_id(event))
                # Count how many events we've seen in this lane so far
                events_in_lane = sum(1 for e in by_lane.get(event.lane_index, []) 
                                     if e.index <= event.index)
                is_first_in_lane = events_in_lane == 1
                # Only add code if it's not the first event (i.e., not a request)
                if code and not is_first_in_lane:
                    parts.append(str(code))
                if parts:
                    label = ", ".join(parts)
            draw_lane_arrow(previous_event.lane_index, event.lane_index, arrow_y, event.index, "chronological", label)

        if (
            previous_event is not None
            and event.parent_group_lane_index is not None
            and event.parent_group_lane_index != event.lane_index
            and previous_event.lane_index == event.parent_group_lane_index
            and event.parents
        ):
            prev_lane_group = lane_groups.get(event.parent_group_lane_index)
            curr_lane_group = event.group
            # Skip tcp_connection -> tcp_chunk arrows (internal)
            if parent_is_tcp_connection(event) and curr_lane_group != "script":
                previous_event = event
                continue
            # Skip udp -> non-script arrows (but allow udp -> script)
            if parent_is_udp_flow(event) and curr_lane_group != "script":
                previous_event = event
                continue
            # Don't draw arrows from transaction to transaction
            if prev_lane_group == "transaction" and curr_lane_group == "transaction":
                previous_event = event
                continue
            # Don't draw arrows between script events
            if prev_lane_group == "script" and curr_lane_group == "script":
                previous_event = event
                continue
            if event.group in {"tcp_chunk", "udp"}:
                previous_event = event
                continue
            label = None
            if event.group in {"transaction", "dialog"}:
                code = event.data.get("code")
                method = event.data.get("method")
                parts = []
                if method:
                    parts.append(str(method))
                # Check if this is the first event in this lane (new timeline for transaction)
                events_in_lane = sum(1 for e in by_lane.get(event.lane_index, []) 
                                     if e.index <= event.index)
                is_first_in_lane = events_in_lane == 1
                # Only add code if it's not the first event (i.e., not a request)
                if code and not is_first_in_lane:
                    parts.append(str(code))
                if parts:
                    label = ", ".join(parts)
            draw_lane_arrow(event.parent_group_lane_index, event.lane_index, arrow_y, event.index, "parent", label)

        previous_event = event

    lane_positions = {
        event.lane_index: event.position[0] for event in events if event.position
    }
    sorted_lanes = sorted(lane_positions.items())
    lane_coords = [coord for _, coord in sorted_lanes]
    x_positions = [event.position[0] for event in events if event.position]
    max_extent = max((event.extent_right for event in events), default=0.0)
    band_x0 = band_x1 = None
    if x_positions:
        lane_spacing = LANE_SPACING
        if len(lane_coords) >= 2:
            lane_spacing = max(1.3, lane_coords[1] - lane_coords[0])
        padding_x = max(1.1, lane_spacing * 0.45 + 0.7)
        min_x = min(x_positions)
        max_x = max(x_positions)
        right_limit = max(max_x + padding_x, max_extent + padding_x)
        ax.set_xlim(min_x - padding_x, right_limit)
        band_width = max(0.3, lane_spacing * 0.25)
        band_gap = max(0.3, lane_spacing * 0.2)
        band_x1 = min_x - band_gap
        band_x0 = band_x1 - band_width

    if lane_labels:
        fallback_spacing = LANE_SPACING
        tick_positions = [
            lane_positions.get(index, index * fallback_spacing)
            for index in range(len(lane_labels))
        ]
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(lane_labels, rotation=18, ha="right")

    min_top = min((event.extent_top for event in events), default=0.0)
    max_bottom = max((event.extent_bottom for event in events), default=1.0)
    vertical_padding = max(0.6, (max_bottom - min_top) * 0.02 + 0.5)
    ax.set_ylim(min_top - vertical_padding, max_bottom + vertical_padding)

    if band_x0 is not None and time_segments:
        time_durations = np.array([seg[2] for seg in time_segments], dtype=float)
        if time_durations.size:
            positive_t = time_durations[time_durations > 0]
            min_positive_t = float(positive_t.min()) if positive_t.size else 1.0
            adjusted_t = time_durations + min_positive_t * 0.1
            log_t = np.log10(adjusted_t)
            min_log_t = float(log_t.min())
            max_log_t = float(log_t.max())
            range_log_t = max(max_log_t - min_log_t, 1e-6)
            for top, bottom, delta_time in time_segments:
                log_delta_time = np.log10(delta_time + min_positive_t * 0.1)
                intensity = (log_delta_time - min_log_t) / range_log_t
                intensity = max(0.05, min(1.0, intensity))
                base_color = cm.Reds(0.15 + 0.85 * intensity)
                color = lighten_rgba(base_color, amount=0.2)
                rect = plt.Rectangle(
                    (band_x0, top),
                    band_x1 - band_x0,
                    bottom - top,
                    color=color,
                    alpha=0.6,
                    zorder=0,
                )
                ax.add_patch(rect)

    ax.set_xlabel("Group")
    ax.set_ylabel("Time")
    ax.invert_yaxis()
    if y_tick_positions and y_tick_labels:
        ax.set_yticks(y_tick_positions)
        ax.set_yticklabels(y_tick_labels, fontsize=8)
    ax.set_title("Tracing Events Timeline")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.4)

    plt.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path)
    plt.close(fig)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a PNG diagram from tracing_events.log"
    )
    parser.add_argument(
        "-i",
        "--input",
        default="t/tracing_events.log",
        help="Path to the tracing events log (default: %(default)s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="tracing_events.png",
        help="Path to the output PNG file (default: %(default)s)",
    )
    parser.add_argument(
        "--width",
        type=float,
        default=None,
        help="Override the figure width in inches",
    )
    parser.add_argument(
        "--height",
        type=float,
        default=None,
        help="Override the figure height in inches",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=150,
        help="Dots per inch of the generated PNG (default: %(default)s)",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    if not input_path.exists():
        print(f"[error] input log not found: {input_path}", file=sys.stderr)
        return 1

    events = parse_log(input_path)
    if not events:
        print(f"[error] no events found in {input_path}", file=sys.stderr)
        return 1

    lane_labels = assign_positions(events)
    link_parents(events)
    render(events, lane_labels, output_path, args.width, args.height, args.dpi)

    print(f"[ok] wrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


