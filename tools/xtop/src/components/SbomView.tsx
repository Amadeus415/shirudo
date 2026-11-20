// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What the SBOMs and kernels say is vulnerable on the nodes, one row per
// finding or one per advisory, or the images of the SBOM store and how far
// they are scanned. Enter on a finding shows its nodes; on an advisory, its
// packages; on an image, its findings.

import { useEffect, useMemo, useState } from "react";
import { Box, Text, useInput } from "ink";
import type { Backend } from "../lib/backend.ts";
import { ago } from "../lib/format.ts";
import { useRefreshing } from "../lib/useRefreshing.ts";
import { literalSearch } from "../lib/search.ts";
import {
  FINDING_STATUS_RANK,
  IMAGE_STATES,
  groupByVuln,
  imageKey,
  type Finding,
  type FindingStatus,
  type ImageState,
  type ImagesReport,
  type SbomImage,
  type SbomReport,
  type Vuln,
} from "../lib/sbom.ts";
import { severityRank } from "../lib/shields.ts";
import { DataTable, Tabs, type Column } from "./DataTable.tsx";
import { ViewMessage } from "./ViewMessage.tsx";
import { FindingDetail } from "./FindingDetail.tsx";
import { FINDING_STATUS_STYLE, IMAGE_STATE_COLOR, SeverityText } from "./style.tsx";

export type SbomMode = "findings" | "vulns" | "images";

type Props = {
  backend: Backend;
  mode: SbomMode;
  onModeChange: (mode: SbomMode) => void;
  /** Lines available inside the panel. */
  height: number;
  active: boolean;
  onClose: () => void;
  onSearchingChange: (searching: boolean) => void;
  /** A finding's nodes or an advisory's packages are open. */
  onDetailChange?: (open: boolean) => void;
};

function FindingStatusCell({ f }: { f: Finding }) {
  const style = FINDING_STATUS_STYLE[f.status];
  return (
    <>
      <Text color={style.color}>{style.label}</Text>
      {f.status !== "no_shield" && f.status !== "shielded" && (
        <Text dimColor>
          {" "}
          {f.shielded}/{f.affected}
        </Text>
      )}
    </>
  );
}

// ---- findings --------------------------------------------------------------

const FINDING_COLUMNS: readonly Column<Finding>[] = [
  {
    id: "severity",
    title: "SEVERITY",
    width: 10,
    defaultDir: "asc",
    sortKey: (f) => severityRank(f.severity),
    render: (f) => <SeverityText severity={f.severity} />,
  },
  {
    id: "id",
    title: "VULNERABILITY",
    width: 18,
    defaultDir: "asc",
    sortKey: (f) => f.vulnId,
    render: (f) => <Text bold>{f.vulnId}</Text>,
  },
  {
    id: "package",
    title: "PACKAGE",
    defaultDir: "asc",
    sortKey: (f) => f.package,
    render: (f) => <PackageCell f={f} />,
  },
  {
    id: "fixed",
    title: "FIXED IN",
    width: 12,
    defaultDir: "asc",
    sortKey: (f) => f.fixed,
    render: (f) => (f.fixed ? <Text color="green">{f.fixed}</Text> : <Text dimColor>none yet</Text>),
  },
  {
    id: "nodes",
    title: "NODES",
    width: 9,
    align: "right",
    defaultDir: "desc",
    sortKey: (f) => f.affected,
    render: (f) => (
      <Text>
        <Text bold>{f.affected}</Text>
        <Text dimColor>/{f.total}</Text>
      </Text>
    ),
  },
  {
    id: "shield",
    title: "SHIELD",
    width: 14,
    defaultDir: "asc",
    sortKey: (f) => f.upatchId || "~",
    render: (f) => (f.upatchId ? <Text>{f.upatchId}</Text> : <Text dimColor>—</Text>),
  },
  {
    id: "status",
    title: "STATUS",
    width: 15,
    defaultDir: "asc",
    sortKey: (f) => FINDING_STATUS_RANK[f.status],
    render: (f) => <FindingStatusCell f={f} />,
  },
];

const findingFields = (f: Finding) =>
  [
    f.vulnId,
    f.package,
    f.severity,
    f.source,
    f.upatchId,
    f.status,
    ...f.installed,
    ...f.nodes.flatMap((n) => [n.name, `${n.imageId} ${n.imageVersion}`]),
  ];

const findingTiebreak = (a: Finding, b: Finding) =>
  severityRank(a.severity) - severityRank(b.severity) || b.affected - a.affected || a.vulnId.localeCompare(b.vulnId);

function PackageCell({ f, more = 0 }: { f: Finding; more?: number }) {
  return (
    <>
      <Text color={f.source === "kernel" ? "magenta" : "cyan"}>{f.source === "kernel" ? "kernel" : f.package}</Text>
      {more > 0 && <Text color="yellow"> +{more}</Text>}
      <Text dimColor> {f.installed.join(", ")}</Text>
    </>
  );
}

// ---- vulnerabilities -------------------------------------------------------

const VULN_COLUMNS: readonly Column<Vuln>[] = [
  {
    id: "severity",
    title: "SEVERITY",
    width: 10,
    defaultDir: "asc",
    sortKey: (v) => severityRank(v.severity),
    render: (v) => <SeverityText severity={v.severity} />,
  },
  {
    id: "id",
    title: "VULNERABILITY",
    width: 18,
    defaultDir: "asc",
    sortKey: (v) => v.vulnId,
    render: (v) => <Text bold>{v.vulnId}</Text>,
  },
  {
    id: "packages",
    title: "PACKAGES",
    defaultDir: "desc",
    sortKey: (v) => v.findings.length,
    render: (v) => <PackageCell f={v.findings[0]!} more={v.findings.length - 1} />,
  },
  {
    id: "fixed",
    title: "FIXED IN",
    width: 12,
    defaultDir: "asc",
    sortKey: (v) => v.findings[0]!.fixed,
    render: (v) => {
      const fixed = v.findings[0]!.fixed;
      return fixed ? <Text color="green">{fixed}</Text> : <Text dimColor>none yet</Text>;
    },
  },
  {
    id: "nodes",
    title: "NODES",
    width: 9,
    align: "right",
    defaultDir: "desc",
    sortKey: (v) => v.affected,
    render: (v) => (
      <Text>
        <Text bold>{v.affected}</Text>
        <Text dimColor>/{v.total}</Text>
      </Text>
    ),
  },
  {
    id: "shield",
    title: "SHIELD",
    width: 14,
    defaultDir: "asc",
    sortKey: (v) => v.upatchIds.join(" ") || "~",
    render: (v) => (v.upatchIds.length ? <Text>{v.upatchIds.join(", ")}</Text> : <Text dimColor>—</Text>),
  },
  {
    id: "status",
    title: "STATUS",
    width: 15,
    defaultDir: "asc",
    sortKey: (v) => FINDING_STATUS_RANK[v.status],
    render: (v) => <Text color={FINDING_STATUS_STYLE[v.status].color}>{FINDING_STATUS_STYLE[v.status].label}</Text>,
  },
];

const vulnFields = (v: Vuln) => [...new Set(v.findings.flatMap(findingFields))];

const vulnTiebreak = (a: Vuln, b: Vuln) =>
  severityRank(a.severity) - severityRank(b.severity) || b.affected - a.affected || a.vulnId.localeCompare(b.vulnId);

/** The findings of one advisory, one row per package, in the popup. */
const PACKAGE_COLUMNS: readonly Column<Finding>[] = [
  { ...FINDING_COLUMNS.find((c) => c.id === "package")!, render: (f) => <PackageCell f={f} /> },
  ...FINDING_COLUMNS.filter((c) => c.id !== "id" && c.id !== "package"),
];

const findingKey = (f: Finding) => `${f.vulnId}\0${f.package}`;

function VulnDetail({
  vuln: v,
  height,
  active,
  onClose,
  onOpen,
  onSearchingChange,
}: {
  /** null when the advisory left node_vulns since it was opened. */
  vuln: Vuln | null;
  height: number;
  active: boolean;
  onClose: () => void;
  onOpen: (f: Finding) => void;
  onSearchingChange: (searching: boolean) => void;
}) {
  if (!v)
    return (
      <ViewMessage active={active} onClose={onClose} color="yellow">
        the advisory is no longer in node_vulns
      </ViewMessage>
    );
  const style = FINDING_STATUS_STYLE[v.status];
  return (
    <Box flexDirection="column">
      <Text wrap="truncate-end">
        <Text bold>{v.vulnId}</Text> <SeverityText severity={v.severity} />
        <Text color={style.color}>  {style.label}</Text>
        <Text dimColor>
          {"  "}
          {v.findings.length} package{v.findings.length === 1 ? "" : "s"} · {v.affected} of {v.total} nodes · shield {v.upatchIds.join(", ") || "none"}
        </Text>
        {v.stale && <Text color="red"> · from a stale scan</Text>}
      </Text>
      <DataTable
        key={v.vulnId}
        footerHint="enter nodes · esc back"
        rows={v.findings}
        columns={PACKAGE_COLUMNS}
        rowKey={findingKey}
        height={Math.max(4, height - 1)}
        active={active}
        initialSort={{ col: "package", dir: "asc" }}
        tiebreak={findingTiebreak}
        searchFields={findingFields}
        onSearchingChange={onSearchingChange}
        onClose={onClose}
        onOpen={onOpen}
      />
    </Box>
  );
}

// ---- images ----------------------------------------------------------------

const STATE_RANK = Object.fromEntries(IMAGE_STATES.map((s, i) => [s, i])) as Record<ImageState, number>;

const IMAGE_COLUMNS: readonly Column<SbomImage>[] = [
  {
    id: "state",
    title: "STATE",
    width: 19,
    defaultDir: "asc",
    sortKey: (i) => STATE_RANK[i.state] * 2 + (i.stale ? 0 : 1),
    render: (i) => (
      <>
        <Text color={IMAGE_STATE_COLOR[i.state]}>{i.state}</Text>
        {i.stale && <Text color="red"> stale</Text>}
      </>
    ),
  },
  {
    id: "image",
    title: "IMAGE",
    defaultDir: "asc",
    sortKey: imageKey,
    render: (i) => (
      <>
        <Text color="cyan">{imageKey(i)}</Text>
        <Text dimColor> {i.imageRoot ? i.imageRoot.slice(0, 8) : "no root"}</Text>
      </>
    ),
  },
  {
    id: "nodes",
    title: "NODES",
    width: 6,
    align: "right",
    defaultDir: "desc",
    sortKey: (i) => i.nodes,
    render: (i) => <Text>{i.nodes}</Text>,
  },
  {
    id: "findings",
    title: "FINDINGS",
    width: 16,
    defaultDir: "desc",
    sortKey: (i) => i.critical * 1e6 + i.high * 1e3 + i.vulns,
    render: (i) =>
      i.state !== "ok" ? (
        <Text dimColor>—</Text>
      ) : (
        <>
          <Text>{i.vulns}</Text>
          {i.critical > 0 && <Text color="red"> {i.critical} crit</Text>}
          {i.high > 0 && <Text color="red"> {i.high} high</Text>}
        </>
      ),
  },
  {
    id: "scanned",
    title: "SCANNED",
    width: 8,
    align: "right",
    defaultDir: "desc",
    sortKey: (i) => i.scannedAt?.getTime() ?? 0,
    render: (i) =>
      i.scannedAt ? <Text color={i.stale ? "red" : undefined}>{ago(i.scannedAt)}</Text> : <Text dimColor>never</Text>,
  },
  {
    id: "db",
    title: "DATABASE",
    width: 21,
    defaultDir: "desc",
    sortKey: (i) => i.dbVersion,
    render: (i) => <Text dimColor>{i.dbVersion || "—"}</Text>,
  },
];

const imageFields = (i: SbomImage) =>
  [imageKey(i), i.imageRoot, i.state, i.sbomSha256, i.dbVersion, i.stale ? "stale" : ""];

// ---- view ------------------------------------------------------------------

export function SbomView({ backend, mode, onModeChange, height, active, onClose, onSearchingChange, onDetailChange }: Props) {
  const [reload, setReload] = useState(0);
  const findings = useRefreshing<SbomReport>(mode !== "images", reload, () => backend.getSbom());
  const images = useRefreshing<ImagesReport>(mode === "images", reload, () => backend.getSbomImages());
  const vulns = useMemo(() => (findings.data ? groupByVuln(findings.data.findings) : []), [findings.data]);
  const [searching, setSearching] = useState(false);
  // Set when drilling into an image; seeds the findings table's search.
  const [drill, setDrill] = useState("");
  const [onTabs, setOnTabs] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const [openVuln, setOpenVuln] = useState<string | null>(null);
  // As of the newest query, so a refresh updates the open pane.
  const detailFinding = detail ? (findings.data?.findings.find((f) => findingKey(f) === detail) ?? null) : null;
  const vulnDetail = openVuln ? (vulns.find((v) => v.vulnId === openVuln) ?? null) : null;
  const paneOpen = detail !== null || openVuln !== null;

  useEffect(() => onDetailChange?.(paneOpen), [paneOpen, onDetailChange]);

  const reportSearching = (s: boolean) => {
    setSearching(s);
    onSearchingChange(s);
  };
  const switchTo = (m: SbomMode, fromTabs = false) => {
    setDrill("");
    setOnTabs(fromTabs);
    onModeChange(m);
  };
  const modes: SbomMode[] = ["findings", "vulns", "images"];
  const tabs = {
    labels: ["findings", "vulnerabilities", "images"],
    selected: modes.indexOf(mode),
    onSelect: (i: number) => switchTo(modes[i]!, true),
  };
  const next = modes[(modes.indexOf(mode) + 1) % modes.length]!;
  const footerHint = `t ${tabs.labels[modes.indexOf(next)]} · r refresh`;

  useInput(
    (input) => {
      if (input === "t") switchTo(next);
      if (input === "r") setReload((r) => r + 1);
    },
    { isActive: active && !searching && !paneOpen },
  );

  const tableHeight = Math.max(4, height);
  const query = mode === "images" ? images : findings;
  if (!query.data)
    return (
      <Box flexDirection="column">
        <Tabs labels={tabs.labels} selected={tabs.selected} />
        <ViewMessage active={active && !searching} onClose={onClose} color={query.error ? "red" : undefined}>
          {query.error ? `${mode === "images" ? "images" : "findings"} query failed: ${query.error}` : "querying backend…"}
        </ViewMessage>
      </Box>
    );
  const status = (generatedAt: Date) => (
    <>
      <Text dimColor> · as of {generatedAt.toTimeString().slice(0, 8)}</Text>
      {query.loading && <Text dimColor> · querying…</Text>}
    </>
  );
  const failed = query.error && <Text color="red">refresh failed: {query.error} · </Text>;

  if (mode === "images") {
    const report = images.data!;
    return (
      <DataTable
        tabs={tabs}
        startOnTabs={onTabs}
        footerHint={footerHint}
        rows={report.images}
        columns={IMAGE_COLUMNS}
        rowKey={(i) => `${imageKey(i)} ${i.imageRoot}`}
        height={tableHeight}
        active={active}
        initialSort={{ col: "state", dir: "asc" }}
        tiebreak={(a, b) => b.nodes - a.nodes || imageKey(a).localeCompare(imageKey(b))}
        searchFields={imageFields}
        onSearchingChange={reportSearching}
        onClose={onClose}
        onOpen={(i) => {
          setOnTabs(false);
          setDrill(literalSearch(imageKey(i)));
          onModeChange("findings");
        }}
        summary={(rows, sortedBy) => {
          const count = (s: ImageState) => rows.filter((i) => i.state === s).length;
          const bad = rows.filter((i) => i.state !== "ok" && i.state !== "no_sbom").length;
          return (
            <>
              {failed}
              <Text bold>{rows.length}</Text> images · <Text color="green">{count("ok")} scanned</Text> ·{" "}
              <Text color="red">{rows.filter((i) => i.stale).length} stale</Text> · <Text color="red">{bad} refused</Text> ·{" "}
              <Text color="yellow">{count("no_sbom")} without an SBOM</Text>
              <Text dimColor> · sorted by {sortedBy}</Text>
              {status(report.generatedAt)}
            </>
          );
        }}
      />
    );
  }

  const report = findings.data!;
  const shieldCounts = <R extends { status: FindingStatus }>(rows: readonly R[]) => {
    const count = (s: FindingStatus) => rows.filter((r) => r.status === s).length;
    return (
      <>
        <Text color="red">{count("no_shield")} no shield</Text> · <Text color="yellow">{count("partial")} partial</Text> ·{" "}
        <Text color="yellow">{count("pending")} pending</Text> · <Text color="green">{count("shielded")} shielded</Text>
      </>
    );
  };
  return (
    <Box flexDirection="column">
      {detail && <FindingDetail finding={detailFinding} height={tableHeight} active={active} onClose={() => setDetail(null)} />}
      {/* Hidden, not unmounted, so the tables keep their cursor, sort and search. */}
      <Box flexDirection="column" display={detail ? "none" : "flex"}>
        {mode === "findings" ? (
          <DataTable
            key={`findings:${drill}`}
            tabs={tabs}
            startOnTabs={onTabs}
            footerHint={footerHint}
            rows={report.findings}
            columns={FINDING_COLUMNS}
            rowKey={findingKey}
            height={tableHeight}
            active={active && !paneOpen}
            initialSort={{ col: "status", dir: "asc" }}
            initialQuery={drill}
            tiebreak={findingTiebreak}
            searchFields={findingFields}
            onSearchingChange={reportSearching}
            onClose={onClose}
            onOpen={(f) => setDetail(findingKey(f))}
            summary={(rows, sortedBy) => (
              <>
                {failed}
                <Text bold>{rows.length}</Text> findings · {shieldCounts(rows)}
                {rows.some((f) => f.stale) && <Text color="red"> · from a stale scan</Text>}
                <Text dimColor> · sorted by {sortedBy}</Text>
                {status(report.generatedAt)}
              </>
            )}
          />
        ) : (
          <>
            {openVuln && (
              <VulnDetail
                vuln={vulnDetail}
                height={tableHeight}
                active={active && !detail}
                onClose={() => setOpenVuln(null)}
                onOpen={(f) => setDetail(findingKey(f))}
                onSearchingChange={reportSearching}
              />
            )}
            <Box flexDirection="column" display={openVuln ? "none" : "flex"}>
              <DataTable
                tabs={tabs}
                startOnTabs={onTabs}
                footerHint={footerHint}
                rows={vulns}
                columns={VULN_COLUMNS}
                rowKey={(v) => v.vulnId}
                height={tableHeight}
                active={active && !paneOpen}
                initialSort={{ col: "status", dir: "asc" }}
                tiebreak={vulnTiebreak}
                searchFields={vulnFields}
                onSearchingChange={reportSearching}
                onClose={onClose}
                onOpen={(v) => setOpenVuln(v.vulnId)}
                summary={(rows, sortedBy) => (
                  <>
                    {failed}
                    <Text bold>{rows.length}</Text> vulnerabilities in{" "}
                    {rows.reduce((n, v) => n + v.findings.length, 0)} findings · {shieldCounts(rows)}
                    {rows.some((v) => v.stale) && <Text color="red"> · from a stale scan</Text>}
                    <Text dimColor> · sorted by {sortedBy}</Text>
                    {status(report.generatedAt)}
                  </>
                )}
              />
            </Box>
          </>
        )}
      </Box>
    </Box>
  );
}
