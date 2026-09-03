"use client";

import { useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Copy,
  Download,
  FileCode2,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";

import { useCbom, useCbomValidation, useReport } from "@/lib/queries";
import { exportUrl } from "@/lib/api-client";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function ReportsPage() {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState("executive");

  const reportQuery = useReport(true);
  const validationQuery = useCbomValidation();
  const cbomQuery = useCbom(activeTab === "cbom_raw");

  const handleCopyReport = () => {
    if (reportQuery.data) {
      void navigator.clipboard.writeText(reportQuery.data);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <PageShell>
      <PageHeader
        title="Reports & CBOM"
        question="Export compliance documents and machine-readable Cryptography Bills of Materials."
        description="ECDAT generates formal executive text reports, CSV data dumps, and validated CycloneDX 1.6 Cryptography Bill of Materials (CBOM) documents."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void reportQuery.refetch();
              void validationQuery.refetch();
              void cbomQuery.refetch();
            }}
            disabled={reportQuery.isFetching}
          >
            <RefreshCw className={reportQuery.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Export Downloads Strip */}
      <Section
        title="Data Exports"
        description="Download inventory, roadmap, and graph datasets in standardized formats"
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <ExportCard
            title="Assets Inventory (CSV)"
            description="Full canonical asset fields for spreadsheets and data warehouses."
            href={exportUrl("assets.csv")}
            icon={FileSpreadsheet}
          />
          <ExportCard
            title="Migration Roadmap (CSV)"
            description="Phase-by-phase execution items, effort months, and dependencies."
            href={exportUrl("roadmap.csv")}
            icon={FileSpreadsheet}
          />
          <ExportCard
            title="Blast Radius & Impact (CSV)"
            description="Graph coupling metrics, affected applications, and gating reach."
            href={exportUrl("impact.csv")}
            icon={FileSpreadsheet}
          />
          <ExportCard
            title="Complete Estate (JSON)"
            description="Full programmatic JSON dump of the current scan results."
            href={exportUrl("json")}
            icon={FileCode2}
          />
        </div>
      </Section>

      {/* Main Tabs for Executive Report vs CBOM */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="executive">Executive Summary Report</TabsTrigger>
          <TabsTrigger value="cbom_status">CBOM Validation (CycloneDX 1.6)</TabsTrigger>
          <TabsTrigger value="cbom_raw">Raw CBOM Document</TabsTrigger>
        </TabsList>

        {/* Tab 1: Executive Text Report */}
        <TabsContent value="executive" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileText className="size-4 text-primary" />
                Executive Cryptographic Discovery Report
              </CardTitle>
              <Button variant="outline" size="sm" onClick={handleCopyReport} disabled={!reportQuery.data}>
                <Copy className="mr-1.5 size-3.5" />
                {copied ? "Copied!" : "Copy Report"}
              </Button>
            </CardHeader>
            <CardContent className="pt-4">
              {reportQuery.isPending ? (
                <PanelSkeleton lines={10} />
              ) : reportQuery.isError ? (
                <ErrorState error={reportQuery.error} onRetry={() => reportQuery.refetch()} />
              ) : reportQuery.data ? (
                <pre className="max-h-[600px] overflow-auto rounded-md bg-muted/40 p-4 font-mono text-xs leading-relaxed text-foreground whitespace-pre-wrap">
                  {reportQuery.data}
                </pre>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 2: CBOM Validation */}
        <TabsContent value="cbom_status" className="space-y-4">
          <Card>
            <CardHeader className="border-b pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldCheck className="size-4 text-primary" />
                  CycloneDX 1.6 CBOM Schema Conformance
                </CardTitle>
                {validationQuery.data ? (
                  validationQuery.data.valid ? (
                    <Badge variant="outline" className="border-success text-success bg-success/10 gap-1 font-mono text-xs">
                      <CheckCircle2 className="size-3" />
                      Schema Valid
                    </Badge>
                  ) : (
                    <Badge variant="destructive" className="gap-1 font-mono text-xs">
                      <AlertCircle className="size-3" />
                      {validationQuery.data.error_count} Schema Errors
                    </Badge>
                  )
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="pt-4 space-y-4 text-xs">
              {validationQuery.isPending ? (
                <PanelSkeleton lines={6} />
              ) : validationQuery.isError ? (
                <ErrorState error={validationQuery.error} onRetry={() => validationQuery.refetch()} />
              ) : validationQuery.data ? (
                <div className="space-y-4">
                  <div className="rounded-md border p-3 space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Schema Specification</span>
                      <span className="font-mono text-foreground">{validationQuery.data.schema}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Validation Scope</span>
                      <span className="font-medium text-foreground">{validationQuery.data.scope}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Claim Bound</span>
                      <span className="text-muted-foreground italic">{validationQuery.data.claim}</span>
                    </div>
                  </div>

                  {validationQuery.data.errors && validationQuery.data.errors.length > 0 ? (
                    <div className="space-y-2">
                      <h4 className="font-semibold text-destructive">Validation Errors:</h4>
                      <ul className="list-disc pl-5 text-destructive font-mono text-[11px] space-y-1">
                        {validationQuery.data.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 rounded-md bg-success/10 p-3 text-success">
                      <CheckCircle2 className="size-4 shrink-0" />
                      <span>
                        The generated Cryptography Bill of Materials is 100% compliant with the official CycloneDX 1.6 JSON schema without any dangling dependency refs or unredacted secrets.
                      </span>
                    </div>
                  )}
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 3: Raw CBOM JSON */}
        <TabsContent value="cbom_raw" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileCode2 className="size-4 text-primary" />
                Raw CycloneDX 1.6 Document
              </CardTitle>
              <Button asChild variant="outline" size="sm">
                <a href={exportUrl("json")} download="cbom-cyclonedx.json">
                  <Download className="mr-1.5 size-3.5" />
                  Download JSON
                </a>
              </Button>
            </CardHeader>
            <CardContent className="pt-4">
              {cbomQuery.isPending ? (
                <PanelSkeleton lines={10} />
              ) : cbomQuery.isError ? (
                <ErrorState error={cbomQuery.error} onRetry={() => cbomQuery.refetch()} />
              ) : cbomQuery.data ? (
                <pre className="max-h-[600px] overflow-auto rounded-md bg-muted/40 p-4 font-mono text-[11px] leading-relaxed text-foreground">
                  {JSON.stringify(cbomQuery.data, null, 2)}
                </pre>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </PageShell>
  );
}

function ExportCard({
  title,
  description,
  href,
  icon: Icon,
}: {
  title: string;
  description: string;
  href: string;
  icon: typeof FileSpreadsheet;
}) {
  return (
    <Card className="flex flex-col justify-between p-4 transition-colors hover:border-primary/50">
      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <Icon className="size-4 text-primary" />
          <h3 className="font-semibold text-xs text-foreground">{title}</h3>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">{description}</p>
      </div>

      <Button asChild variant="outline" size="sm" className="mt-3 w-full justify-start text-xs">
        <a href={href} download>
          <Download className="mr-1.5 size-3.5" />
          Download
        </a>
      </Button>
    </Card>
  );
}
