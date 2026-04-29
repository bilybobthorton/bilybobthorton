"use client";
import { useCallback, useState } from "react";
import { Upload, Loader2, File } from "lucide-react";
import { submitScan, pollScan, ScanResult } from "@/lib/api";
import { ScanResult as ScanResultComponent } from "./ScanResult";

type Status = "idle" | "uploading" | "polling" | "done" | "error";

export function ScanUpload() {
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [dragging, setDragging] = useState(false);

  const runScan = useCallback(async (file: File) => {
    setStatus("uploading");
    setResult(null);
    setErrorMsg("");
    try {
      const submitted = await submitScan(file);
      setStatus("polling");

      // Poll until complete or failed
      let attempts = 0;
      while (attempts < 60) {
        await new Promise((r) => setTimeout(r, 2000));
        const scan = await pollScan(submitted.scan_id);
        if (scan.status === "complete" || scan.status === "failed") {
          setResult(scan);
          setStatus("done");
          return;
        }
        attempts++;
      }
      throw new Error("Scan timed out");
    } catch (e: any) {
      setErrorMsg(e.message ?? "Unknown error");
      setStatus("error");
    }
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) runScan(file);
  }, [runScan]);

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) runScan(file);
  };

  const busy = status === "uploading" || status === "polling";

  return (
    <div className="space-y-6">
      <label
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`
          flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed
          cursor-pointer transition-colors p-12
          ${dragging ? "border-red-500 bg-red-950/20" : "border-slate-700 bg-slate-900/40 hover:border-slate-500"}
          ${busy ? "pointer-events-none opacity-60" : ""}
        `}
      >
        <input type="file" className="hidden" onChange={onChange} disabled={busy} />
        {busy ? (
          <>
            <Loader2 size={32} className="text-red-500 animate-spin" />
            <p className="text-sm text-slate-400">
              {status === "uploading" ? "Uploading..." : "Analyzing file..."}
            </p>
          </>
        ) : (
          <>
            <Upload size={32} className="text-slate-500" />
            <div className="text-center">
              <p className="text-sm font-medium text-slate-300">Drop a file here or click to browse</p>
              <p className="text-xs text-slate-500 mt-1">PE, ELF, scripts, documents — up to 100MB</p>
            </div>
          </>
        )}
      </label>

      {status === "error" && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 px-4 py-3 text-sm text-red-400">
          {errorMsg}
        </div>
      )}

      {result && <ScanResultComponent result={result} />}
    </div>
  );
}
