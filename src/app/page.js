"use client";

import { useState, useRef, useCallback } from "react";

export default function Home() {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const inputRef = useRef(null);

  const handleFile = useCallback((selected) => {
    if (!selected) return;
    if (!selected.type.startsWith("image/")) {
      setError("Please upload an image file (PNG, JPG, etc).");
      return;
    }
    setError(null);
    setResult(null);
    setFile(selected);
    setPreviewUrl(URL.createObjectURL(selected));
  }, []);

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files?.[0];
    handleFile(dropped);
  };

  const clearFile = () => {
    setFile(null);
    setPreviewUrl(null);
    setResult(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  };

  const analyze = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Something went wrong while analyzing the image.");
        return;
      }

      setResult(data);
    } catch (err) {
      setError("Could not reach the analysis engine. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const verdictClass = result?.analysis?.verdict?.toLowerCase() || "";

  return (
    <main className="page">
      <div className="header">
        <div className="logo-mark">Q</div>
        <div>
          <div className="brand-name">QRizon</div>
          <div className="brand-tag">Malicious QR Code Detection &amp; Risk Analysis</div>
        </div>
      </div>

      <p className="tagline">
        Upload an image of a QR code and QRizon will decode it, run it through a
        security heuristics engine, and give you a clear verdict before you ever open the link.
      </p>

      <div
        className={`dropzone ${dragging ? "dragging" : ""}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <div className="dropzone-icon">📷</div>
        <div className="dropzone-title">Drop a QR code image here, or click to browse</div>
        <div className="dropzone-sub">PNG, JPG, or WEBP — analyzed instantly, nothing is stored</div>
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
      </div>

      {file && (
        <div className="preview-row">
          {previewUrl && <img src={previewUrl} alt="QR preview" className="preview-thumb" />}
          <div className="preview-info">
            <div className="preview-name">{file.name}</div>
            <div className="preview-size">{(file.size / 1024).toFixed(1)} KB</div>
          </div>
          <button className="btn-clear" onClick={clearFile}>Clear</button>
        </div>
      )}

      <div className="actions">
        <button className="btn-primary" onClick={analyze} disabled={!file || loading}>
          {loading ? "Analyzing..." : "Analyze QR Code"}
        </button>
      </div>

      {loading && (
        <div className="loading-row">
          <div className="spinner" />
          Analyzing threats...
        </div>
      )}

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className={`result-card ${verdictClass}`}>
          <div className="verdict-row">
            <div>
              <div className="verdict-label">Threat Verdict</div>
              <div className="verdict-title">{result.analysis.verdict}</div>
            </div>
            <div className="score-badge">
              <div className="score-number">{result.analysis.score}</div>
              <div className="score-out-of">/ 100 safety score</div>
            </div>
          </div>

          <div className="decoded-url">{result.decoded}</div>

          <div className="flags-title">Security Flags</div>
          {result.analysis.flags.length > 0 ? (
            <ul className="flags-list">
              {result.analysis.flags.map((flag) => (
                <li key={flag.id} className="flag-item">
                  <span className={`flag-severity ${flag.severity}`} />
                  <span>{flag.message}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="no-flags">No suspicious indicators were detected.</div>
          )}
        </div>
      )}

      <div className="footer">
        QRizon performs rule-based heuristic analysis only. Always exercise caution before visiting unfamiliar links.
      </div>
    </main>
  );
}
