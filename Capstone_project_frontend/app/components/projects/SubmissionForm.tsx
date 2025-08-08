"use client";

import { useState, useEffect } from "react";
import { projectsApi } from "@/app/api/api";
import { Loader2, Upload } from "lucide-react";

interface SubmissionFormProps {
    projectId: number | string;
    phase: "phase1" | "phase2";
    onSubmissionSuccess?: () => void;
    projectState?: 'active' | 'past';
}

export default function SubmissionForm({ projectId, phase, onSubmissionSuccess, projectState }: SubmissionFormProps) {
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [previewUrl, setPreviewUrl] = useState<string | null>(null);
    const [status, setStatus] = useState<{
        loading: boolean;
        error: string | null;
        success: boolean;
    }>({
        loading: false,
        error: null,
        success: false,
    });

    if (projectState === 'past') {
        return (
            <div className="border border-gray-300 rounded-lg p-6 bg-gray-50">
                <h4 className="text-lg font-semibold mb-4">Submit Your Solution for {phase === "phase1" ? "Phase 1" : "Phase 2"}</h4>
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-yellow-800">
                    <p className="font-medium">This project is no longer accepting submissions</p>
                    <p className="text-sm mt-1">The project has been marked as past and is not accepting new submissions.</p>
                </div>
            </div>
        );
    }

    useEffect(() => {
        if (selectedFile) {
            const url = URL.createObjectURL(selectedFile);
            setPreviewUrl(url);
            return () => URL.revokeObjectURL(url);
        } else {
            setPreviewUrl(null);
        }
    }, [selectedFile]);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0] || null;

        if (file && file.type !== "application/pdf") {
            setStatus({
                loading: false,
                error: "Only PDF files are allowed",
                success: false,
            });
            setSelectedFile(null);
            return;
        }

        setSelectedFile(file);
        setStatus({ loading: false, error: null, success: false });
    };

    const handleSubmit = async () => {
        if (!selectedFile) return;

        setStatus({ loading: true, error: null, success: false });

        try {
            const formData = new FormData();
            formData.append("file", selectedFile);

            if (phase === "phase1") {
                await projectsApi.submitPhase1Solution(projectId.toString(), formData);
            } else if (phase === "phase2") {
                await projectsApi.submitPhase2Solution(projectId.toString(), formData);
            }

            setStatus({ loading: false, error: null, success: true });
            setSelectedFile(null);

            if (onSubmissionSuccess) {
                onSubmissionSuccess();
            }
        } catch (err: any) {
            setStatus({ loading: false, error: err.message || "Failed to submit solution", success: false });
        }
    };

    return (
        <div className="border border-gray-300 rounded-lg p-6 bg-gray-50">
            <h4 className="text-lg font-semibold mb-4">Submit Your Solution for {phase === "phase1" ? "Phase 1" : "Phase 2"}</h4>

            {!selectedFile ? (
                <label
                    htmlFor={`file-upload-${phase}`}
                    className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-gray-400 rounded-lg cursor-pointer hover:bg-gray-100 transition-colors"
                >
                    <Upload className="w-8 h-8 mb-3 text-gray-500" />
                    <p className="text-sm text-gray-600">
                        Click to upload or drag and drop your PDF solution
                    </p>
                    <p className="text-xs text-gray-400">PDF files only</p>
                    <input
                        id={`file-upload-${phase}`}
                        type="file"
                        accept=".pdf"
                        className="hidden"
                        onChange={handleFileChange}
                    />
                </label>
            ) : (
                <div className="flex flex-col gap-4">
                    <div className="flex items-center justify-between bg-white p-4 border border-gray-300 rounded-md">
                        <p className="truncate max-w-xs">{selectedFile.name}</p>
                        <button
                            onClick={() => setSelectedFile(null)}
                            className="text-red-600 hover:text-red-800"
                            aria-label="Remove selected file"
                        >
                            ✕
                        </button>
                    </div>

                    <div className="w-full h-280 border border-gray-300 rounded-lg overflow-hidden bg-white">
                        <iframe
                            src={previewUrl || undefined}
                            className="w-full h-full"
                            title="PDF preview"
                            aria-label="PDF preview"
                        />
                    </div>
                </div>
            )}

            <button
                onClick={handleSubmit}
                disabled={!selectedFile || status.loading}
                className="mt-4 w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 rounded-md disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
                {status.loading ? (
                    <Loader2 className="h-5 w-5 mx-auto animate-spin" />
                ) : (
                    "Submit Solution"
                )}
            </button>

            {status.error && <p className="mt-2 text-red-600">{status.error}</p>}
            {status.success && <p className="mt-2 text-green-600">Submission successful!</p>}
        </div>
    );
}