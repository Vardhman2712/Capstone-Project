"use client";

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { projectsApi } from '@/app/api/api';
import { useAuth } from '@/app/context/AuthContext';
import MultiFileUpload from '@/app/components/projects/MultiFileUpload';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { Clock4 } from 'lucide-react';
import Link from 'next/link';

interface FileState {
    problem_statement: File | null;
    dataset: File | null;
    additional_resource: File | null;
}

// Move ProjectForm component outside to prevent recreation on every render
const ProjectForm = ({
    title, setTitle,
    description, setDescription,
    firstDeadline, setFirstDeadline,
    finalDeadline, setFinalDeadline,
    files, handleFileSelect,
    handleSubmit,
    error, success,
    loading, isSubmitting,
    debugInfo,
    router
}) => (
    <div className="max-w-4xl mx-auto mt-10 mb-16">
        <div className="bg-white shadow-md border border-gray-200 rounded-lg overflow-hidden">
            <div className="px-6 py-5 border-b border-gray-100">
                <h1 className="text-2xl font-bold text-black">Create New Project</h1>
            </div>

            <form onSubmit={handleSubmit} className="p-6 text-gray-800">
                {/* Error and success messages */}
                {error && (
                    <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
                        <h3 className="text-red-600 font-medium">Error:</h3>
                        <p className="text-red-500 text-sm">{error}</p>
                        {debugInfo && (
                            <details className="mt-2 text-xs text-red-400">
                                <summary>Debug info</summary>
                                <pre>{JSON.stringify(debugInfo, null, 2)}</pre>
                            </details>
                        )}
                    </div>
                )}
                {success && (
                    <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-md">
                        <p className="text-green-600">Project created successfully!</p>
                    </div>
                )}

                {/* Project details form */}
                <div className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                            Project Title
                        </label>
                        <input
                            type="text"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 focus:border-black focus:outline-none focus:ring-1 focus:ring-black"
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                            Description
                        </label>
                        <textarea
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            rows={4}
                            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 focus:border-black focus:outline-none focus:ring-1 focus:ring-black"
                            required
                        />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                Phase 1 Deadline
                            </label>
                            <input
                                type="date"
                                value={firstDeadline}
                                onChange={(e) => setFirstDeadline(e.target.value)}
                                min={new Date().toISOString().split('T')[0]}
                                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 focus:border-black focus:outline-none focus:ring-1 focus:ring-black"
                                required
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                Final Deadline
                            </label>
                            <input
                                type="date"
                                value={finalDeadline}
                                onChange={(e) => setFinalDeadline(e.target.value)}
                                min={firstDeadline || new Date().toISOString().split('T')[0]}
                                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 focus:border-black focus:outline-none focus:ring-1 focus:ring-black"
                                required
                            />
                        </div>
                    </div>

                    {/* File upload section */}
                    <div className="border-t pt-6">
                        <h3 className="text-lg font-medium text-black mb-4">Project Files (Optional)</h3>
                        <p className="text-sm text-gray-600 mb-6">
                            You can upload files now or add them later. All files are optional during project creation.
                        </p>

                        <MultiFileUpload
                            onFileSelect={handleFileSelect}
                            files={files}
                        />
                    </div>
                </div>

                <div className="mt-8 flex justify-end">
                    <button
                        type="button"
                        onClick={() => router.back()}
                        className="mr-2 px-4 py-2 border border-gray-300 rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                        disabled={loading || isSubmitting}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        className="px-4 py-2 bg-black text-white rounded-md hover:bg-gray-900 focus:ring-2 focus:ring-offset-2 focus:ring-black disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-gray-400"
                        disabled={loading || isSubmitting}
                    >
                        {loading ? (
                            <span className="flex items-center">
                                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                Creating Project...
                            </span>
                        ) : success ? 'Project Created!' : 'Create Project'}
                    </button>
                </div>
            </form>
        </div>
    </div>
);

export default function ProjectCreatePage() {
    const { user } = useAuth();
    const router = useRouter();
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [firstDeadline, setFirstDeadline] = useState('');
    const [finalDeadline, setFinalDeadline] = useState('');
    const [files, setFiles] = useState<FileState>({
        problem_statement: null,
        dataset: null,
        additional_resource: null
    });
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [debugInfo, setDebugInfo] = useState<any>(null);
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleFileSelect = (fileType: keyof FileState, file: File | null) => {
        setFiles(prev => ({
            ...prev,
            [fileType]: file
        }));
    };

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();

        // Prevent multiple submissions
        if (isSubmitting || loading) {
            return;
        }

        setError(null);
        setDebugInfo(null);

        if (!title.trim() || !description.trim()) {
            setError('Title and description are required');
            return;
        }

        if (!firstDeadline || !finalDeadline) {
            setError('Both deadlines must be provided');
            return;
        }

        const firstDate = new Date(firstDeadline);
        const finalDate = new Date(finalDeadline);

        if (firstDate >= finalDate) {
            setError('First deadline must be before final deadline');
            return;
        }

        try {
            setLoading(true);
            setIsSubmitting(true);

            // First create the project
            const projectData = {
                title,
                description,
                firstDeadline: firstDate.toISOString(),
                finalDeadline: finalDate.toISOString(),
                accessRoles: [
                    { role: "student", canView: true, canEdit: false, canSubmit: true },
                    { role: "teacher", canView: true, canEdit: true, canSubmit: false }
                ]
            };

            const response = await projectsApi.createProject(projectData);

            if (!response?.project?.id) {
                throw new Error('Invalid server response: missing project ID');
            }

            const projectId = response.project.id;

            // Then upload all files if they exist
            const fileUploadPromises = Object.entries(files)
                .filter(([_, file]) => file !== null)
                .map(async ([fileType, file]) => {
                    if (!file) return;

                    const formData = new FormData();
                    formData.append("file", file);

                    try {
                        await projectsApi.uploadProjectFile(
                            projectId,
                            formData,
                            fileType
                        );
                    } catch (uploadError) {
                        console.error(`Error uploading ${fileType}:`, uploadError);
                        throw new Error(`Failed to upload ${fileType}: ${uploadError.message}`);
                    }
                });

            if (fileUploadPromises.length > 0) {
                await Promise.all(fileUploadPromises);
            }

            setSuccess(true);
            setTimeout(() => {
                router.push(`/projects/${projectId}`);
            }, 1500);

        } catch (err) {
            console.error('Error creating project:', err);
            setError(err instanceof Error ? err.message : 'Failed to create project');
            setDebugInfo({
                error: err instanceof Error ? err.toString() : 'Unknown error',
                stack: err instanceof Error ? err.stack : undefined
            });
        } finally {
            setLoading(false);
            setIsSubmitting(false);
        }
    };

    // First check: Loading state
    if (approvalLoading) {
        return (
            <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    // Second check: Authentication
    if (!user) {
        return (
            <div className="flex justify-center items-center h-screen">
                <div className="text-center">
                    <h1 className="text-2xl font-bold mb-4">Please log in</h1>
                    <Link href="/login" className="text-blue-500 hover:text-blue-700">
                        Go to Login
                    </Link>
                </div>
            </div>
        );
    }

    // Third check: Admin bypass - use the ProjectForm component
    if (user.role === 'admin') {
        return (
            <ProjectForm
                title={title}
                setTitle={setTitle}
                description={description}
                setDescription={setDescription}
                firstDeadline={firstDeadline}
                setFirstDeadline={setFirstDeadline}
                finalDeadline={finalDeadline}
                setFinalDeadline={setFinalDeadline}
                files={files}
                handleFileSelect={handleFileSelect}
                handleSubmit={handleSubmit}
                error={error}
                success={success}
                loading={loading}
                isSubmitting={isSubmitting}
                debugInfo={debugInfo}
                router={router}
            />
        );
    }

    // Fourth check: Student permission
    if (user.role === 'student') {
        return (
            <div className="max-w-2xl mx-auto mt-10 p-6 bg-white border border-red-300 rounded-lg text-center">
                <div className="flex flex-col items-center">
                    <svg className="w-10 h-10 text-red-500 mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <h2 className="text-xl font-semibold text-black">Permission Denied</h2>
                    <p className="mt-2 text-gray-600">You do not have permission to create a project. Please contact your teacher or administrator.</p>
                </div>
            </div>
        );
    }

    // Fifth check: Approval status for non-admin users
    if (!isApproved) {
        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
                <div className="max-w-md w-full space-y-8 text-center">
                    <div className="flex flex-col items-center">
                        <Clock4 className="h-12 w-12 text-indigo-600 mb-4" />
                        <h2 className="text-2xl font-bold text-gray-900">Account Pending Approval</h2>
                    </div>
                    <div className="mt-4 text-gray-600">
                        <p>Your account is currently pending approval from an administrator.</p>
                        <p className="mt-2">You will be able to create projects once your account is approved.</p>
                    </div>
                    <div className="mt-4 text-sm text-gray-500">
                        <p>Please contact an administrator if you have any questions.</p>
                    </div>
                </div>
            </div>
        );
    }

    // Final case: Approved user - use the ProjectForm component
    return (
        <ProjectForm
            title={title}
            setTitle={setTitle}
            description={description}
            setDescription={setDescription}
            firstDeadline={firstDeadline}
            setFirstDeadline={setFirstDeadline}
            finalDeadline={finalDeadline}
            setFinalDeadline={setFinalDeadline}
            files={files}
            handleFileSelect={handleFileSelect}
            handleSubmit={handleSubmit}
            error={error}
            success={success}
            loading={loading}
            isSubmitting={isSubmitting}
            debugInfo={debugInfo}
            router={router}
        />
    );
}