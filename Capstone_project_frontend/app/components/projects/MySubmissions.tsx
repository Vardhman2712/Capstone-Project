'use client';

import { useEffect, useState } from "react";
import Image from "next/image";
import pdf from "../../../public/pdf.jpg";
import {
    CheckCircle2,
    Clock,
    FileText,
    AlertCircle,
    Loader2,
    Clock4,
} from "lucide-react";
import { projectsApi } from "../../api/api";
import Link from "next/link";
import { useRouter } from 'next/navigation';
import { useApprovalStatus } from '../../hooks/useApprovalStatus';

interface File {
    id: number;
    project_id: number;
    file_name: string;
    file_url: string;
    file_type: string;
}

interface Submission {
    id: number;
    project_id: number;
    student_id: number;
    file_name: string;
    file_url: string;
    submitted_at: string;
    phase: number;
    status: string;
}

interface Project {
    id: number;
    title: string;
    description: string;
    created_at: string;
    hasSubmittedPhase1: boolean;
    hasSubmittedPhase2: boolean;
    phase1Submission?: Submission | null;
    phase2Submission?: Submission | null;
    files: File[] | null;
    phase1DeadlinePassed: boolean;
    phase2DeadlinePassed: boolean;
}

const MySubmissions = () => {
    const [projects, setProjects] = useState<Project[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<{ type: string; message: string } | null>(null);
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();
    const router = useRouter();

    useEffect(() => {
        // Only fetch projects if user is approved
        if (isApproved === false) {
            router.push('/pending-approval');
            return;
        }

        if (isApproved === true) {
            const fetchProjects = async () => {
                try {
                    setIsLoading(true);
                    const data = await projectsApi.getStudentProjects();
                    const uniqueMap = new Map<number, Project>();

                    (data.projects || []).forEach((p: any) => {
                        uniqueMap.set(p.id, {
                            ...p,
                            hasSubmitted: p.hasSubmittedPhase1 && p.hasSubmittedPhase2,
                        });
                    });

                    setProjects(Array.from(uniqueMap.values()));
                } catch (err) {
                    console.error(err);
                    if (err instanceof Error) {
                        if ('code' in err) {
                            switch (err.code) {
                                case 'PENDING_APPROVAL':
                                    router.push('/pending-approval');
                                    break;
                                case 'FORBIDDEN':
                                    setError({
                                        type: 'forbidden',
                                        message: err.message || 'You do not have permission to access this resource.'
                                    });
                                    break;
                                case 'UNAUTHORIZED':
                                    setError({
                                        type: 'unauthorized',
                                        message: err.message || 'Your session has expired. Please log in again.'
                                    });
                                    router.push('/login');
                                    break;
                                default:
                                    setError({
                                        type: 'error',
                                        message: err.message || 'Failed to load projects. Please try again later.'
                                    });
                            }
                        } else {
                            setError({
                                type: 'error',
                                message: err.message || 'Failed to load projects. Please try again later.'
                            });
                        }
                    } else {
                        setError({
                            type: 'error',
                            message: 'An unexpected error occurred. Please try again later.'
                        });
                    }
                } finally {
                    setIsLoading(false);
                }
            };

            fetchProjects();
        }
    }, [isApproved, router]);

    const formatDate = (dateString: string) => {
        const date = new Date(dateString);
        return date.toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric",
        });
    };

    const getLatestSubmission = (project: Project) => {
        const submissions = [];
        if (project.phase1Submission) submissions.push(project.phase1Submission);
        if (project.phase2Submission) submissions.push(project.phase2Submission);

        return submissions.sort(
            (a, b) => new Date(b.submitted_at).getTime() - new Date(a.submitted_at).getTime()
        )[0];
    };

    const getProjectStatus = (project: Project) => {
        if (project.hasSubmittedPhase1 && project.hasSubmittedPhase2) return 'completed';
        if (project.phase1DeadlinePassed || project.phase2DeadlinePassed) return 'overdue';
        return 'pending';
    };

    const submittedProjects = projects.filter(p =>
        p.hasSubmittedPhase1 && p.hasSubmittedPhase2
    );

    const pendingProjects = projects.filter(p =>
        !p.hasSubmittedPhase1 || !p.hasSubmittedPhase2
    );

    if (approvalLoading || isLoading) {
        return (
            <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className={`max-w-xl mx-auto mt-12 p-8 rounded-xl shadow-sm text-center ${error.type === 'pending'
                ? 'bg-yellow-50 border border-yellow-200'
                : error.type === 'forbidden'
                    ? 'bg-red-50 border border-red-200'
                    : 'bg-red-100 border border-red-400'
                }`}>
                <div className="mb-4">
                    {error.type === 'pending' && (
                        <Clock4 className="h-12 w-12 text-yellow-500 mx-auto" />
                    )}
                    {error.type === 'forbidden' && (
                        <FileText className="h-12 w-12 text-red-500 mx-auto" />
                    )}
                    {error.type === 'error' && (
                        <FileText className="h-12 w-12 text-red-600 mx-auto" />
                    )}
                </div>
                <h3 className={`text-xl font-semibold mb-2 ${error.type === 'pending'
                    ? 'text-yellow-800'
                    : error.type === 'forbidden'
                        ? 'text-red-800'
                        : 'text-red-700'
                    }`}>
                    {error.type === 'pending' ? 'Account Pending Approval' : 'Error'}
                </h3>
                <p className={`mb-6 ${error.type === 'pending'
                    ? 'text-yellow-700'
                    : error.type === 'forbidden'
                        ? 'text-red-700'
                        : 'text-red-600'
                    }`}>
                    {error.message}
                </p>
                <button
                    className={`px-4 py-2 rounded-md transition-colors ${error.type === 'pending'
                        ? 'bg-yellow-100 hover:bg-yellow-200 text-yellow-700'
                        : 'bg-red-100 hover:bg-red-200 text-red-700'
                        }`}
                    onClick={() => window.location.reload()}
                >
                    Try Again
                </button>
            </div>
        );
    }

    if (projects.length === 0) {
        return (
            <div className="max-w-xl mx-auto mt-12 p-8 bg-gray-50 border border-gray-200 rounded-xl shadow-sm text-center">
                <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-gray-800 mb-2">No Projects Available</h3>
                <p className="text-gray-600 mb-6">
                    There are currently no projects assigned to you. Check back later or contact your instructor.
                </p>
                <button
                    className="px-4 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors"
                    onClick={() => window.location.reload()}
                >
                    Refresh
                </button>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto p-4 md:p-8">
            <div className="mb-12">
                <h1 className="text-3xl md:text-4xl font-bold text-gray-900 text-center">
                    My Project Submissions
                </h1>
                <p className="text-gray-600 text-center mt-2 max-w-2xl mx-auto">
                    Track your academic projects and their submission status.
                </p>
            </div>

            {submittedProjects.length > 0 && (
                <section className="mb-16">
                    <div className="flex items-center mb-6 space-x-3">
                        <h2 className="text-xl md:text-2xl font-bold text-gray-800">
                            Submitted Projects
                        </h2>
                        <div className="h-6 px-3 flex items-center bg-green-100 text-green-800 text-sm font-medium rounded-full">
                            {submittedProjects.length}
                        </div>
                    </div>

                    <div className="grid gap-6">
                        {submittedProjects.map((project) => {
                            const status = getProjectStatus(project);
                            const latestSubmission = getLatestSubmission(project);
                            const phaseStatus = [
                                { phase: 1, data: project.phase1Submission },
                                { phase: 2, data: project.phase2Submission }
                            ];

                            return (
                                <div
                                    key={`submitted-${project.id}`}
                                    className="border border-gray-200 rounded-xl shadow-sm hover:shadow-md transition-all duration-300 bg-white overflow-hidden"
                                >
                                    <div className={`border-l-4 ${status === 'completed' ? 'border-green-500 bg-green-50' :
                                        'border-red-500 bg-red-50'
                                        } pl-4 py-3 flex items-center`}>
                                        {status === 'completed' ? (
                                            <CheckCircle2 className="text-green-600 mr-2" size={18} />
                                        ) : (
                                            <AlertCircle className="text-red-600 mr-2" size={18} />
                                        )}
                                        <span className={`font-medium ${status === 'completed' ? 'text-green-800' : 'text-red-800'
                                            }`}>
                                            {status === 'completed' ? 'Completed' : 'Overdue'}
                                        </span>
                                        {latestSubmission && (
                                            <span className="ml-auto mr-6 text-sm font-medium">
                                                Last Submission: {formatDate(latestSubmission.submitted_at)}
                                                {latestSubmission.phase === 2 && ` (Phase 2)`}
                                            </span>
                                        )}
                                        <Link
                                            href={`/projects/${project.id}`}
                                            className="ml-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-md transition-colors"
                                        >
                                            View Details
                                        </Link>
                                    </div>

                                    <div className="p-6">
                                        <div className="flex flex-col lg:flex-row">
                                            <div className="w-full lg:w-1/2 mb-6 lg:mb-0">
                                                <h3 className="text-xl font-bold text-gray-800 mb-3">
                                                    {project.title}
                                                </h3>
                                                <p className="text-gray-600 mb-4 line-clamp-3">
                                                    {project.description}
                                                </p>
                                                <div className="flex items-center text-sm text-gray-500 mb-2">
                                                    <Clock className="mr-2" size={16} />
                                                    Created: {formatDate(project.created_at)}
                                                </div>
                                            </div>

                                            <div className="w-full lg:w-1/2 lg:pl-6 lg:border-l lg:border-gray-100">
                                                <div className="grid grid-cols-2 gap-4 mb-4">
                                                    {phaseStatus.map(({ phase, data }) => (
                                                        <div
                                                            key={`phase-${phase}`}
                                                            className={`p-3 rounded-lg ${data ? 'bg-green-50' : 'bg-gray-100'
                                                                }`}
                                                        >
                                                            <div className="flex items-center">
                                                                {data ? (
                                                                    <CheckCircle2 className="h-5 w-5 text-green-600 mr-2" />
                                                                ) : (
                                                                    <Clock className="h-5 w-5 text-gray-600 mr-2" />
                                                                )}
                                                                <span className="font-medium">
                                                                    Phase {phase}
                                                                </span>
                                                            </div>
                                                            {data && (
                                                                <p className="text-sm text-gray-600 mt-1">
                                                                    Submitted: {formatDate(data.submitted_at)}
                                                                </p>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>

                                                {(project.files ?? []).length > 0 && (
                                                    <>
                                                        <h4 className="font-medium text-gray-700 mb-3 flex items-center">
                                                            <FileText className="mr-2" size={16} />
                                                            Project Files
                                                        </h4>
                                                        <div className="flex items-start space-x-4">
                                                            <div className="relative w-16 h-20 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                                <Image
                                                                    src={pdf}
                                                                    alt="File icon"
                                                                    fill
                                                                    className="object-contain p-1"
                                                                    priority
                                                                />
                                                            </div>
                                                            <div className="flex-1">
                                                                <div className="space-y-1 text-sm text-gray-600">
                                                                    {(project.files ?? []).slice(0, 3).map((file) => (
                                                                        <div
                                                                            key={`file-${file.id}`}
                                                                            className="flex items-center group"
                                                                        >
                                                                            <span className="truncate max-w-[250px]" title={file.file_name}>
                                                                                {file.file_name}
                                                                            </span>
                                                                            <a
                                                                                href={file.file_url}
                                                                                className="ml-2 opacity-0 group-hover:opacity-100 text-indigo-600 transition-opacity"
                                                                                title="Download file"
                                                                                onClick={(e) => e.stopPropagation()}
                                                                            >
                                                                                Download
                                                                            </a>
                                                                        </div>
                                                                    ))}
                                                                    {(project.files?.length ?? 0) > 3 && (
                                                                        <div className="text-indigo-600 font-medium mt-1 cursor-pointer hover:text-indigo-800 transition-colors">
                                                                            +{(project.files?.length ?? 0) - 3} more files
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </section>
            )}

            {pendingProjects.length > 0 && (
                <section>
                    <div className="flex items-center mb-6 space-x-3">
                        <h2 className="text-xl md:text-2xl font-bold text-gray-800">
                            Pending Projects
                        </h2>
                        <div className="h-6 px-3 flex items-center bg-yellow-100 text-yellow-800 text-sm font-medium rounded-full">
                            {pendingProjects.length}
                        </div>
                    </div>

                    <div className="grid gap-6">
                        {pendingProjects.map((project) => {
                            const status = getProjectStatus(project);
                            const missingPhases = [
                                !project.hasSubmittedPhase1 && 'Phase 1',
                                !project.hasSubmittedPhase2 && 'Phase 2'
                            ].filter(Boolean).join(' and ');

                            return (
                                <div
                                    key={`pending-${project.id}`}
                                    className="border border-gray-200 rounded-xl shadow-sm hover:shadow-md transition-all duration-300 bg-white overflow-hidden"
                                >
                                    <div className={`border-l-4 ${status === 'overdue' ? 'border-red-500 bg-red-50' : 'border-yellow-500 bg-yellow-50'
                                        } pl-4 py-3 flex items-center`}>
                                        {status === 'overdue' ? (
                                            <AlertCircle className="text-red-600 mr-2" size={18} />
                                        ) : (
                                            <Clock className="text-yellow-600 mr-2" size={18} />
                                        )}
                                        <span className={`font-medium ${status === 'overdue' ? 'text-red-800' : 'text-yellow-800'
                                            }`}>
                                            {status === 'overdue' ? 'Overdue' : 'Pending'}
                                        </span>
                                        <span className="ml-2 text-sm">
                                            ({missingPhases} required)
                                        </span>
                                        <Link
                                            href={`/projects/${project.id}`}
                                            className="ml-auto bg-indigo-600 hover:bg-indigo-700 text-white py-1 px-4 text-sm font-medium rounded-md transition-colors mr-6"
                                        >
                                            Submit Now
                                        </Link>
                                    </div>

                                    <div className="p-6">
                                        <div className="flex flex-col lg:flex-row">
                                            <div className="w-full lg:w-1/2 mb-6 lg:mb-0">
                                                <h3 className="text-xl font-bold text-gray-800 mb-3">
                                                    {project.title}
                                                </h3>
                                                <p className="text-gray-600 mb-4 line-clamp-3">
                                                    {project.description}
                                                </p>
                                                <div className="flex items-center text-sm text-gray-500 mb-2">
                                                    <Clock className="mr-2" size={16} />
                                                    Created: {formatDate(project.created_at)}
                                                </div>
                                            </div>

                                            {(project.files ?? []).length > 0 && (
                                                <div className="w-full lg:w-1/2 lg:pl-6 lg:border-l lg:border-gray-100">
                                                    <h4 className="font-medium text-gray-700 mb-3 flex items-center">
                                                        <FileText className="mr-2" size={16} />
                                                        Required Files
                                                    </h4>
                                                    <div className="flex items-start space-x-4">
                                                        <div className="relative w-16 h-20 flex-shrink-0 rounded-md border border-gray-200 bg-gray-50 overflow-hidden">
                                                            <Image
                                                                src={pdf}
                                                                alt="File icon"
                                                                fill
                                                                className="object-contain p-1"
                                                                priority
                                                            />
                                                        </div>
                                                        <div className="flex-1">
                                                            <div className="space-y-1 text-sm text-gray-600">
                                                                {(project.files ?? []).slice(0, 3).map((file) => (
                                                                    <div
                                                                        key={`file-${file.id}`}
                                                                        className="flex items-center group"
                                                                    >
                                                                        <span className="truncate max-w-[250px]" title={file.file_name}>
                                                                            {file.file_name}
                                                                        </span>
                                                                        <a
                                                                            href={file.file_url}
                                                                            className="ml-2 opacity-0 group-hover:opacity-100 text-indigo-600 transition-opacity"
                                                                            title="Download file"
                                                                        >
                                                                            Download
                                                                        </a>
                                                                    </div>
                                                                ))}
                                                                {(project.files?.length ?? 0) > 3 && (
                                                                    <div className="text-indigo-600 font-medium mt-1 cursor-pointer hover:text-indigo-800 transition-colors">
                                                                        +{(project.files?.length ?? 0) - 3} more files
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </section>
            )}
        </div>
    );
};

export default MySubmissions;