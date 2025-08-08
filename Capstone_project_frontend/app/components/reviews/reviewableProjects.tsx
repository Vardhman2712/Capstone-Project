'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { projectsApi } from '../../api/api';
import Link from 'next/link';

interface Project {
    id: number;
    title: string;
    description: string;
    created_by: number;
    first_deadline: string;
    final_deadline: string;
    created_at: string;
    status: string;
    approved_by?: number;
    approved_at?: string;
    files: Array<{
        id: number;
        project_id: number;
        file_name: string;
        file_url: string;
        file_type: string;
        uploaded_by: number;
        uploaded_at: string;
    }>;
    // For non-student roles
    phase1SubmissionCount?: number;
    phase2SubmissionCount?: number;
    completeSubmissionCount?: number;
    reviewCount?: number;
    phase1_reviewable?: number;
    phase2_reviewable?: number;
    reviewed_count?: number;
    reviews?: any[];
    // For student role
    hasSubmittedPhase1?: boolean;
    hasSubmittedPhase2?: boolean;
    phase1Submission?: any;
    phase2Submission?: any;
    // Computed fields
    phase1Available?: boolean;
    phase2Available?: boolean;
}

type FilterPhase = 'phase1' | 'phase2' | 'all';

export default function ReviewableProjects() {
    const { user } = useAuth();
    const [projects, setProjects] = useState<Project[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeFilter, setActiveFilter] = useState<FilterPhase>('phase1');
    const [expandedProject, setExpandedProject] = useState<number | null>(null);

    useEffect(() => {
        if (!user) return;

        const fetchProjects = async () => {
            try {
                setLoading(true);
                setError(null);
                let projectsData: Project[] = [];

                if (user.role === 'student') {
                    const response = await projectsApi.getStudentProjects();
                    projectsData = response.projects || [];

                    // Filter only projects with submissions and enhance data
                    const enhancedProjects = projectsData
                        .filter(project => project.hasSubmittedPhase1 || project.hasSubmittedPhase2)
                        .map(project => ({
                            ...project,
                            phase1Available: project.hasSubmittedPhase1 || false,
                            phase2Available: project.hasSubmittedPhase2 || false,
                            reviewed_count: project.reviews?.length || 0,
                        }));
                    setProjects(enhancedProjects);
                } else if (['teacher', 'evaluator', 'admin', 'coordinator', 'manager', 'academic_team'].includes(user.role)) {
                    const response = user.role === 'teacher'
                        ? await projectsApi.getTeacherProjects()
                        : await projectsApi.getAllProjects();
                    projectsData = response.projects || [];

                    const enhancedProjects = projectsData.map(project => {
                        const phase1Reviewable = (project.phase1SubmissionCount || 0) > (project.reviewCount || 0) ? 1 : 0;
                        const remainingReviews = Math.max(0, (project.reviewCount || 0) - (project.phase1SubmissionCount || 0));
                        const phase2Reviewable = (project.phase2SubmissionCount || 0) > remainingReviews ? 1 : 0;
                        return {
                            ...project,
                            phase1_reviewable: phase1Reviewable,
                            phase2_reviewable: phase2Reviewable,
                            reviewed_count: project.reviewCount || 0,
                        };
                    });
                    setProjects(enhancedProjects);
                } else {
                    setError("Your role doesn't have access to reviews");
                }
            } catch (err) {
                console.error('Error fetching projects:', err);
                setError(err instanceof Error ? err.message : 'Failed to load projects');
            } finally {
                setLoading(false);
            }
        };

        fetchProjects();
    }, [user]);

    const getFilteredProjects = () => {
        if (user?.role === 'student') {
            return projects.filter(project => {
                if (activeFilter === 'phase1') {
                    return project.phase1Available;
                } else if (activeFilter === 'phase2') {
                    return project.phase2Available;
                } else {
                    return project.phase1Available || project.phase2Available;
                }
            });
        } else {
            return projects.filter(project => {
                if (activeFilter === 'phase1') {
                    return (project.phase1SubmissionCount || 0) > 0;
                } else if (activeFilter === 'phase2') {
                    return (project.phase2SubmissionCount || 0) > 0;
                } else {
                    return (project.phase1SubmissionCount || 0) > 0 || (project.phase2SubmissionCount || 0) > 0;
                }
            });
        }
    };

    const getProjectCounts = () => {
        const phase1Count = projects.filter(project =>
            user?.role === 'student'
                ? project.phase1Available
                : (project.phase1SubmissionCount || 0) > 0
        ).length;

        const phase2Count = projects.filter(project =>
            user?.role === 'student'
                ? project.phase2Available
                : (project.phase2SubmissionCount || 0) > 0
        ).length;

        return { phase1Count, phase2Count };
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    const getPhaseReviews = (project: Project, phase: number) => {
        if (!project.reviews) return [];
        const targetSubmissionId = phase === 1 ? project.phase1Submission?.id : project.phase2Submission?.id;
        return project.reviews.filter(review => review.submission_id === targetSubmissionId);
    };

    const renderStudentProjectCard = (project: Project) => (
        <div key={project.id} className="bg-white border border-gray-200 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
            <div className="p-6">
                {/* Project Header */}
                <div className="flex items-start justify-between mb-4">
                    <h3 className="text-xl font-bold text-gray-900 line-clamp-2 pr-2 leading-tight">
                        {project.title || 'Untitled Project'}
                    </h3>
                    <div className={`px-3 py-1 rounded-full text-xs font-semibold whitespace-nowrap ${project.status === 'approved'
                        ? 'bg-gray-100 text-gray-800'
                        : 'bg-gray-100 text-gray-600'
                        }`}>
                        {project.status}
                    </div>
                </div>

                <p className="text-gray-600 text-sm mb-4 line-clamp-2 leading-relaxed">
                    {project.description || 'No description provided'}
                </p>

                {/* Deadlines */}
                <div className="mb-6 p-4 bg-gray-50 rounded-lg border border-gray-100">
                    <div className="grid grid-cols-2 gap-3 text-sm">
                        <div>
                            <span className="text-gray-500 block font-medium">Phase 1 Due:</span>
                            <span className="font-semibold text-gray-800">{formatDate(project.first_deadline)}</span>
                        </div>
                        <div>
                            <span className="text-gray-500 block font-medium">Final Due:</span>
                            <span className="font-semibold text-gray-800">{formatDate(project.final_deadline)}</span>
                        </div>
                    </div>
                </div>

                {/* Phase Sections */}
                <div className="space-y-4">
                    {/* Phase 1 */}
                    {project.phase1Available && (
                        <div className="border border-gray-200 rounded-lg overflow-hidden">
                            <div
                                className="bg-gray-50 p-4 cursor-pointer hover:bg-gray-100 transition-colors"
                                onClick={() => setExpandedProject(expandedProject === project.id * 10 + 1 ? null : project.id * 10 + 1)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center space-x-3">
                                        <div className="w-8 h-8 bg-violet-100 rounded-full flex items-center justify-center">
                                            <span className="text-violet-600 font-bold text-sm">1</span>
                                        </div>
                                        <div>
                                            <h4 className="font-semibold text-gray-900">Phase 1 Submission</h4>
                                            <p className="text-xs text-gray-500">
                                                Submitted: {project.phase1Submission?.submitted_at ? formatDate(project.phase1Submission.submitted_at) : 'N/A'}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="flex items-center space-x-3">
                                        {getPhaseReviews(project, 1).length > 0 && (
                                            <span className="bg-violet-100 text-violet-700 px-2 py-1 rounded-full text-xs font-medium">
                                                {getPhaseReviews(project, 1).length} Review{getPhaseReviews(project, 1).length > 1 ? 's' : ''}
                                            </span>
                                        )}
                                        <svg
                                            className={`w-5 h-5 text-gray-400 transition-transform ${expandedProject === project.id * 10 + 1 ? 'rotate-180' : ''
                                                }`}
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                        </svg>
                                    </div>
                                </div>
                            </div>

                            {expandedProject === project.id * 10 + 1 && (
                                <div className="p-4 bg-white border-t border-gray-200">
                                    {/* File Info */}
                                    <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                                        <p className="text-sm font-medium text-gray-700 mb-1">Submitted File:</p>
                                        <p className="text-sm text-gray-600">{project.phase1Submission?.file_name || 'No file'}</p>
                                    </div>

                                    {/* Reviews */}
                                    {getPhaseReviews(project, 1).length > 0 ? (
                                        <div className="space-y-3">
                                            <h5 className="font-medium text-gray-900">Reviews & Feedback</h5>
                                            {getPhaseReviews(project, 1).map((review, idx) => (
                                                <Link
                                                    href={`/review?projectId=${project.id}`}
                                                    key={idx}
                                                    className="block no-underline"
                                                >
                                                    <div key={idx} className="border border-gray-200 rounded-lg p-4">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-medium text-gray-900">{review.reviewer_name}</span>
                                                            <div className="flex items-center space-x-2">
                                                                <span className="text-xs text-gray-500">{review.reviewer_role}</span>
                                                                <div className="flex items-center space-x-1">
                                                                    <svg className="w-4 h-4 text-violet-500" fill="currentColor" viewBox="0 0 20 20">
                                                                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                                                    </svg>
                                                                    <span className="font-semibold text-gray-900">{review.rating}/10</span>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <p className="text-gray-600 text-sm leading-relaxed">{review.comments}</p>
                                                        <p className="text-xs text-gray-400 mt-2">{formatDate(review.created_at)}</p>
                                                    </div>
                                                </Link>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-center py-4">
                                            <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-2">
                                                <svg className="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                </svg>
                                            </div>
                                            <p className="text-sm text-gray-500">Awaiting review feedback</p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Phase 2 */}
                    {project.phase2Available && (
                        <div className="border border-gray-200 rounded-lg overflow-hidden">
                            <div
                                className="bg-gray-50 p-4 cursor-pointer hover:bg-gray-100 transition-colors"
                                onClick={() => setExpandedProject(expandedProject === project.id * 10 + 2 ? null : project.id * 10 + 2)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center space-x-3">
                                        <div className="w-8 h-8 bg-violet-100 rounded-full flex items-center justify-center">
                                            <span className="text-violet-600 font-bold text-sm">2</span>
                                        </div>
                                        <div>
                                            <h4 className="font-semibold text-gray-900">Phase 2 Submission</h4>
                                            <p className="text-xs text-gray-500">
                                                Submitted: {project.phase2Submission?.submitted_at ? formatDate(project.phase2Submission.submitted_at) : 'N/A'}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="flex items-center space-x-3">
                                        {getPhaseReviews(project, 2).length > 0 && (
                                            <span className="bg-violet-100 text-violet-700 px-2 py-1 rounded-full text-xs font-medium">
                                                {getPhaseReviews(project, 2).length} Review{getPhaseReviews(project, 2).length > 1 ? 's' : ''}
                                            </span>
                                        )}
                                        <svg
                                            className={`w-5 h-5 text-gray-400 transition-transform ${expandedProject === project.id * 10 + 2 ? 'rotate-180' : ''
                                                }`}
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                        </svg>
                                    </div>
                                </div>
                            </div>

                            {expandedProject === project.id * 10 + 2 && (
                                <div className="p-4 bg-white border-t border-gray-200">
                                    {/* File Info */}
                                    <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                                        <p className="text-sm font-medium text-gray-700 mb-1">Submitted File:</p>
                                        <p className="text-sm text-gray-600">{project.phase2Submission?.file_name || 'No file'}</p>
                                    </div>

                                    {/* Reviews */}
                                    {getPhaseReviews(project, 2).length > 0 ? (
                                        <div className="space-y-3">
                                            <h5 className="font-medium text-gray-900">Reviews & Feedback</h5>
                                            {getPhaseReviews(project, 2).map((review, idx) => (
                                                <div key={idx} className="border border-gray-200 rounded-lg p-4">
                                                    <div className="flex items-center justify-between mb-2">
                                                        <span className="font-medium text-gray-900">{review.reviewer_name}</span>
                                                        <div className="flex items-center space-x-2">
                                                            <span className="text-xs text-gray-500">{review.reviewer_role}</span>
                                                            <div className="flex items-center space-x-1">
                                                                <svg className="w-4 h-4 text-violet-500" fill="currentColor" viewBox="0 0 20 20">
                                                                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                                                </svg>
                                                                <span className="font-semibold text-gray-900">{review.rating}/10</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <p className="text-gray-600 text-sm leading-relaxed">{review.comments}</p>
                                                    <p className="text-xs text-gray-400 mt-2">{formatDate(review.created_at)}</p>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-center py-4">
                                            <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-2">
                                                <svg className="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                </svg>
                                            </div>
                                            <p className="text-sm text-gray-500">Awaiting review feedback</p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );

    const renderNonStudentProjectCard = (project: Project) => (
        <div key={project.id} className="group bg-gradient-to-br from-white to-slate-50/50 border border-slate-200/60 rounded-xl overflow-hidden shadow-sm hover:shadow-xl transition-all duration-300 hover:-translate-y-1">
            <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                    <h3 className="text-lg font-bold text-slate-800 line-clamp-2 pr-2 leading-tight">
                        {project.title || 'Untitled Project'}
                    </h3>
                    <div className={`px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap ${project.status === 'approved'
                        ? 'bg-green-100 text-green-700'
                        : 'bg-yellow-100 text-yellow-700'
                        }`}>
                        {project.status}
                    </div>
                </div>

                <p className="text-slate-600 text-sm mb-4 line-clamp-3 leading-relaxed">
                    {project.description || 'No description provided'}
                </p>

                {/* Deadlines */}
                <div className="mb-4 p-3 bg-slate-50/80 rounded-lg">
                    <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>
                            <span className="text-slate-500 block">Phase 1 Due:</span>
                            <span className="font-medium text-slate-700">{formatDate(project.first_deadline)}</span>
                        </div>
                        <div>
                            <span className="text-slate-500 block">Final Due:</span>
                            <span className="font-medium text-slate-700">{formatDate(project.final_deadline)}</span>
                        </div>
                    </div>
                </div>

                {/* Status Information */}
                <div className="space-y-2 mb-4">
                    <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-600">Phase 1 Pending:</span>
                        <span className={`font-semibold px-2 py-1 rounded-full text-xs ${project.phase1_reviewable ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'
                            }`}>
                            {project.phase1_reviewable || 0}
                        </span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-600">Phase 2 Pending:</span>
                        <span className={`font-semibold px-2 py-1 rounded-full text-xs ${project.phase2_reviewable ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'
                            }`}>
                            {project.phase2_reviewable || 0}
                        </span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-600">Reviews Completed:</span>
                        <span className="font-semibold text-green-600 px-2 py-1 rounded-full text-xs bg-green-100">
                            {project.reviewed_count || 0}
                        </span>
                    </div>
                </div>

                {/* Action Button */}
                <Link
                    href={`/review?projectId=${project.id}${project.phase1_reviewable ? '&phase=1' : project.phase2_reviewable ? '&phase=2' : ''}`}
                    className={`block w-full text-center py-3 px-4 rounded-lg font-medium text-sm transition-all duration-200 ${(project.phase1_reviewable || project.phase2_reviewable)
                        ? 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white shadow-lg shadow-indigo-500/25 hover:shadow-xl hover:shadow-indigo-500/30'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200'
                        }`}
                >
                    {project.phase1_reviewable
                        ? 'Review Phase 1 Submissions'
                        : project.phase2_reviewable
                            ? 'Review Phase 2 Submissions'
                            : 'View Completed Reviews'}
                </Link>
            </div>
        </div>
    );

    if (loading) {
        return (
            <div className="min-h-[400px] flex justify-center items-center">
                <div className="relative">
                    <div className="w-16 h-16 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    <div className="absolute inset-0 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 opacity-20 animate-pulse"></div>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-[400px] flex items-center justify-center">
                <div className="bg-red-50 border-l-4 border-red-500 p-6 rounded-lg max-w-lg">
                    <div className="flex items-center space-x-3">
                        <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <h3 className="text-lg font-semibold text-red-800">Error Loading Projects</h3>
                    </div>
                    <p className="mt-2 text-red-700">{error}</p>
                </div>
            </div>
        );
    }

    const filteredProjects = getFilteredProjects();
    const { phase1Count, phase2Count } = getProjectCounts();

    // Filter tabs
    const renderFilterTabs = () => (
        <div className="mb-8">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="flex items-center space-x-2 p-1 bg-white/60 backdrop-blur-sm rounded-xl border border-gray-200/50 shadow-sm">
                    <button
                        onClick={() => setActiveFilter('phase1')}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${activeFilter === 'phase1'
                            ? 'bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg shadow-indigo-500/25'
                            : 'text-gray-600 hover:bg-gray-50'
                            }`}
                    >
                        Phase 1 ({phase1Count})
                    </button>
                    <button
                        onClick={() => setActiveFilter('phase2')}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${activeFilter === 'phase2'
                            ? 'bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg shadow-indigo-500/25'
                            : 'text-gray-600 hover:bg-gray-50'
                            }`}
                    >
                        Phase 2 ({phase2Count})
                    </button>
                    <button
                        onClick={() => setActiveFilter('all')}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${activeFilter === 'all'
                            ? 'bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg shadow-indigo-500/25'
                            : 'text-gray-600 hover:bg-gray-50'
                            }`}
                    >
                        All Projects
                    </button>
                </div>
                <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <div className="flex items-center">
                        <div className="w-3 h-3 bg-green-500 rounded-full mr-2"></div>
                        <span>Reviewed</span>
                    </div>
                    <div className="flex items-center">
                        <div className="w-3 h-3 bg-amber-500 rounded-full mr-2"></div>
                        <span>Pending Review</span>
                    </div>
                </div>
            </div>
        </div>
    );

    if (filteredProjects.length === 0) {
        return (
            <div className="min-h-[400px] flex items-center justify-center">
                <div className="bg-white/80 backdrop-blur-sm border border-gray-200/50 rounded-2xl p-8 shadow-xl text-center max-w-lg">
                    <div className="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center mx-auto mb-4">
                        <svg className="w-8 h-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h14a2 2 0 012 2v14a2 2 0 01-2 2z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 7v6l3 3" />
                        </svg>
                    </div>
                    <h2 className="text-2xl font-bold text-gray-900 mb-2">
                        {user?.role === 'student'
                            ? "No Submissions Available"
                            : "No Projects to Review"}
                    </h2>
                    <p className="text-gray-600 mb-6">
                        {user?.role === 'student'
                            ? "You don't have any submissions ready for review at this time."
                            : "There are currently no projects that require your review."}
                    </p>
                    <div className="bg-indigo-50 border border-indigo-100 rounded-xl p-4 text-left">
                        <h3 className="font-medium text-indigo-900 mb-2">What to do next?</h3>
                        <ul className="space-y-2 text-sm text-indigo-800">
                            {user?.role === 'student' ? (
                                <>
                                    <li className="flex items-center">
                                        <svg className="w-4 h-4 mr-2 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                        </svg>
                                        Submit your work for review
                                    </li>
                                    <li className="flex items-center">
                                        <svg className="w-4 h-4 mr-2 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                        </svg>
                                        Check back after submission
                                    </li>
                                </>
                            ) : (
                                <>
                                    <li className="flex items-center">
                                        <svg className="w-4 h-4 mr-2 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                        </svg>
                                        Check back later for new submissions
                                    </li>
                                    <li className="flex items-center">
                                        <svg className="w-4 h-4 mr-2 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                        </svg>
                                        Review project guidelines
                                    </li>
                                </>
                            )}
                        </ul>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div>
            {renderFilterTabs()}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredProjects.map((project) => (
                    <div key={project.id}>
                        {user?.role === 'student'
                            ? renderStudentProjectCard(project)
                            : renderNonStudentProjectCard(project)}
                    </div>
                ))}
            </div>
        </div>
    );
}