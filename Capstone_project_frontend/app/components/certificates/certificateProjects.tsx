'use client';

import React, { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { projectsApi } from '../../api/api';
import Link from 'next/link';

interface Review {
    id: number;
    submission_id: number;
    project_id: number;
    student_id: number;
    reviewer_id: number;
    reviewer_role: string;
    rating: number;
    comments: string;
    created_at: string;
    reviewer_name: string;
}

interface Project {
    id: string | number;
    title: string;
    description: string;
    finalDeadline: string;
    reviews: Review[];
    phase1Submission?: {
        id: number;
        submitted_at: string;
    };
    phase2Submission?: {
        id: number;
        submitted_at: string;
    };
    category?: string;
    duration?: string;
}

const CertificateProjects = () => {
    const { user } = useAuth();
    const [projects, setProjects] = useState<Project[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState<'all' | 'high-rating'>('all');

    const getPhaseRating = (project: Project, phaseSubmission?: { id: number }) => {
        if (!phaseSubmission?.id || !project.reviews) return 0;

        // Find reviews for this phase submission
        const phaseReviews = project.reviews.filter(review => review.submission_id === phaseSubmission.id);
        if (phaseReviews.length === 0) return 0;

        // Get the highest rating
        return Math.max(...phaseReviews.map(r => r.rating));
    };

    const getCombinedRating = (project: Project) => {
        const phase1Rating = getPhaseRating(project, project.phase1Submission);
        const phase2Rating = getPhaseRating(project, project.phase2Submission);
        return (phase1Rating + phase2Rating) / 2;
    };

    const isProjectCertificateEligible = (project: Project) => {
        if (!project.phase1Submission || !project.phase2Submission) return false;
        const combinedRating = getCombinedRating(project);
        return combinedRating > 6;
    };

    useEffect(() => {
        if (!user) return;

        const fetchProjects = async () => {
            try {
                setLoading(true);
                setError(null);
                let projectsData: Project[] = [];

                if (user.role === 'student') {
                    const response = await projectsApi.getStudentProjects();
                    projectsData = response.projects?.filter(isProjectCertificateEligible) || [];
                }

                setProjects(projectsData);
            } catch (err) {
                console.error('Error fetching projects:', err);
                setError(err instanceof Error ? err.message : 'Failed to load projects');
            } finally {
                setLoading(false);
            }
        };

        fetchProjects();
    }, [user]);

    const filteredProjects = projects.filter(project => {
        if (filter === 'high-rating') {
            const combinedRating = getCombinedRating(project);
            return combinedRating >= 9;
        }
        return true;
    });

    const formatDate = (dateString: string) => {
        const date = new Date(dateString);
        return isNaN(date.getTime()) ? 'Invalid date' : date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    const getRatingBadgeColor = (rating: number) => {
        if (rating >= 9) return 'bg-gray-900 text-white border-gray-700';
        if (rating >= 8) return 'bg-gray-700 text-white border-gray-600';
        if (rating >= 7) return 'bg-gray-600 text-white border-gray-500';
        if (rating >= 6) return 'bg-gray-500 text-white border-gray-400';
        return 'bg-gray-400 text-white border-gray-300';
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-white">
                <div className="text-gray-700 text-lg font-medium">Loading projects...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-white">
                <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-red-800 max-w-md shadow">
                    <h3 className="text-lg font-semibold mb-2">Failed to load projects</h3>
                    <p>{error}</p>
                    <button onClick={() => window.location.reload()} className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition">
                        Retry
                    </button>
                </div>
            </div>
        );
    }

    if (filteredProjects.length === 0) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-white px-4 py-12">
                <div className="max-w-xl w-full text-center">
                    <div className="mx-auto mb-6 text-gray-400">
                        <svg
                            className="w-20 h-20 mx-auto"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={1.5}
                                d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0H5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 8v-4a1 1 0 011-1h2a1 1 0 011 1v4"
                            />
                        </svg>
                    </div>

                    <h2 className="text-2xl font-bold text-gray-900 mb-2">
                        {user?.role === 'student'
                            ? "No Certificate-Eligible Projects"
                            : "No Certificates Available"}
                    </h2>

                    <p className="text-gray-600 mb-6">
                        {user?.role === 'student' ? (
                            "You haven't completed any projects that meet the certificate requirements yet."
                        ) : (
                            "There are currently no student projects eligible for certificates."
                        )}
                    </p>

                    {user?.role === 'student' ? (
                        <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 text-left shadow-inner">
                            <p className="text-sm font-medium text-gray-800 mb-3">
                                Certificate Requirements:
                            </p>
                            <ul className="text-sm text-gray-700 space-y-2">
                                <li className="flex items-center">
                                    <svg
                                        className="w-5 h-5 text-green-500 mr-2"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M5 13l4 4L19 7"
                                        />
                                    </svg>
                                    Complete both Phase 1 and Phase 2 submissions
                                </li>
                                <li className="flex items-center">
                                    <svg
                                        className="w-5 h-5 text-blue-500 mr-2"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                        />
                                    </svg>
                                    Maintain an average rating of 8.0 or higher
                                </li>
                                <li className="flex items-center">
                                    <svg
                                        className="w-5 h-5 text-purple-500 mr-2"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                                        />
                                    </svg>
                                    Final submission approved within project timeline
                                </li>
                            </ul>
                        </div>
                    ) : (
                        <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
                            <p className="text-sm text-blue-800">
                                Certificates will become available when students:
                            </p>
                            <ul className="list-disc list-inside text-sm text-blue-700 mt-2 space-y-1">
                                <li>Complete all required project phases</li>
                                <li>Meet minimum rating requirements</li>
                                <li>Have final submissions approved</li>
                            </ul>
                        </div>
                    )}
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-white px-4 py-5">
            <div className="max-w-7xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-4xl font-bold text-gray-900 text-center mb-2">Certificate Projects</h1>
                    <p className="text-center text-gray-500  text-lg">
                        {user?.role === 'student'
                            ? 'View and generate certificates for eligible projects'
                            : 'Manage certificates for student submissions'}
                    </p>
                </div>

                <div className="flex justify-between items-center mb-6 flex-wrap gap-4">
                    <div className="flex space-x-2">
                        <button
                            onClick={() => setFilter('all')}
                            className={`px-4 py-2 rounded-md text-sm border transition ${filter === 'all'
                                ? 'bg-black text-white border-black'
                                : 'bg-gray-100 text-gray-800 border-gray-300 hover:bg-gray-200'
                                }`}
                        >
                            All ({projects.length})
                        </button>
                        <button
                            onClick={() => setFilter('high-rating')}
                            className={`px-4 py-2 rounded-md text-sm border transition ${filter === 'high-rating'
                                ? 'bg-black text-white border-black'
                                : 'bg-gray-100 text-gray-800 border-gray-300 hover:bg-gray-200'
                                }`}
                        >
                            Excellent (9+) ({projects.filter(p => p.reviews?.some(r => r.rating >= 9)).length})
                        </button>
                    </div>
                    <span className="text-sm text-gray-500">
                        Showing {filteredProjects.length} project{filteredProjects.length !== 1 ? 's' : ''}
                    </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                    {filteredProjects.map((project) => {
                        const phase1Rating = getPhaseRating(project, project.phase1Submission);
                        const phase2Rating = getPhaseRating(project, project.phase2Submission);
                        const combinedRating = getCombinedRating(project);

                        return (
                            <div key={project.id} className="border border-gray-200 rounded-lg p-6 mt-4 hover:shadow-md transition bg-white flex flex-col min-h-80">
                                <div className="flex-grow">
                                    <h3 className="text-lg font-semibold text-gray-900 mb-3 line-clamp-2">{project.title}</h3>
                                    <p className="text-sm text-gray-600 mb-4 line-clamp-3">{project.description}</p>
                                    <div className="text-sm space-y-3 mb-4">
                                        <div className="flex justify-between items-center">
                                            <span className="text-gray-500">Project Rating:</span>
                                            <div className="flex items-center gap-2">
                                                <span className={`px-3 py-1.5 rounded text-sm font-medium border ${getRatingBadgeColor(combinedRating)}`}>
                                                    {combinedRating.toFixed(1)}/10
                                                </span>
                                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${combinedRating > 6
                                                    ? 'bg-green-100 text-green-800'
                                                    : 'bg-yellow-100 text-yellow-800'
                                                    }`}>
                                                    {combinedRating > 6 ? 'Eligible' : 'Not Eligible'}
                                                </span>
                                            </div>
                                        </div>
                                        <div className="flex justify-between">
                                            <span className="text-gray-500">Completed:</span>
                                            <span className="text-gray-700 text-xs">
                                                {project.phase2Submission?.submitted_at ? formatDate(project.phase2Submission.submitted_at) : 'N/A'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <Link
                                    href={`/certificate?projectId=${project.id}`}
                                    className={`inline-block w-full text-center py-2 rounded-md text-sm font-medium mt-auto transition
                                        ${combinedRating > 6
                                            ? 'bg-black text-white hover:bg-gray-800'
                                            : 'bg-gray-100 text-gray-400 cursor-not-allowed'}`}
                                    onClick={(e) => {
                                        if (!(combinedRating > 6)) {
                                            e.preventDefault();
                                        }
                                    }}
                                >
                                    {combinedRating > 6
                                        ? (user?.role === 'student' ? 'Generate Certificate' : 'View Certificate')
                                        : 'Not Eligible for Certificate'}
                                </Link>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default CertificateProjects;