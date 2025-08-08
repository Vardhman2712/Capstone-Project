'use client';

import React, { Suspense } from 'react';
import Link from 'next/link';
import PDFViewer from "@/app/components/pdf/pdfViewer";
import { Eye, Clock4 } from 'lucide-react';
import { useAuth } from '@/app/context/AuthContext';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';

// Types
interface Review {
    id: string;
    reviewer_id: string;
    reviewer_name: string;
    reviewer_role: string;
    rating: number;
    comments: string;
    created_at: string;
    submission_id?: string;
    project_id?: string;
    student_id?: string;
}

interface Submission {
    student_id: string;
    username: string;
    email: string;
    phase1_submission_id: string;
    phase1_file_url: string;
    phase1_submitted_at: string;
    phase1_review_count: number;
    phase2_submission_id?: string | null;
    phase2_file_url?: string | null;
    phase2_submitted_at?: string | null;
    phase2_review_count?: number;
    status: string;
}

interface ProjectResponse {
    submissions: Submission[];
    project_state: 'active' | 'past';
}

// Loading component
const ReviewDashboardLoading = () => {
    return (
        <div className="flex justify-center items-center h-96">
            <div className="text-center">
                <h1 className="text-2xl mb-4">Loading...</h1>
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
            </div>
        </div>
    );
};

// Main component
const ReviewDashboardContent = () => {
    const React = require('react');
    const { useState, useEffect } = React;
    const { useAuth } = require('@/app/context/AuthContext');
    const { projectsApi } = require('../api/api');
    const { useRouter, useSearchParams } = require('next/navigation');
    const Link = require('next/link').default;
    const { X } = require('lucide-react');
    const { useApprovalStatus } = require('@/app/hooks/useApprovalStatus');

    const { user } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();

    const projectId = searchParams.get('projectId');
    const phase = searchParams.get('phase');
    const [submissions, setSubmissions] = useState<Submission[]>([]);
    const [selectedSubmission, setSelectedSubmission] = useState<Submission | null>(null);
    const [reviews, setReviews] = useState<Review[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const [rating, setRating] = useState<number>(7);
    const [comments, setComments] = useState<string>('');
    const [reviewSubmitting, setReviewSubmitting] = useState<boolean>(false);
    const [reviewError, setReviewError] = useState<string | null>(null);
    const [editingReview, setEditingReview] = useState<string | null>(null);
    const [editRating, setEditRating] = useState<number>(7);
    const [editComments, setEditComments] = useState<string>('');
    const [selectedPdf, setSelectedPdf] = useState<{
        file_name: string;
        file_url: string;
        file_type: string;
    } | null>(null);
    const [isPDF, setIsPDF] = useState<boolean>(false);
    const [isImage, setIsImage] = useState<boolean>(false);
    const [isZip, setIsZip] = useState<boolean>(false);
    const [isCSV, setIsCSV] = useState(false);
    const [isTxt, setIsTxt] = useState<boolean>(false);
    const [isCode, setIsCode] = useState<boolean>(false);
    const [projectState, setProjectState] = useState<'active' | 'past'>('active');

    const canReview = user && ['teacher', 'evaluator', 'admin', 'coordinator', 'manager', 'academic_team'].includes(user.role);
    const isStudent = user?.role === 'student';

    useEffect(() => {
        if (!projectId || !user) return;

        setLoading(true);
        setError(null);

        const fetchData = async () => {
            try {
                if (isStudent) {
                    const studentProjects = await projectsApi.getStudentProjects();
                    const thisProject = studentProjects.projects.find((p: any) => p.id.toString() === projectId.toString());

                    if (thisProject?.phase2Submission) {
                        const submission = {
                            ...thisProject,
                            student_id: user.id.toString(),
                            phase1_review_count: thisProject.phase1Reviews?.length || 0,
                            phase2_review_count: thisProject.phase2Reviews?.length || 0
                        };
                        setSubmissions([submission]);
                        setSelectedSubmission(submission);
                        setReviews(thisProject.phase2Reviews || []);
                    }
                } else {
                    const response = await projectsApi.getSubmissionsReview(projectId);
                    let filteredSubmissions = response.submissions;

                    // Filter submissions based on phase
                    if (phase === '1') {
                        filteredSubmissions = filteredSubmissions.filter(s => s.phase1_submission_id);
                    } else if (phase === '2') {
                        filteredSubmissions = filteredSubmissions.filter(s => s.phase2_submission_id);
                    }

                    setSubmissions(filteredSubmissions);
                    setProjectState(response.project_state);

                    // If there's only one submission, select it automatically
                    if (filteredSubmissions.length === 1) {
                        handleSelectSubmission(filteredSubmissions[0], phase === '2' ? 2 : 1);
                    }
                }
            } catch (err) {
                console.error('Error fetching data:', err);
                setError(err instanceof Error ? err.message : 'Failed to load data');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [projectId, user, phase]);

    const loadReviews = async (submissionId?: string) => {
        if (!submissionId) return;

        try {
            setLoading(true);
            const response = await projectsApi.getSubmissionReviews(submissionId);
            setReviews(response.reviews || []);
        } catch (err) {
            console.error('Error loading reviews:', err);
            setError(err instanceof Error ? err.message : 'Failed to load reviews');
        } finally {
            setLoading(false);
        }
    };

    const handleSelectSubmission = async (submission: Submission, phase: number) => {
        const selected = {
            ...submission,
            phase,
            submission_id: phase === 1 ? submission.phase1_submission_id : submission.phase2_submission_id,
            file_url: phase === 1 ? submission.phase1_file_url : submission.phase2_file_url,
            submitted_at: phase === 1 ? submission.phase1_submitted_at : submission.phase2_submitted_at
        };

        setSelectedSubmission(selected);
        await loadReviews(selected.submission_id || undefined);
    };

    const handleSubmitReview = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedSubmission) return;

        setReviewSubmitting(true);
        setReviewError(null);

        try {
            const reviewData = { rating, comments };
            await projectsApi.submitReview(selectedSubmission.submission_id, reviewData);
            await loadReviews(selectedSubmission.submission_id);

            setRating(7);
            setComments('');
            // Update submissions state...
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Failed to submit review';
            setReviewError(errorMessage);
            console.error('Review submission error:', err);
        } finally {
            setReviewSubmitting(false);
        }
    };

    // Start editing a review
    const handleStartEdit = (review: Review) => {
        setEditingReview(review.id);
        setEditRating(Number(review.rating));
        setEditComments(review.comments);
    };

    // Cancel editing
    const handleCancelEdit = () => {
        setEditingReview(null);
        setEditRating(7);
        setEditComments('');
    };

    // Save edited review
    const handleSaveEdit = async (reviewId: string) => {
        try {
            setLoading(true);
            const response = await projectsApi.updateReview(reviewId, {
                rating: editRating,
                comments: editComments
            });

            // Update the review in the list
            setReviews(prevReviews =>
                prevReviews.map(review =>
                    review.id === reviewId
                        ? {
                            ...review,
                            rating: editRating,
                            comments: editComments,
                            updated_at: new Date().toISOString()
                        }
                        : review
                )
            );

            // Reset edit state
            setEditingReview(null);
            setEditRating(7);
            setEditComments('');

            // Show success message or notification here if needed
        } catch (err) {
            console.error('Error updating review:', err);
            setError(err instanceof Error ? err.message : 'Failed to update review');
        } finally {
            setLoading(false);
        }
    };

    // Delete a review
    const handleDeleteReview = async (reviewId: string) => {
        if (!confirm('Are you sure you want to delete this review?')) return;

        try {
            setLoading(true);
            await projectsApi.deleteReview(reviewId);

            // Remove the review from the list
            setReviews(prevReviews => prevReviews.filter(review => review.id !== reviewId));

            // Update submission review count if needed
            if (selectedSubmission) {
                const phase = selectedSubmission.phase;
                setSubmissions(prev =>
                    prev.map(sub =>
                        sub.student_id === selectedSubmission.student_id
                            ? {
                                ...sub,
                                [`phase${phase}_review_count`]: Math.max(0, sub[`phase${phase}_review_count`] - 1)
                            }
                            : sub
                    )
                );
            }
        } catch (err) {
            console.error('Error deleting review:', err);
            setError(err instanceof Error ? err.message : 'Failed to delete review');
        } finally {
            setLoading(false);
        }
    };

    const handlePreview = (fileUrl: string, fileName: string) => {
        // Get the file extension
        const extension = fileName.split('.').pop()?.toLowerCase() || '';
        console.log('Opening file:', fileName, 'with extension:', extension); // Debug log

        // Reset all type flags
        setIsImage(false);
        setIsPDF(false);
        setIsZip(false);
        setIsCSV(false);
        setIsTxt(false);
        setIsCode(false);

        // Set appropriate flag based on extension
        if (['txt', 'md', 'text'].includes(extension)) {
            console.log('Setting as text file'); // Debug log
            setIsTxt(true);
        } else if (['js', 'jsx', 'ts', 'tsx', 'json', 'html', 'css', 'py', 'java', 'cpp', 'c', 'rb', 'php', 'sql'].includes(extension)) {
            console.log('Setting as code file'); // Debug log
            setIsCode(true);
        } else if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(extension)) {
            setIsImage(true);
        } else if (extension === 'pdf') {
            setIsPDF(true);
        } else if (['zip', 'rar'].includes(extension)) {
            setIsZip(true);
        } else if (['csv', 'xlsx', 'xls'].includes(extension)) {
            setIsCSV(true);
        }

        setSelectedPdf({
            file_name: fileName,
            file_url: fileUrl,
            file_type: extension
        });
    };

    const getFileTypeFromName = (fileName: string) => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';

        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(extension)) {
            return 'image';
        } else if (extension === 'pdf') {
            return 'pdf';
        } else if (extension === 'zip' || extension === 'rar') {
            return 'zip';
        } else if (extension === 'csv' || extension === 'xlsx' || extension === 'xls') {
            return 'spreadsheet';
        } else if (extension === 'txt' || extension === 'md') {
            return 'text';
        } else if (['js', 'jsx', 'ts', 'tsx', 'json', 'html', 'css', 'py'].includes(extension)) {
            return 'code';
        }
        return 'unknown';
    };

    if (approvalLoading) {
        return (
            <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

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

    if (isApproved === false) {
        return (
            <div className="max-w-xl mx-auto mt-12 p-8 rounded-xl shadow-sm text-center bg-yellow-50 border border-yellow-200">
                <div className="mb-4">
                    <Clock4 className="h-12 w-12 text-yellow-500 mx-auto" />
                </div>
                <h3 className="text-xl font-semibold mb-2 text-yellow-800">
                    Account Pending Approval
                </h3>
                <p className="mb-6 text-yellow-700">
                    Your account is pending approval from an administrator. You will be able to access reviews once your account is approved.
                </p>
                <button
                    className="px-4 py-2 rounded-md transition-colors bg-yellow-100 hover:bg-yellow-200 text-yellow-700"
                    onClick={() => window.location.reload()}
                >
                    Check Again
                </button>
            </div>
        );
    }

    if (!projectId) {
        return (
            <div className="flex justify-center items-center h-96">
                <div className="text-center">
                    <h1 className="text-2xl mb-4">No Project Selected</h1>
                    <Link href="/dashboard" className="text-blue-500 hover:text-blue-700">
                        Return to Dashboard
                    </Link>
                </div>
            </div>
        );
    }

    if (loading && !selectedSubmission) {
        return (
            <div className="flex justify-center items-center h-96">
                <div className="text-center">
                    <h1 className="text-2xl mb-4">Loading...</h1>
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
                </div>
            </div>
        );
    }

    return (
        <div className="w-full min-h-screen relative flex flex-col lg:flex-row min-w-[320px]">
            {/* PDF Viewer - Full screen on mobile, half screen on desktop */}
            {selectedPdf && (
                <div
                    className={`fixed lg:sticky top-0 left-0 w-full lg:w-[45%] h-screen bg-white shadow-lg border-r border-gray-200 z-[100] min-w-[320px] overflow-hidden
                    ${selectedPdf ? 'block' : 'hidden'}`}
                >
                    <div className="h-full w-full flex flex-col">
                        <div className="flex-shrink-0 p-2 border-b border-gray-200 flex justify-between items-center bg-gray-50 sticky top-0 z-10">
                            <h3 className="text-sm font-medium text-gray-700 truncate px-2 flex-1">{selectedPdf.file_name}</h3>
                            <button
                                onClick={() => {
                                    setSelectedPdf(null);
                                    setIsPDF(false);
                                    setIsImage(false);
                                    setIsZip(false);
                                    setIsCSV(false);
                                    setIsTxt(false);
                                    setIsCode(false);
                                }}
                                className="p-2 hover:bg-gray-100 rounded-full transition-colors"
                            >
                                <X className="h-5 w-5 text-gray-600" />
                            </button>
                        </div>
                        <div className="flex-1 overflow-auto relative">
                            <PDFViewer
                                fileName={selectedPdf.file_name}
                                fileUrl={selectedPdf.file_url}
                                fileType={selectedPdf.file_type}
                                isOpen={!!selectedPdf}
                                onClose={() => {
                                    setSelectedPdf(null);
                                    setIsPDF(false);
                                    setIsImage(false);
                                    setIsZip(false);
                                    setIsCSV(false);
                                    setIsTxt(false);
                                    setIsCode(false);
                                }}
                                layout="inline"
                                isPDF={isPDF}
                                isImage={isImage}
                                isZip={isZip}
                                isCSV={isCSV}
                                isTxt={isTxt}
                                isCode={isCode}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Main Content */}
            <div className={`w-full ${selectedPdf ? 'lg:w-[55%]' : 'w-full'} min-h-screen bg-gray-50 overflow-y-auto p-4 sm:p-6 min-w-[320px]`}>
                <div className="max-w-[1200px] mx-auto">
                    <div className="flex flex-col sm:flex-row justify-between items-center gap-4 mb-6">
                        <h1 className="text-2xl sm:text-3xl font-bold text-gray-800 text-center sm:text-left">Project Reviews</h1>
                        <Link href={`/projects/${projectId}`} className="w-full sm:w-auto px-4 py-2 bg-gray-200 rounded hover:bg-gray-300 text-center">
                            Back to Project
                        </Link>
                    </div>

                    {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">{error}</div>}

                    <div className={`${selectedPdf ? 'flex flex-col' : 'grid'} ${isStudent ? 'grid-cols-1' : 'md:grid-cols-4'} gap-4 sm:gap-6 min-w-[300px]`}>
                        {/* Submissions List - Always show at top when PDF is open */}
                        {!isStudent && (
                            <div className={`${selectedPdf ? 'w-full' : 'md:col-span-1'} bg-white rounded-lg shadow p-4 min-w-[250px]`}>
                                <h2 className="text-xl font-semibold mb-4">Submissions</h2>
                                {submissions.length === 0 ? (
                                    <p className="text-gray-500">No submissions available</p>
                                ) : (
                                    <ul className={`${selectedPdf ? 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4' : 'space-y-2'}`}>
                                        {submissions.map((submission) => (
                                            <div key={submission.student_id} className="space-y-2">
                                                <li
                                                    className={`p-3 rounded-md cursor-pointer border ${selectedSubmission?.phase === 1 &&
                                                        selectedSubmission?.student_id === submission.student_id
                                                        ? 'bg-blue-100 border-blue-300'
                                                        : 'hover:bg-gray-100 border-gray-200'
                                                        }`}
                                                    onClick={() => handleSelectSubmission(submission, 1)}
                                                >
                                                    <div className="flex flex-col space-y-2">
                                                        <div className="font-medium text-sm sm:text-base break-words">{submission.username} - Phase 1</div>
                                                        <div className="flex flex-wrap items-center gap-2">
                                                            <span className={`px-2 py-1 text-xs rounded inline-flex items-center ${submission.phase1_review_count > 0
                                                                ? 'bg-green-100 text-green-800'
                                                                : 'bg-yellow-100 text-yellow-800'
                                                                }`}>
                                                                {submission.phase1_review_count} Review(s)
                                                            </span>
                                                        </div>
                                                    </div>
                                                </li>

                                                {submission.phase2_submission_id && (
                                                    <li
                                                        className={`p-3 rounded-md cursor-pointer border ${selectedSubmission?.phase === 2 &&
                                                            selectedSubmission?.student_id === submission.student_id
                                                            ? 'bg-blue-100 border-blue-300'
                                                            : 'hover:bg-gray-100 border-gray-200'
                                                            }`}
                                                        onClick={() => handleSelectSubmission(submission, 2)}
                                                    >
                                                        <div className="flex flex-col space-y-2">
                                                            <div className="font-medium text-sm sm:text-base break-words">{submission.username} - Phase 2</div>
                                                            <div className="flex flex-wrap items-center gap-2">
                                                                <span className={`px-2 py-1 text-xs rounded inline-flex items-center ${(submission.phase2_review_count || 0) > 0
                                                                    ? 'bg-green-100 text-green-800'
                                                                    : 'bg-yellow-100 text-yellow-800'
                                                                    }`}>
                                                                    {submission.phase2_review_count || 0} Review(s)
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </li>
                                                )}
                                            </div>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}

                        {/* Current Submission Details */}
                        <div className={`${selectedPdf ? 'w-full' : isStudent ? 'col-span-1' : 'md:col-span-3'} bg-white rounded-lg shadow min-w-[300px]`}>
                            {selectedSubmission ? (
                                <div className="p-4 sm:p-6">
                                    <div className="mb-6">
                                        <h2 className="text-2xl font-semibold">
                                            {isStudent ? "Your Submission" : `${selectedSubmission.username}'s Submission`}
                                        </h2>

                                        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 min-w-[280px]">
                                            <div className="border rounded-md p-3">
                                                <h3 className="font-medium">Phase 1 Submission</h3>
                                                <p className="text-sm text-gray-500">
                                                    {selectedSubmission.phase1_submitted_at
                                                        ? new Date(selectedSubmission.phase1_submitted_at).toLocaleString()
                                                        : 'Not submitted'}
                                                </p>
                                                {selectedSubmission.phase1_file_url && (
                                                    <button
                                                        onClick={() => handlePreview(selectedSubmission.phase1_file_url, `Submission_${selectedSubmission.username}_Phase1.pdf`)}
                                                        className="mt-2 flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm w-full sm:w-fit min-w-[140px]"
                                                    >
                                                        <Eye size={14} className="sm:w-4 sm:h-4" />
                                                        <span>View Submission</span>
                                                    </button>
                                                )}
                                            </div>

                                            <div className="border rounded-md p-3">
                                                <h3 className="font-medium">Phase 2 Submission</h3>
                                                {selectedSubmission.phase2_submitted_at ? (
                                                    <>
                                                        <p className="text-sm text-gray-500">
                                                            {new Date(selectedSubmission.phase2_submitted_at).toLocaleString()}
                                                        </p>
                                                        {selectedSubmission.phase2_file_url && (
                                                            <button
                                                                onClick={() => handlePreview(selectedSubmission.phase2_file_url, `Submission_${selectedSubmission.username}_Phase2.pdf`)}
                                                                className="mt-2 flex items-center gap-2 px-3 py-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-md transition-colors text-sm w-full sm:w-fit min-w-[140px]"
                                                            >
                                                                <Eye size={14} className="sm:w-4 sm:h-4" />
                                                                <span>View Submission</span>
                                                            </button>
                                                        )}
                                                    </>
                                                ) : (
                                                    <p className="text-sm text-gray-500">Not submitted</p>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Reviews section */}
                                    <div className="mb-6">
                                        <h3 className="text-xl font-semibold mb-4">Reviews ({reviews.length})</h3>

                                        {reviews.length === 0 ? (
                                            <p className="text-gray-500">No reviews yet.</p>
                                        ) : (
                                            <div className="space-y-4 min-w-[280px]">
                                                {reviews.map((review) => (
                                                    <div key={review.id} className="border rounded-lg p-4">
                                                        <div>
                                                            <div className="flex flex-col sm:flex-row justify-between gap-4">
                                                                <div className="min-w-[200px]">
                                                                    <p className="font-medium text-gray-800">{review.reviewer_name || 'Anonymous'}</p>
                                                                    <p className="text-sm text-gray-500">{review.reviewer_role}</p>
                                                                </div>
                                                                <div className="text-left sm:text-right flex flex-col sm:items-end">
                                                                    <div className="inline-block px-3 py-1 bg-blue-100 text-blue-800 rounded-full font-medium text-sm min-w-[100px] text-center">
                                                                        Rating: {review.rating}/10
                                                                    </div>
                                                                    <p className="text-xs text-gray-500 mt-1">
                                                                        {new Date(review.created_at).toLocaleString()}
                                                                    </p>
                                                                </div>
                                                            </div>

                                                            {editingReview === review.id ? (
                                                                <div className="space-y-4">
                                                                    <div>
                                                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                                                            Rating (1-10)
                                                                        </label>
                                                                        <input
                                                                            type="number"
                                                                            min="1"
                                                                            max="10"
                                                                            value={editRating}
                                                                            onChange={(e) => setEditRating(Number(e.target.value))}
                                                                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                                                        />
                                                                    </div>
                                                                    <div>
                                                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                                                            Comments
                                                                        </label>
                                                                        <textarea
                                                                            value={editComments}
                                                                            onChange={(e) => setEditComments(e.target.value)}
                                                                            rows={4}
                                                                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                                                        />
                                                                    </div>
                                                                    <div className="flex justify-end space-x-2">
                                                                        <button
                                                                            onClick={() => handleCancelEdit()}
                                                                            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                                                        >
                                                                            Cancel
                                                                        </button>
                                                                        <button
                                                                            onClick={() => handleSaveEdit(review.id)}
                                                                            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                                                        >
                                                                            Save
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                            ) : (
                                                                <>
                                                                    <div className="mt-4">
                                                                        <p className="whitespace-pre-wrap text-sm sm:text-base">{review.comments}</p>
                                                                    </div>

                                                                    {/* Edit/Delete buttons section */}
                                                                    <div className="mt-4 flex flex-col gap-2">
                                                                        {user?.username === review.reviewer_name ? (
                                                                            <div className="flex flex-wrap gap-2 justify-end">
                                                                                <button
                                                                                    onClick={() => {
                                                                                        setEditingReview(review.id);
                                                                                        setEditRating(Number(review.rating));
                                                                                        setEditComments(review.comments);
                                                                                    }}
                                                                                    className="px-3 py-1.5 text-sm bg-gray-200 rounded hover:bg-gray-300 flex items-center gap-1"
                                                                                >
                                                                                    Edit
                                                                                </button>
                                                                                <button
                                                                                    onClick={() => handleDeleteReview(review.id)}
                                                                                    className="px-3 py-1.5 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200 flex items-center gap-1"
                                                                                >
                                                                                    Delete
                                                                                </button>
                                                                            </div>
                                                                        ) : (
                                                                            <div className="flex flex-col gap-2">
                                                                                <div className="flex flex-wrap gap-2 justify-end">
                                                                                    <button
                                                                                        disabled
                                                                                        title="You can only edit your own reviews"
                                                                                        className="px-3 py-1.5 text-sm bg-gray-100 text-gray-400 rounded cursor-not-allowed"
                                                                                    >
                                                                                        Edit
                                                                                    </button>
                                                                                    <button
                                                                                        disabled
                                                                                        title="You can only delete your own reviews"
                                                                                        className="px-3 py-1.5 text-sm bg-gray-100 text-gray-400 rounded cursor-not-allowed"
                                                                                    >
                                                                                        Delete
                                                                                    </button>
                                                                                </div>
                                                                                <p className="text-xs text-gray-500 text-right italic">
                                                                                    Note: You can only edit your own reviews
                                                                                </p>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                </>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>

                                    {/* Submit new review form - only visible for teachers, evaluators, etc. */}
                                    {canReview && selectedSubmission && (
                                        <div className="mt-8 border-t pt-6">
                                            <h3 className="text-xl font-semibold mb-4">
                                                Submit Review for Phase {selectedSubmission.phase}
                                            </h3>

                                            {reviewError && (
                                                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4 text-sm">
                                                    {reviewError}
                                                </div>
                                            )}

                                            <form onSubmit={handleSubmitReview} className="space-y-4">
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                                        Rating (1-10)
                                                    </label>
                                                    <input
                                                        type="number"
                                                        min="1"
                                                        max="10"
                                                        value={rating}
                                                        onChange={(e) => setRating(parseInt(e.target.value))}
                                                        className="w-full sm:w-32 p-2 border rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                                        required
                                                    />
                                                </div>

                                                <div>
                                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                                        Comments
                                                    </label>
                                                    <textarea
                                                        value={comments}
                                                        onChange={(e) => setComments(e.target.value)}
                                                        className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500 min-h-[120px]"
                                                        rows={4}
                                                        required
                                                    ></textarea>
                                                </div>

                                                <button
                                                    type="submit"
                                                    disabled={reviewSubmitting}
                                                    className="w-full sm:w-auto px-6 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-blue-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                                                >
                                                    {reviewSubmitting ? (
                                                        <>
                                                            <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                                                            <span>Submitting...</span>
                                                        </>
                                                    ) : (
                                                        <span>Submit Phase {selectedSubmission.phase} Review</span>
                                                    )}
                                                </button>
                                            </form>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-[500px] p-6 text-center">
                                    <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mb-4">
                                        <Eye className="w-8 h-8" />
                                    </div>
                                    <h2 className="text-2xl font-semibold text-gray-800 mb-2">Select a Submission to Review</h2>
                                    <p className="text-gray-600 max-w-md mb-4">
                                        {isStudent
                                            ? "Your submissions will appear here once they're ready for review."
                                            : "Choose a submission from the list on the left to view details and provide your review."}
                                    </p>
                                    {!isStudent && submissions.length > 0 && (
                                        <div className="text-sm text-gray-500">
                                            <p>{submissions.length} submission{submissions.length !== 1 ? 's' : ''} available for review</p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const ReviewDashboard = () => {
    return (
        <Suspense fallback={<ReviewDashboardLoading />}>
            <ReviewDashboardContent />
        </Suspense>
    );
};

export default ReviewDashboard;