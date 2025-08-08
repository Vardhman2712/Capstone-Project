'use client';

import React from 'react';
import { useAuth } from '@/app/context/AuthContext';
import ReviewableProjects from '@/app/components/reviews/reviewableProjects';
import Link from 'next/link';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { Clock4, FileText } from 'lucide-react';

const ReviewDashboardPage = () => {
    const { user } = useAuth();
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();

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
            <div className="min-h-screen flex justify-center items-center bg-gradient-to-br from-slate-50 to-blue-50">
                <div className="bg-white/80 backdrop-blur-sm border border-white/20 rounded-2xl p-8 shadow-xl text-center max-w-md w-full mx-4">
                    <div className="mb-6">
                        <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                            <svg className="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                        </div>
                        <h1 className="text-2xl font-bold text-gray-900 mb-2">Authentication Required</h1>
                        <p className="text-gray-600 mb-6">Please log in to access the review dashboard</p>
                        <Link
                            href="/login"
                            className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-medium rounded-xl shadow-lg shadow-blue-500/30 hover:shadow-xl hover:shadow-blue-500/40 transition-all duration-200"
                        >
                            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                            </svg>
                            Go to Login
                        </Link>
                    </div>
                </div>
            </div>
        );
    }

    // Third check: Admin bypass
    if (user.role === 'admin') {
        const isReviewer = ['teacher', 'evaluator', 'admin', 'coordinator', 'manager', 'academic_team'].includes(user.role);
        // Rest of the admin view...
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
                {/* Header Section */}
                <div className="bg-white/30 backdrop-blur-sm border-b border-white/20">
                    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
                        <div className="text-center">
                            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-indigo-100 to-purple-100 rounded-full mb-4">
                                <svg className="w-8 h-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                                </svg>
                            </div>
                            <h1 className="text-4xl sm:text-5xl font-bold bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-800 bg-clip-text text-transparent mb-4">
                                Reviews Dashboard
                            </h1>
                            <p className="text-lg sm:text-xl text-slate-600 max-w-2xl mx-auto">
                                {user.role === 'student'
                                    ? 'Track your project submissions and view detailed feedback from reviewers'
                                    : 'Evaluate student projects and provide constructive feedback to help them succeed'}
                            </p>

                            {/* User Role Badge */}
                            <div className="mt-6">
                                <span className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-indigo-100 to-purple-100 text-indigo-700 rounded-full text-sm font-medium">
                                    <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
                                    </svg>
                                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)} Dashboard
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Main Content */}
                <div className="max-w-7xl mx-auto  sm:px-6 lg:px-2 ">
                    <ReviewableProjects />
                </div>

                {/* Guidelines Section */}
                <div className="max-w-7xl mx-auto sm py-2:px-6 lg:px-2 ">
                    {isReviewer ? (
                        <div className="bg-gradient-to-br from-blue-50/80 to-indigo-50/80 backdrop-blur-sm rounded-2xl border border-blue-200/50 shadow-lg p-6 sm:p-8">
                            <div className="flex items-start space-x-4">
                                <div className="flex-shrink-0">
                                    <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center">
                                        <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <h2 className="text-2xl font-bold text-slate-800 mb-4">
                                        Review Guidelines & Best Practices
                                    </h2>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="space-y-4">
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Comprehensive Evaluation:</span> Review both Phase 1 and Phase 2 submissions for complete assessment of student progress.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Fair Scoring:</span> Use the 1-10 rating scale consistently, considering quality, completeness, and technical correctness.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Constructive Feedback:</span> Provide specific, actionable comments that help students understand areas for improvement.
                                                </p>
                                            </div>
                                        </div>
                                        <div className="space-y-4">
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Review Management:</span> You can edit or delete your reviews if needed before final submission.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Student Visibility:</span> All reviews and ratings will be visible to students for their learning benefit.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Timely Reviews:</span> Complete reviews promptly to help students progress with their projects.
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-gradient-to-br from-green-50/80 to-emerald-50/80 backdrop-blur-sm rounded-2xl border border-green-200/50 shadow-lg p-6 sm:p-8">
                            <div className="flex items-start space-x-4">
                                <div className="flex-shrink-0">
                                    <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl flex items-center justify-center">
                                        <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <h2 className="text-2xl font-bold text-slate-800 mb-4">
                                        Understanding Your Reviews
                                    </h2>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="space-y-4">
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Review Availability:</span> You can view reviews once both Phase 1 and Phase 2 submissions have been evaluated by instructors.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Rating System:</span> Ratings are provided on a 1-10 scale, with 10 representing exceptional work and 1 indicating areas needing significant improvement.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Feedback Value:</span> Review comments provide detailed insights to help you enhance your technical skills and project quality.
                                                </p>
                                            </div>
                                        </div>
                                        <div className="space-y-4">
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Multiple Perspectives:</span> You may receive reviews from different instructors, each offering unique insights into your work.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Questions & Support:</span> If you have questions about any review or need clarification, don't hesitate to contact your instructor.
                                                </p>
                                            </div>
                                            <div className="flex items-start space-x-3">
                                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                                <p className="text-slate-700 leading-relaxed">
                                                    <span className="font-semibold">Learning Opportunity:</span> Use review feedback as a roadmap for continuous improvement in your academic journey.
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        );
    }

    // Fourth check: Approval status for non-admin users
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
                        <p className="mt-2">You will be able to access the reviews once your account is approved.</p>
                    </div>
                    <div className="mt-4 text-sm text-gray-500">
                        <p>Please contact an administrator if you have any questions.</p>
                    </div>
                </div>
            </div>
        );
    }

    // Main content for approved users
    const isReviewer = ['teacher', 'evaluator', 'admin', 'coordinator', 'manager', 'academic_team'].includes(user.role);

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 via-indigo-50/30 to-blue-50">
            {/* Header Section */}
            <div className="bg-white/80 backdrop-blur-sm border-b border-white/20 shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                        <div className="flex-1 min-w-0">
                            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent mb-2">
                                Review Dashboard
                            </h1>
                            <p className="text-lg text-gray-600 max-w-2xl">
                                {user.role === 'student'
                                    ? 'Track your project submissions and view detailed feedback from reviewers'
                                    : 'Evaluate student projects and provide constructive feedback to help them succeed'}
                            </p>
                            <div className="mt-4 flex items-center space-x-4">
                                <span className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-indigo-50 to-blue-50 text-indigo-700 rounded-full text-sm font-medium border border-indigo-100/50">
                                    <svg className="w-4 h-4 mr-2 text-indigo-500" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
                                    </svg>
                                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                                </span>
                                <div className="flex items-center text-sm text-gray-500">
                                    <Clock4 className="w-4 h-4 mr-1 text-indigo-500" />
                                    <span>Last updated: {new Date().toLocaleDateString()}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <ReviewableProjects />
            </div>

            {/* Guidelines Section */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-12">
                <div className="bg-white/80 backdrop-blur-sm border border-white/20 rounded-2xl shadow-xl p-6 sm:p-8">
                    <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center">
                        <FileText className="w-5 h-5 mr-2 text-indigo-500" />
                        Review Guidelines
                    </h2>
                    <div className="grid md:grid-cols-2 gap-6">
                        <div>
                            <h3 className="font-semibold text-gray-900 mb-2">Best Practices</h3>
                            <ul className="space-y-2">
                                <li className="flex items-start">
                                    <svg className="w-5 h-5 text-green-500 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    <span className="text-gray-600">Provide constructive and actionable feedback</span>
                                </li>
                                <li className="flex items-start">
                                    <svg className="w-5 h-5 text-green-500 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    <span className="text-gray-600">Be specific about areas of improvement</span>
                                </li>
                                <li className="flex items-start">
                                    <svg className="w-5 h-5 text-green-500 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    <span className="text-gray-600">Maintain a professional and respectful tone</span>
                                </li>
                            </ul>
                        </div>
                        <div>
                            <h3 className="font-semibold text-gray-900 mb-2">Review Process</h3>
                            <ul className="space-y-2">
                                <li className="flex items-start">
                                    <div className="w-5 h-5 bg-indigo-100 rounded-full flex items-center justify-center mr-2 mt-0.5">
                                        <span className="text-indigo-600 text-xs font-bold">1</span>
                                    </div>
                                    <span className="text-gray-600">Read through the submission thoroughly</span>
                                </li>
                                <li className="flex items-start">
                                    <div className="w-5 h-5 bg-indigo-100 rounded-full flex items-center justify-center mr-2 mt-0.5">
                                        <span className="text-indigo-600 text-xs font-bold">2</span>
                                    </div>
                                    <span className="text-gray-600">Evaluate against project criteria</span>
                                </li>
                                <li className="flex items-start">
                                    <div className="w-5 h-5 bg-indigo-100 rounded-full flex items-center justify-center mr-2 mt-0.5">
                                        <span className="text-indigo-600 text-xs font-bold">3</span>
                                    </div>
                                    <span className="text-gray-600">Provide comprehensive feedback</span>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReviewDashboardPage;