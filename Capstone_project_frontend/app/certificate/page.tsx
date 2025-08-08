'use client';

import React, { Suspense } from 'react';
import Link from 'next/link';
import { useAuth } from '@/app/context/AuthContext';
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { Clock4 } from 'lucide-react';

// Loading component for Suspense fallback
const CertificateLoading = () => {
    return (
        <div className="flex justify-center items-center h-96">
            <div className="text-center">
                <h1 className="text-2xl mb-4">Loading...</h1>
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
            </div>
        </div>
    );
};

// The component that uses useSearchParams inside Suspense
const CertificateContent = () => {
    const React = require('react');
    const { useState, useEffect } = React;
    const { useAuth } = require('@/app/context/AuthContext');
    const { projectsApi } = require('../api/api');
    const { useRouter, useSearchParams } = require('next/navigation');
    const Link = require('next/link').default;
    const Certificate = require('../components/certificate/certificate').default;
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();

    const { user } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();

    // Get projectId from URL
    const projectId = searchParams.get('projectId');

    const [projectData, setProjectData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isEligibleForCertificate, setIsEligibleForCertificate] = useState(false);
    const [maxRating, setMaxRating] = useState(0);
    const [certificateData, setCertificateData] = useState(null);

    useEffect(() => {
        if (!projectId || !user) return;

        setLoading(true);
        setError(null);

        const fetchData = async () => {
            try {
                // For students - fetch their specific project data
                if (user.role === 'student') {
                    const studentProjects = await projectsApi.getStudentProjects();
                    const thisProject = studentProjects.projects.find(
                        (p) => p.id.toString() === projectId.toString()
                    );

                    if (thisProject) {
                        setProjectData(thisProject);

                        // Check if both phases are completed
                        const phase1Completed = !!thisProject.phase1Submission;
                        const phase2Completed = !!thisProject.phase2Submission;

                        // Calculate the max rating from reviews
                        let highestRating = 0;
                        if (thisProject.reviews && thisProject.reviews.length > 0) {
                            highestRating = Math.max(...thisProject.reviews.map(review => review.rating));
                        }
                        setMaxRating(highestRating);

                        // Eligible for certificate if both phases are completed and max rating > 7
                        const eligible = phase1Completed && phase2Completed && highestRating >= 7;
                        setIsEligibleForCertificate(eligible);

                        // If eligible, prepare certificate data
                        if (eligible) {
                            // Find the review with the highest rating (for the date)
                            const highestReview = thisProject.reviews.reduce((prev, current) =>
                                (prev.rating > current.rating) ? prev : current
                            );

                            setCertificateData({
                                studentName: user.username || user.name || 'Student',
                                projectName: thisProject.title || 'Capstone Project',
                                teacherName: highestReview.reviewer_name || 'Project Instructor',
                                completionDate: highestReview.created_at,
                                referenceNumber: `CP-${projectId}-${user.id}`
                            });
                        }
                    }
                } else {
                    // For non-students (teachers, admins, etc.)
                    setError("Certificate download is only available for students");
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Failed to load project data');
                console.error("Error fetching data:", err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [projectId, user]);

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
                    Your account is pending approval from an administrator. You will be able to access certificates once your account is approved.
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

    if (loading) {
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
        <div className="container mx-auto  py-8">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-3xl font-bold">Project Certificate</h1>
                <Link href={`/projects/${projectId}`} className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300">
                    Back to Project
                </Link>
            </div>

            {error && (
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    {error}
                </div>
            )}

            {!isEligibleForCertificate && !error ? (
                <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-4">
                    <h2 className="text-xl font-bold mb-2">Not Eligible for Certificate</h2>
                    <p>To earn your certificate, you need to:</p>
                    <ul className="list-disc ml-6 mt-2">
                        <li>Complete both Phase 1 and Phase 2 of the project</li>
                        <li>Receive a review rating of at least 7/10</li>
                    </ul>
                    <p className="mt-2">Your highest review rating: {maxRating}/10</p>
                </div>
            ) : null}

            {isEligibleForCertificate && certificateData && (
                <div className="bg-white rounded-lg shadow-lg py-1">
                    <h2 className="text-2xl font-semibold mb-6 text-center">Congratulations! You've earned your certificate</h2>
                    <Certificate
                        studentName={certificateData.studentName}
                        projectName={certificateData.projectName}
                        teacherName={certificateData.teacherName}
                        completionDate={certificateData.completionDate}
                        referenceNumber={certificateData.referenceNumber}
                    />
                </div>
            )}
        </div>
    );
};

// Main Certificate Page Component
const CertificatePage = () => {
    return (
        <Suspense fallback={<CertificateLoading />}>
            <CertificateContent />
        </Suspense>
    );
};

export default CertificatePage;