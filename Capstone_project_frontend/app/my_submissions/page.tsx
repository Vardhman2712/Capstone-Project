'use client';

import { useAuth } from '@/app/context/AuthContext';
import StudentProjectsStatus from "../components/projects/MySubmissions";
import { useApprovalStatus } from '@/app/hooks/useApprovalStatus';
import { Clock4 } from 'lucide-react';
import Link from 'next/link';

export default function StudentDashboard() {
    const { user } = useAuth();
    const { isApproved, isLoading: approvalLoading } = useApprovalStatus();

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
                    Your account is pending approval from an administrator. You will be able to access your submissions once your account is approved.
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

    return (
        <div>
            {/* <h1 className="text-2xl font-bold mb-4">Welcome Student</h1> */}
            <StudentProjectsStatus />
        </div>
    );
}
