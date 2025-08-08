'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Clock4 } from 'lucide-react';
import { adminApi } from '../api/api';

export default function PendingApprovalPage() {
    const router = useRouter();

    useEffect(() => {
        // Poll for approval status every 30 seconds
        const checkStatus = async () => {
            try {
                const response = await adminApi.getUserApprovalStatus();
                if (response.is_approved) {
                    router.push('/dashboard'); // Redirect to dashboard when approved
                }
            } catch (error) {
                console.error('Error checking approval status:', error);
            }
        };

        const interval = setInterval(checkStatus, 30000);
        return () => clearInterval(interval);
    }, [router]);

    return (
        <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
            <div className="sm:mx-auto sm:w-full sm:max-w-md">
                <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
                    <div className="text-center">
                        <Clock4 className="mx-auto h-12 w-12 text-yellow-500" />
                        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                            Account Pending Approval
                        </h2>
                        <p className="mt-2 text-center text-sm text-gray-600">
                            Your account is currently pending administrator approval. This page will
                            automatically update when your account is approved.
                        </p>
                        <div className="mt-6">
                            <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-gray-300" />
                                </div>
                                <div className="relative flex justify-center text-sm">
                                    <span className="px-2 bg-white text-gray-500">What to do next</span>
                                </div>
                            </div>
                            <div className="mt-6">
                                <ul className="mt-3 list-disc list-inside text-sm text-gray-600 text-left">
                                    <li>Please contact your administrator for approval</li>
                                    <li>You will be automatically redirected once approved</li>
                                    <li>This page refreshes every 30 seconds</li>
                                    <li>You can also manually refresh the page</li>
                                </ul>
                            </div>
                            <button
                                onClick={() => window.location.reload()}
                                className="mt-6 w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500"
                            >
                                Check Status Now
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
} 