'use client';

import { Suspense } from 'react';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/app/context/AuthContext';
// import TeacherDashboard from './TeacherDashboard.tsx';
import StudentDashboard from './StudentDashboard';
import OtherRoleDashboard from './OtherRoleDashboard';
import TeacherDashboard from './TeacherDashboard';
import ManagerDashboard from './ManagerDashboard';
import AdminDashboard from './AdminDashboard';
import Loader from '../components/ui/Loader';

export default function DashboardPage() {
    const { user, isLoading } = useAuth();
    const router = useRouter();
    const [isClient, setIsClient] = useState(false);

    // Handle client-side rendering
    useEffect(() => {
        setIsClient(true);
    }, []);

    // Redirect to login if not authenticated
    useEffect(() => {
        if (!isLoading && !user && isClient) {
            router.push('/login');
        }
    }, [user, isLoading, router, isClient]);

    if (!isClient || isLoading || !user) {
        return <Loader variant="full-page" text="Loading your dashboard..." />;
    }

    const getDashboardComponent = () => {
        switch (user.role) {
            case 'teacher':
                return (
                    <Suspense fallback={<Loader variant="default" text="Loading teacher dashboard..." />}>
                        <TeacherDashboard />
                    </Suspense>
                );
            case 'student':
                return (
                    <Suspense fallback={<Loader variant="default" text="Loading student dashboard..." />}>
                        <StudentDashboard />
                    </Suspense>
                );
            case 'admin':
                return (
                    <Suspense fallback={<Loader variant="default" text="Loading admin dashboard..." />}>
                        <AdminDashboard />
                    </Suspense>
                );
            case 'manager':
                return (
                    <Suspense fallback={<Loader variant="default" text="Loading manager dashboard..." />}>
                        <ManagerDashboard />
                    </Suspense>
                );
            default:
                return (
                    <Suspense fallback={<Loader variant="default" text="Loading dashboard..." />}>
                        <OtherRoleDashboard />
                    </Suspense>
                );
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 to-gray-100">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div className="mb-8">
                    <div className="relative bg-white border border-gray-200 p-8 rounded-2xl shadow-lg">
                        <div className="relative z-10">
                            <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
                            <div className="flex items-center gap-2 mt-3 text-lg font-medium text-gray-600">
                                <p>Welcome back,</p>
                                <p className="text-gray-900 font-semibold">{user.username}!</p>
                                <p className="capitalize text-blue-600 bg-blue-50 px-3 py-1 rounded-full text-sm font-medium">
                                    {user.role}
                                </p>
                            </div>
                        </div>

                        <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-indigo-500 rounded-b-2xl"></div>
                    </div>
                </div>

                {getDashboardComponent()}
            </div>
        </div>
    );
}