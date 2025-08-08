'use client';

import { Suspense } from 'react';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import RegisterForm from '../components/auth/RegisterForm';
import { useAuth } from '../context/AuthContext';
import Loader from '../components/ui/Loader';

export default function RegisterPage() {
    const { user } = useAuth();
    const router = useRouter();

    // Redirect if already logged in
    useEffect(() => {
        if (user) {
            router.push('/dashboard');
        }
    }, [user, router]);

    return (
        <Suspense fallback={<Loader variant="full-page" text="Setting up your registration..." />}>
            <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white py-12 sm:px-6 lg:px-8">
                <div className="sm:mx-auto sm:w-full sm:max-w-md mb-8">
                    <div className="text-center">
                        <h1 className="text-3xl font-extrabold text-gray-900 mb-2">Create Your Account</h1>
                        <p className="mt-2 text-lg text-gray-600">
                            Join our capstone portal to start your academic journey
                        </p>
                    </div>
                </div>

                <RegisterForm />

                <div className="mt-8 text-center text-sm text-gray-500">
                    <p>
                        By creating an account, you agree to our{' '}
                        <a href="/terms" className="font-medium text-teal-600 hover:text-teal-500">
                            Terms of Service
                        </a>{' '}
                        and{' '}
                        <a href="/privacy" className="font-medium text-teal-600 hover:text-teal-500">
                            Privacy Policy
                        </a>
                    </p>
                </div>
            </div>
        </Suspense>
    );
}