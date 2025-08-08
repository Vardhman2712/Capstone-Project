// app/components/auth/LoginClient.tsx
'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import LoginForm from './LoginForm';
import { useAuth } from '../../context/AuthContext';

const LoginClient = () => {
    const { user } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();
    const registered = searchParams.get('registered');

    // Redirect if already logged in
    useEffect(() => {
        if (user) {
            router.push('/dashboard');
        }
    }, [user, router]);

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white py-12 sm:px-6 lg:px-8 flex flex-col justify-center">
            {registered && (
                <div className="max-w-md mx-auto mb-8">
                    <div className="bg-green-50 border-l-4 border-green-500 p-4 rounded-md">
                        <div className="flex">
                            <div className="flex-shrink-0">
                                <svg className="h-5 w-5 text-green-500" viewBox="0 0 20 20" fill="currentColor">
                                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                </svg>
                            </div>
                            <div className="ml-3">
                                <p className="text-sm text-green-700">
                                    Registration successful! Please log in with your new account.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <div className="sm:mx-auto sm:w-full sm:max-w-md mb-8">
                <div className="text-center">
                    <h1 className="text-3xl font-extrabold text-gray-900 mb-2">Welcome Back</h1>
                    <p className="text-gray-500 text-lg">
                        Sign in to continue to your capstone portal
                    </p>
                </div>
            </div>

            <LoginForm />

            <div className="mt-8 text-center text-sm text-gray-500">
                <p>
                    By signing in, you agree to our{' '}
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
    );
};

export default LoginClient;