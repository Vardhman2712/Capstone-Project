'use client';

import { useState, useEffect } from 'react';
import emailjs from '@emailjs/browser';
import { authApi } from '@/app/api/api';
import Loader from '../ui/Loader';

interface ForgotPasswordModalProps {
    isOpen: boolean;
    onClose: () => void;
}

const ForgotPasswordModal = ({ isOpen, onClose }: ForgotPasswordModalProps) => {
    const SERVICE_ID = process.env.NEXT_PUBLIC_SERVICE_ID;
    const TEMPLATE_ID = process.env.NEXT_PUBLIC_TEMPLATE_ID;
    const PUBLIC_KEY = process.env.NEXT_PUBLIC_PUBLIC_KEY;

    // Form states
    const [email, setEmail] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');

    // OTP states
    const [otp, setOtp] = useState('');
    const [userEnteredOtp, setUserEnteredOtp] = useState('');
    const [otpSent, setOtpSent] = useState(false);
    const [otpVerified, setOtpVerified] = useState(false);
    const [emailSubmitted, setEmailSubmitted] = useState(false);

    // UI states
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [countdown, setCountdown] = useState(0);
    const [success, setSuccess] = useState(false);

    // Initialize EmailJS
    useEffect(() => {
        if (isOpen && PUBLIC_KEY) {
            emailjs.init({
                publicKey: PUBLIC_KEY,
                blockHeadless: true,
                blockList: { watchVariable: 'userEmail' },
                limitRate: { id: 'app', throttle: 10000 },
            });
        }
    }, [isOpen, PUBLIC_KEY]);

    // Timer for OTP resend cooldown
    useEffect(() => {
        if (countdown > 0) {
            const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
            return () => clearTimeout(timer);
        }
    }, [countdown]);

    // Reset states on close
    useEffect(() => {
        if (!isOpen) resetAllStates();
    }, [isOpen]);

    const resetAllStates = () => {
        setEmail('');
        setNewPassword('');
        setConfirmPassword('');
        setOtp('');
        setUserEnteredOtp('');
        setOtpSent(false);
        setOtpVerified(false);
        setEmailSubmitted(false);
        setIsLoading(false);
        setError('');
        setCountdown(0);
        setSuccess(false);
    };

    const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

    const handleSendOtp = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            setError('Please enter a valid email address');
            return;
        }

        setIsLoading(true);

        try {
            const generatedOtp = generateOtp();
            setOtp(generatedOtp);

            const otpExpiryIST = new Date(Date.now() + 15 * 60 * 1000)
                .toLocaleString('en-IN', {
                    timeZone: 'Asia/Kolkata',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true,
                    day: 'numeric',
                    month: 'short',
                    year: 'numeric',
                });

            const templateParams = {
                email,
                name: email.split('@')[0],
                passcode: generatedOtp,
                time: otpExpiryIST,
            };

            if (SERVICE_ID && TEMPLATE_ID) {
                await emailjs.send(SERVICE_ID, TEMPLATE_ID, templateParams);
            }

            setOtpSent(true);
            setEmailSubmitted(true);
            setCountdown(60);

            // For development only
            // console.log(`OTP: ${generatedOtp}`);
            // alert(`For demo purposes: Your OTP is ${generatedOtp}`);

        } catch (error) {
            console.error('Error sending OTP:', error);
            setError('Failed to send verification code. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerifyOtp = (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (!userEnteredOtp) {
            setError('Please enter the verification code');
            return;
        }

        if (userEnteredOtp === otp) {
            setOtpVerified(true);
            setError('');
        } else {
            setError('Invalid verification code. Please try again.');
        }
    };

    const handleResetPassword = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (!newPassword || !confirmPassword) {
            setError('Both password fields are required');
            return;
        }

        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (newPassword.length < 6) {
            setError('Password must be at least 6 characters long');
            return;
        }

        setIsLoading(true);

        try {
            await authApi.forgotPassword(email, newPassword);
            setSuccess(true);
            setTimeout(onClose, 3000);
        } catch (error) {
            console.error('Password reset error:', error);
            setError(error instanceof Error ? error.message : 'Failed to reset password');
        } finally {
            setIsLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="w-full bg-white rounded-2xl shadow-xl overflow-hidden">
            {/* Header */}
            <div className="relative bg-gradient-to-r from-gray-900 to-black text-white p-10">
                <div className="absolute top-0 left-0 w-full h-full bg-black opacity-50"></div>
                <div className="relative z-10">
                    <div className="flex justify-between items-center">
                        <h2 className="text-3xl font-bold">Reset Password</h2>
                        <button
                            onClick={onClose}
                            className="text-gray-300 hover:text-white transition-colors p-2 hover:bg-white/10 rounded-full"
                        >
                            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>
                    <p className="text-gray-300 mt-3 text-lg">
                        {success ? 'Password reset successfully!' : 'Recover access to your account'}
                    </p>
                </div>
                <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-teal-500 to-cyan-500"></div>
            </div>

            {/* Content */}
            <div className="p-10">
                {isLoading ? (
                    <div className="py-8">
                        <Loader variant="default" size="medium" text="Processing your request..." />
                    </div>
                ) : success ? (
                    <div className="text-center py-8">
                        <div className="mx-auto w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mb-4">
                            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                        </div>
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">Password Reset Successful!</h3>
                        <p className="text-gray-600 mb-6">
                            Your password has been updated successfully. You can now login with your new password.
                        </p>
                        <button
                            onClick={onClose}
                            className="inline-flex justify-center items-center px-6 py-2 border border-transparent text-base font-medium rounded-lg text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200"
                        >
                            Return to Login
                        </button>
                    </div>
                ) : (
                    <div className="space-y-6">
                        {error && (
                            <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-md">
                                <div className="flex">
                                    <div className="flex-shrink-0">
                                        <svg className="h-5 w-5 text-red-500" viewBox="0 0 20 20" fill="currentColor">
                                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                                        </svg>
                                    </div>
                                    <div className="ml-3">
                                        <p className="text-sm text-red-700">{error}</p>
                                    </div>
                                </div>
                            </div>
                        )}

                        {!otpVerified ? (
                            // Email Verification Step
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                                        Email Address
                                    </label>
                                    <div className="mt-1 relative rounded-md shadow-sm">
                                        <input
                                            type="email"
                                            id="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            disabled={emailSubmitted}
                                            className={`block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500 ${emailSubmitted ? 'bg-gray-50' : ''}`}
                                            placeholder="Enter your email address"
                                        />
                                    </div>
                                </div>

                                {otpSent && (
                                    <div>
                                        <label htmlFor="otp" className="block text-sm font-medium text-gray-700">
                                            Verification Code
                                        </label>
                                        <div className="mt-1">
                                            <input
                                                type="text"
                                                id="otp"
                                                value={userEnteredOtp}
                                                onChange={(e) => setUserEnteredOtp(e.target.value)}
                                                maxLength={6}
                                                className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                                placeholder="Enter 6-digit code"
                                            />
                                        </div>
                                        <div className="mt-2 flex justify-end">
                                            <button
                                                onClick={handleSendOtp}
                                                disabled={countdown > 0}
                                                className="text-sm text-teal-600 hover:text-teal-500 disabled:text-gray-400"
                                            >
                                                {countdown > 0 ? `Resend in ${countdown}s` : 'Resend Code'}
                                            </button>
                                        </div>
                                    </div>
                                )}

                                <button
                                    onClick={otpSent ? handleVerifyOtp : handleSendOtp}
                                    disabled={!email || isLoading}
                                    className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200 disabled:opacity-50"
                                >
                                    {otpSent ? 'Verify Code' : 'Send Verification Code'}
                                </button>
                            </div>
                        ) : (
                            // Password Reset Step
                            <form onSubmit={handleResetPassword} className="space-y-4">
                                <div>
                                    <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700">
                                        New Password
                                    </label>
                                    <div className="mt-1">
                                        <input
                                            type="password"
                                            id="newPassword"
                                            value={newPassword}
                                            onChange={(e) => setNewPassword(e.target.value)}
                                            className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                            placeholder="Enter new password"
                                        />
                                    </div>
                                </div>

                                <div>
                                    <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                                        Confirm Password
                                    </label>
                                    <div className="mt-1">
                                        <input
                                            type="password"
                                            id="confirmPassword"
                                            value={confirmPassword}
                                            onChange={(e) => setConfirmPassword(e.target.value)}
                                            className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                            placeholder="Confirm new password"
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={isLoading || !newPassword || !confirmPassword}
                                    className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200 disabled:opacity-50"
                                >
                                    Reset Password
                                </button>
                            </form>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ForgotPasswordModal;