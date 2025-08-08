'use client';

import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import Link from 'next/link';
import emailjs from '@emailjs/browser';
import Loader from '../ui/Loader';

const RegisterForm = () => {
    const { register, isLoading, error } = useAuth();

    const SERVICE_ID = process.env.NEXT_PUBLIC_SERVICE_ID;
    const TEMPLATE_ID = process.env.NEXT_PUBLIC_TEMPLATE_ID;
    const PUBLIC_KEY = process.env.NEXT_PUBLIC_PUBLIC_KEY;


    // Initialize EmailJS when component mounts
    useEffect(() => {
        // emailjs.init(PUBLIC_KEY);
        emailjs.init({
            publicKey: PUBLIC_KEY,
            // Do not allow headless browsers
            blockHeadless: true,
            blockList: {
                // Block the suspended email
                // The variable contains the email address
                watchVariable: 'userEmail',
            },
            limitRate: {
                // Set the limit rate for the application
                id: 'app',
                // Allow 1 request per 10s
                throttle: 10000,
            },
        });
    }, []);

    // Form fields
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [role, setRole] = useState('student');
    const [formError, setFormError] = useState('');

    // OTP related states
    const [otp, setOtp] = useState('');
    const [userEnteredOtp, setUserEnteredOtp] = useState('');
    const [otpSent, setOtpSent] = useState(false);
    const [otpVerified, setOtpVerified] = useState(false);
    const [otpError, setOtpError] = useState('');
    const [countdown, setCountdown] = useState(0);
    const [emailSubmitted, setEmailSubmitted] = useState(false);

    // Timer for OTP resend cooldown
    useEffect(() => {
        if (countdown > 0) {
            const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
            return () => clearTimeout(timer);
        }
    }, [countdown]);

    // Generate OTP
    const generateOtp = () => {
        return Math.floor(100000 + Math.random() * 900000).toString();
    };

    // Send OTP to email
    const handleSendOtp = async (e: { preventDefault: () => void; }) => {
        e.preventDefault();
        setOtpError('');

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            setOtpError('Please enter a valid email address');
            return;
        }

        try {
            // Generate OTP
            const generatedOtp = generateOtp();
            setOtp(generatedOtp);

            const otpExpiryIST = new Date(Date.now() + 15 * 60 * 1000) // Add 15 minutes
                .toLocaleString('en-IN', {
                    timeZone: 'Asia/Kolkata',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true,
                    day: 'numeric',
                    month: 'short',
                    year: 'numeric',
                });

            // Final templateParams with IST time
            const templateParams = {
                email: email,
                name: username || email.split('@')[0],
                passcode: generatedOtp,
                time: otpExpiryIST,
            };
            // alert(`For demo purposes: Your OTP is ${generatedOtp}`);

            // Send email using EmailJS
            if (SERVICE_ID && TEMPLATE_ID) {
                emailjs.send(SERVICE_ID, TEMPLATE_ID, templateParams);
            } else {
                console.error('SERVICE_ID or TEMPLATE_ID is not defined');
                // You can also throw an error or handle this situation in a way that makes sense for your application
            }


            // Update UI states
            setOtpSent(true);
            setEmailSubmitted(true);
            setCountdown(60); // 60 seconds cooldown

            // For development purposes only - remove in production
            // console.log(`OTP for ${email}: ${generatedOtp}`);

        } catch (error) {
            console.error('Error sending OTP:', error);
            setOtpError('Failed to send verification code. Please try again.');
        }
    };

    // Verify OTP
    const handleVerifyOtp = (e: { preventDefault: () => void; }) => {
        e.preventDefault();
        setOtpError('');

        if (!userEnteredOtp) {
            setOtpError('Please enter the OTP');
            return;
        }

        if (userEnteredOtp === otp) {
            setOtpVerified(true);
            setOtpError('');
        } else {
            setOtpError('Invalid OTP. Please try again.');
        }
    };

    // Resend OTP
    const handleResendOtp = async () => {
        if (countdown > 0) return;

        try {
            const generatedOtp = generateOtp();
            setOtp(generatedOtp);

            // Prepare email template parameters
            const otpExpiryIST = new Date(Date.now() + 15 * 60 * 1000) // Add 15 minutes
                .toLocaleString('en-IN', {
                    timeZone: 'Asia/Kolkata',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true,
                    day: 'numeric',
                    month: 'short',
                    year: 'numeric',
                });

            // Final templateParams with IST time
            const templateParams = {
                email: email,
                name: username || email.split('@')[0],
                passcode: generatedOtp,
                time: otpExpiryIST,
            };

            // Send email using EmailJS
            if (SERVICE_ID && TEMPLATE_ID) {
                emailjs.send(SERVICE_ID, TEMPLATE_ID, templateParams);
            } else {
                console.error('SERVICE_ID or TEMPLATE_ID is not defined');
                // You can also throw an error or handle this situation in a way that makes sense for your application
            }
            setCountdown(60); // 60 seconds cooldown

            // For development purposes only - remove in production
            console.log(`OTP for ${email} (resent): ${generatedOtp}`);

        } catch (error) {
            console.error('Error resending OTP:', error);
            setOtpError('Failed to send verification code. Please try again.');
        }
    };

    // Handle registration form submission
    const handleSubmit = async (e: { preventDefault: () => void; }) => {
        e.preventDefault();
        setFormError('');

        if (!username || !email || !password || !confirmPassword) {
            setFormError('All fields are required');
            return;
        }

        if (password !== confirmPassword) {
            setFormError('Passwords do not match');
            return;
        }

        try {
            await register(username, password, email, role);

            // Optional: Send welcome email after successful registration
            const welcomeTemplateParams = {
                to_email: email,
                to_name: username,
                recipient: email,
                subject: 'Welcome to Our Platform',
                message: `Thank you for registering with us, ${username}! Your account has been created successfully.`
            };

            // You can use a different template ID for welcome emails
            await emailjs.send(
                SERVICE_ID ?? 'default_service_id',
                TEMPLATE_ID ?? 'default_template_id',
                welcomeTemplateParams
            );

        } catch (err) {
            setFormError(err instanceof Error ? err.message : 'An error occurred');
        }
    };

    // Edit email button
    const handleEditEmail = () => {
        setEmailSubmitted(false);
        setOtpSent(false);
        setOtpVerified(false);
        setOtp('');
        setUserEnteredOtp('');
    };

    return (
        <div className="max-w-lg mx-auto bg-white rounded-2xl shadow-xl overflow-hidden">
            {/* Header */}
            <div className="relative bg-gradient-to-r from-gray-900 to-black text-white p-8">
                <div className="absolute top-0 left-0 w-full h-full bg-black opacity-50"></div>
                <div className="relative z-10">
                    <h2 className="text-2xl font-bold">Sign Up</h2>
                    <p className="text-gray-300 mt-2">Register to manage or submit capstone projects</p>
                </div>
                <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-teal-500 to-cyan-500"></div>
            </div>

            {/* Email and OTP Verification Step */}
            {!otpVerified && (
                <div className="p-8">
                    {isLoading ? (
                        <div className="py-8">
                            <Loader variant="default" size="medium" text="Processing your request..." />
                        </div>
                    ) : (
                        <>
                            <div className="mb-5">
                                <h3 className="text-lg font-medium text-gray-800 mb-3">Step 1: Verify Your Email</h3>
                                <p className="text-gray-600 mb-4">We'll send a verification code to your email address.</p>
                            </div>

                            {error && (
                                <div className="mb-5 bg-red-50 border-l-4 border-red-500 p-4 rounded-md">
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

                            <div className="mb-5">
                                <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                                <div className="flex gap-2">
                                    <input
                                        id="email"
                                        type="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        placeholder="Enter your email"
                                        disabled={emailSubmitted}
                                        className={`block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500 ${emailSubmitted ? 'bg-gray-50' : ''}`}
                                    />
                                    {emailSubmitted && (
                                        <button
                                            onClick={handleEditEmail}
                                            className="px-3 py-1 border border-gray-300 rounded-lg hover:bg-gray-50 text-sm transition-colors"
                                        >
                                            Edit
                                        </button>
                                    )}
                                </div>
                            </div>

                            {!emailSubmitted && (
                                <button
                                    onClick={handleSendOtp}
                                    disabled={!email || countdown > 0}
                                    className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200 disabled:opacity-50"
                                >
                                    {countdown > 0 ? `Resend OTP in ${countdown}s` : 'Send OTP'}
                                </button>
                            )}

                            {otpSent && (
                                <>
                                    <div className="mb-5 mt-6">
                                        <label htmlFor="otp" className="block text-sm font-medium text-gray-700 mb-1">
                                            Enter Verification Code
                                        </label>
                                        <div className="flex gap-2">
                                            <input
                                                id="otp"
                                                type="text"
                                                value={userEnteredOtp}
                                                onChange={(e) => setUserEnteredOtp(e.target.value)}
                                                placeholder="Enter 6-digit OTP"
                                                maxLength={6}
                                                className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                            />
                                        </div>
                                        <div className="mt-2 text-right">
                                            <button
                                                onClick={handleResendOtp}
                                                disabled={countdown > 0}
                                                className="text-sm text-teal-600 hover:text-teal-500 disabled:text-gray-400"
                                            >
                                                {countdown > 0 ? `Resend in ${countdown}s` : 'Resend OTP'}
                                            </button>
                                        </div>
                                    </div>

                                    <button
                                        onClick={handleVerifyOtp}
                                        disabled={!userEnteredOtp}
                                        className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200 disabled:opacity-50"
                                    >
                                        Verify Email
                                    </button>
                                </>
                            )}
                        </>
                    )}
                </div>
            )}

            {/* Registration Form Step */}
            {otpVerified && (
                <form onSubmit={handleSubmit} className="p-8">
                    {isLoading ? (
                        <div className="py-8">
                            <Loader variant="default" size="medium" text="Creating your account..." />
                        </div>
                    ) : (
                        <>
                            <div className="mb-5">
                                <h3 className="text-lg font-medium text-gray-800 mb-3">Step 2: Complete Your Registration</h3>
                                <p className="text-gray-600 mb-4">Email verified successfully. Please complete your registration.</p>
                            </div>

                            {error && (
                                <div className="mb-5 bg-red-50 border-l-4 border-red-500 p-4 rounded-md">
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

                            <div className="mb-5">
                                <label htmlFor="verifiedEmail" className="block text-sm font-medium text-gray-700 mb-1">
                                    Email
                                </label>
                                <div className="flex items-center gap-2">
                                    <input
                                        id="verifiedEmail"
                                        type="email"
                                        value={email}
                                        disabled
                                        className="block w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50"
                                    />
                                    <div className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded-full flex items-center">
                                        <svg className="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                        </svg>
                                        Verified
                                    </div>
                                </div>
                            </div>

                            <div className="mb-5">
                                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                                    Username
                                </label>
                                <input
                                    id="username"
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="Choose a username"
                                    className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                />
                            </div>

                            <div className="mb-5">
                                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                                    Password
                                </label>
                                <input
                                    id="password"
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Create a password"
                                    className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                />
                            </div>

                            <div className="mb-5">
                                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
                                    Confirm Password
                                </label>
                                <input
                                    id="confirmPassword"
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Confirm your password"
                                    className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                />
                            </div>

                            <div className="mb-6">
                                <label htmlFor="role" className="block text-sm font-medium text-gray-700 mb-1">
                                    Role
                                </label>
                                <select
                                    id="role"
                                    value={role}
                                    onChange={(e) => setRole(e.target.value)}
                                    className="block w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                                >
                                    <option value="student">Student</option>
                                    <option value="teacher">Teacher</option>
                                    <option value="academic_team">Academic Team</option>
                                    <option value="evaluator">Evaluator</option>
                                    <option value="manager">Manager</option>
                                    <option value="coordinator">Coordinator</option>
                                    {/* <option value="admin">Admin</option> */}
                                </select>
                            </div>

                            <button
                                type="submit"
                                disabled={isLoading}
                                className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 transition-all duration-200 disabled:opacity-50"
                            >
                                Complete Registration
                            </button>
                        </>
                    )}
                </form>
            )}

            <div className="px-8 pb-8">
                <p className="text-center text-sm text-gray-600">
                    Already have an account?{' '}
                    <Link href="/login" className="text-teal-600 font-medium hover:text-teal-500">
                        Login here
                    </Link>
                </p>
            </div>
        </div>
    );
};

export default RegisterForm;