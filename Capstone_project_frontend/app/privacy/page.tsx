'use client';

import Link from 'next/link';

const PrivacyPage = () => {
    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Header */}
                <div className="text-center mb-12">
                    <h1 className="text-4xl font-extrabold text-gray-900 mb-4">Privacy Policy</h1>
                    <p className="text-lg text-gray-600">Last updated: {new Date().toLocaleDateString()}</p>
                </div>

                {/* Content */}
                <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
                    <div className="relative bg-gradient-to-r from-gray-900 to-black text-white p-8">
                        <div className="absolute top-0 left-0 w-full h-full bg-black opacity-50"></div>
                        <div className="relative z-10">
                            <h2 className="text-2xl font-bold mb-2">Your Privacy Matters</h2>
                            <p className="text-gray-300">Learn how we collect, use, and protect your information</p>
                        </div>
                        <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-teal-500 to-cyan-500"></div>
                    </div>

                    <div className="p-8 space-y-8">
                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">1. Information We Collect</h3>
                            <div className="space-y-3 text-gray-600">
                                <p className="leading-relaxed">We collect the following types of information:</p>
                                <ul className="list-disc pl-6 space-y-2">
                                    <li>Account information (name, email, academic details)</li>
                                    <li>Project submissions and related content</li>
                                    <li>Usage data and platform interactions</li>
                                    <li>Communication preferences</li>
                                </ul>
                            </div>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">2. How We Use Your Information</h3>
                            <div className="space-y-3 text-gray-600">
                                <p className="leading-relaxed">Your information helps us:</p>
                                <ul className="list-disc pl-6 space-y-2">
                                    <li>Manage your capstone project submissions</li>
                                    <li>Facilitate communication between students and faculty</li>
                                    <li>Generate project certifications</li>
                                    <li>Improve our platform and services</li>
                                    <li>Ensure academic integrity</li>
                                </ul>
                            </div>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">3. Data Security</h3>
                            <p className="text-gray-600 leading-relaxed">
                                We implement robust security measures to protect your information, including encryption, secure data storage, and regular security audits. Access to your data is strictly controlled and monitored.
                            </p>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">4. Data Sharing</h3>
                            <p className="text-gray-600 leading-relaxed">
                                We share your information only with authorized faculty members and administrators involved in the capstone project evaluation process. We never sell your personal information to third parties.
                            </p>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">5. Your Rights</h3>
                            <div className="space-y-3 text-gray-600">
                                <p className="leading-relaxed">You have the right to:</p>
                                <ul className="list-disc pl-6 space-y-2">
                                    <li>Access your personal information</li>
                                    <li>Request corrections to your data</li>
                                    <li>Download your project submissions</li>
                                    <li>Request data deletion (subject to academic requirements)</li>
                                </ul>
                            </div>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">6. Cookies and Tracking</h3>
                            <p className="text-gray-600 leading-relaxed">
                                We use cookies and similar technologies to enhance your experience and analyze platform usage. You can control cookie preferences through your browser settings.
                            </p>
                        </section>
                    </div>
                </div>

                {/* Footer Navigation */}
                <div className="mt-12 flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-8">
                    <Link
                        href="/terms"
                        className="inline-flex items-center text-teal-600 hover:text-teal-500 font-medium"
                    >
                        <span>Terms of Service</span>
                        <svg className="ml-2 w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                    </Link>
                    <Link
                        href="/"
                        className="inline-flex items-center px-6 py-2 border border-transparent text-base font-medium rounded-md text-white bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 shadow-sm transform hover:scale-105 transition-all duration-200"
                    >
                        Return to Home
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default PrivacyPage; 