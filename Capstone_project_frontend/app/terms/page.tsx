'use client';

import Link from 'next/link';

const TermsPage = () => {
    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Header */}
                <div className="text-center mb-12">
                    <h1 className="text-4xl font-extrabold text-gray-900 mb-4">Terms of Service</h1>
                    <p className="text-lg text-gray-600">Last updated: {new Date().toLocaleDateString()}</p>
                </div>

                {/* Content */}
                <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
                    <div className="relative bg-gradient-to-r from-gray-900 to-black text-white p-8">
                        <div className="absolute top-0 left-0 w-full h-full bg-black opacity-50"></div>
                        <div className="relative z-10">
                            <h2 className="text-2xl font-bold mb-2">Welcome to Capstone Portal</h2>
                            <p className="text-gray-300">Please read these terms carefully before using our platform</p>
                        </div>
                        <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-teal-500 to-cyan-500"></div>
                    </div>

                    <div className="p-8 space-y-8">
                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">1. Acceptance of Terms</h3>
                            <p className="text-gray-600 leading-relaxed">
                                By accessing and using the Capstone Portal, you agree to be bound by these Terms of Service and all applicable laws and regulations. If you do not agree with any of these terms, you are prohibited from using or accessing this platform.
                            </p>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">2. User Responsibilities</h3>
                            <div className="space-y-3 text-gray-600">
                                <p className="leading-relaxed">As a user of the Capstone Portal, you agree to:</p>
                                <ul className="list-disc pl-6 space-y-2">
                                    <li>Maintain the confidentiality of your account credentials</li>
                                    <li>Submit original and authentic project work</li>
                                    <li>Respect intellectual property rights</li>
                                    <li>Follow academic integrity guidelines</li>
                                    <li>Engage professionally with other users</li>
                                </ul>
                            </div>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">3. Academic Integrity</h3>
                            <p className="text-gray-600 leading-relaxed">
                                The Capstone Portal is committed to maintaining high standards of academic integrity. Plagiarism, cheating, and any form of academic dishonesty will result in immediate action, including but not limited to account suspension and academic penalties.
                            </p>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">4. Intellectual Property</h3>
                            <p className="text-gray-600 leading-relaxed">
                                All content submitted through the Capstone Portal remains the intellectual property of its original creators. Users grant the platform a license to store, display, and process submitted content for educational purposes.
                            </p>
                        </section>

                        <section className="space-y-4">
                            <h3 className="text-xl font-semibold text-gray-900">5. Platform Usage</h3>
                            <div className="space-y-3 text-gray-600">
                                <p className="leading-relaxed">The platform is provided for:</p>
                                <ul className="list-disc pl-6 space-y-2">
                                    <li>Submitting and managing capstone projects</li>
                                    <li>Facilitating project review and feedback</li>
                                    <li>Supporting academic collaboration</li>
                                    <li>Generating project certifications</li>
                                </ul>
                            </div>
                        </section>
                    </div>
                </div>

                {/* Footer Navigation */}
                <div className="mt-12 flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-8">
                    <Link
                        href="/privacy"
                        className="inline-flex items-center text-teal-600 hover:text-teal-500 font-medium"
                    >
                        <span>Privacy Policy</span>
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

export default TermsPage; 