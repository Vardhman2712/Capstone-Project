'use client';

import Link from 'next/link';
import { useAuth } from '@/app/context/AuthContext';
import Image from 'next/image';
import { motion } from 'framer-motion';

const Footer = () => {
    const { user } = useAuth();
    const currentYear = new Date().getFullYear();

    // Animation variants
    const fadeInUp = {
        initial: { y: 20, opacity: 0 },
        animate: { y: 0, opacity: 1 },
        transition: { duration: 0.5 }
    };

    const staggerContainer = {
        animate: {
            transition: {
                staggerChildren: 0.1
            }
        }
    };

    const getFooterLinks = () => {
        if (!user) {
            return [
                { href: '/', label: 'Home' },
                { href: '/login', label: 'Login' },
                { href: '/register', label: 'Register' },
            ];
        }

        switch (user.role) {
            case 'admin':
            case 'manager':
                return [
                    { href: '/', label: 'Home' },
                    { href: '/dashboard', label: 'Dashboard' },
                ];
            case 'teacher':
                return [
                    { href: '/', label: 'Home' },
                    { href: '/dashboard', label: 'Dashboard' },
                    { href: '/projects/create', label: 'Create Projects' },
                    { href: '/reviews', label: 'Review Submissions' },
                ];
            case 'coordinator':
                return [
                    { href: '/', label: 'Home' },
                    { href: '/dashboard', label: 'Dashboard' },
                    { href: '/projects/create', label: 'Create Projects' },
                    { href: '/reviews', label: 'Review Submissions' },
                ];
            case 'student':
                return [
                    { href: '/', label: 'Home' },
                    { href: '/dashboard', label: 'Dashboard' },
                    { href: '/my_submissions', label: 'My Submissions' },
                    { href: '/reviews', label: 'Reviews' },
                    { href: '/certifications', label: 'Certifications' },
                ];
            case 'academic_team':
                return [
                    { href: '/', label: 'Home' },
                    { href: '/dashboard', label: 'Dashboard' },
                    { href: '/projects/create', label: 'Create Projects' },
                    { href: '/reviews', label: 'Reviews' },
                ];
            default:
                return [{ href: '/', label: 'Home' }];
        }
    };

    const footerLinks = getFooterLinks();

    const features = [
        {
            icon: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
            text: "Project Management",
            gradient: "from-teal-500 to-cyan-500"
        },
        {
            icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z",
            text: "Peer Review System",
            gradient: "from-blue-500 to-indigo-500"
        },
        {
            icon: "M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253",
            text: "Academic Excellence",
            gradient: "from-purple-500 to-pink-500"
        },
        {
            icon: "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
            text: "Digital Certifications",
            gradient: "from-amber-500 to-orange-500"
        }
    ];

    return (
        <footer className="relative bg-gradient-to-br from-gray-900 via-gray-950 to-black text-white overflow-hidden">
            {/* Background Pattern */}
            <div className="absolute inset-0">
                <div
                    className="absolute inset-0 opacity-5"
                    style={{
                        backgroundImage: `radial-gradient(circle at 25px 25px, white 1px, transparent 0)`,
                        backgroundSize: '50px 50px'
                    }}
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-transparent to-transparent" />
            </div>

            {/* Animated Gradient Blobs */}
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 0.15 }}
                transition={{ duration: 1 }}
                className="absolute inset-0 overflow-hidden pointer-events-none"
            >
                <div className="absolute -top-1/2 -right-1/2 w-96 h-96 bg-gradient-to-br from-teal-500 to-cyan-500 rounded-full blur-3xl animate-blob" />
                <div className="absolute -bottom-1/2 -left-1/2 w-96 h-96 bg-gradient-to-br from-blue-500 to-indigo-500 rounded-full blur-3xl animate-blob animation-delay-2000" />
                <div className="absolute top-1/2 left-1/2 w-96 h-96 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full blur-3xl animate-blob animation-delay-4000" />
            </motion.div>

            <div className="relative z-10">
                {/* Main Footer Content */}
                <motion.div
                    variants={staggerContainer}
                    initial="initial"
                    whileInView="animate"
                    viewport={{ once: true }}
                    className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-16 pb-8"
                >
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-12 mb-12">
                        {/* Brand & Description */}
                        <motion.div
                            variants={fadeInUp}
                            className="lg:col-span-1 space-y-6"
                        >
                            <div className="flex items-center space-x-4 group">
                                <div className="relative">
                                    <div className="w-14 h-14 bg-gradient-to-br from-teal-500 to-cyan-500 rounded-2xl flex items-center justify-center shadow-2xl group-hover:shadow-teal-500/25 transition-all duration-300">
                                        <span className="text-white font-black text-xl">CP</span>
                                    </div>
                                    <div className="absolute -inset-1 bg-gradient-to-br from-teal-500 to-cyan-500 rounded-2xl opacity-20 group-hover:opacity-30 transition-opacity duration-300 blur-xl"></div>
                                </div>
                                <div>
                                    <h3 className="text-2xl font-bold bg-gradient-to-r from-teal-400 to-cyan-400 bg-clip-text text-transparent">
                                        Capstone Portal
                                    </h3>
                                    <p className="text-gray-400 text-sm font-medium">Academic Excellence Platform</p>
                                </div>
                            </div>

                            <p className="text-gray-300 leading-relaxed max-w-md">
                                Empowering academic excellence through innovative project management, collaborative peer review, and comprehensive digital certification systems.
                            </p>

                            {/* Key Features Grid */}
                            <div className="grid grid-cols-2 gap-3 mt-6">
                                {features.map((feature, index) => (
                                    <motion.div
                                        key={index}
                                        variants={fadeInUp}
                                        className="group flex items-center space-x-3 p-3 rounded-xl bg-white/5 hover:bg-white/10 transition-all duration-300 border border-white/10 hover:border-white/20"
                                    >
                                        <div className={`flex-shrink-0 p-2 rounded-lg bg-gradient-to-br ${feature.gradient} bg-opacity-10`}>
                                            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={feature.icon} />
                                            </svg>
                                        </div>
                                        <span className="text-sm text-gray-300 group-hover:text-white transition-colors duration-300 font-medium">
                                            {feature.text}
                                        </span>
                                    </motion.div>
                                ))}
                            </div>
                        </motion.div>

                        {/* Quick Navigation */}
                        <motion.div
                            variants={fadeInUp}
                            className="lg:col-span-1 space-y-6"
                        >
                            <h4 className="text-lg font-semibold text-white mb-6 flex items-center">
                                <div className="w-1 h-6 bg-gradient-to-b from-teal-500 to-cyan-500 rounded-full mr-3"></div>
                                Quick Navigation
                            </h4>
                            <nav className="space-y-3">
                                {footerLinks.map((link, index) => (
                                    <motion.div
                                        key={link.href}
                                        variants={fadeInUp}
                                        custom={index}
                                    >
                                        <Link
                                            href={link.href}
                                            className="group flex items-center space-x-3 text-gray-300 hover:text-white transition-all duration-300 p-2 rounded-lg hover:bg-white/5"
                                        >
                                            <div className="w-2 h-2 bg-gradient-to-r from-teal-500 to-cyan-500 rounded-full opacity-0 group-hover:opacity-100 transform scale-0 group-hover:scale-100 transition-all duration-300"></div>
                                            <span className="font-medium">{link.label}</span>
                                            <svg className="w-4 h-4 opacity-0 group-hover:opacity-100 transform translate-x-0 group-hover:translate-x-1 transition-all duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                            </svg>
                                        </Link>
                                    </motion.div>
                                ))}
                            </nav>
                        </motion.div>

                        {/* Developer Section */}
                        <motion.div
                            variants={fadeInUp}
                            className="lg:col-span-1"
                        >
                            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10 shadow-2xl">
                                <h4 className="text-lg font-semibold text-white mb-6 flex items-center">
                                    <div className="w-1 h-6 bg-gradient-to-b from-teal-500 to-cyan-500 rounded-full mr-3"></div>
                                    Created By
                                </h4>

                                <div className="flex items-center space-x-4 mb-6">
                                    <div className="relative">
                                        <div className="w-16 h-16 rounded-2xl overflow-hidden border-2 border-gradient-to-br from-teal-500 to-cyan-500 shadow-xl">
                                            <Image
                                                src="https://media.licdn.com/dms/image/v2/D5603AQEg5HxGZJm07w/profile-displayphoto-shrink_400_400/profile-displayphoto-shrink_400_400/0/1731651844420?e=1750291200&v=beta&t=L7f3Y_AXIToUiG6MmWHuMJEiM_dHbqeSTy7qAofDd0Q"
                                                alt="Moksh Upadhyay"
                                                width={64}
                                                height={64}
                                                className="w-full h-full object-cover transition-transform duration-300 hover:scale-110"
                                            />
                                        </div>
                                        <div className="absolute -inset-1 bg-gradient-to-br from-teal-500 to-cyan-500 rounded-2xl opacity-20 blur-lg"></div>
                                    </div>
                                    <div>
                                        <h5 className="text-xl font-bold text-white">Moksh Upadhyay</h5>
                                        <div className="flex items-center space-x-2 mt-1">
                                            <div className="px-3 py-1 bg-gradient-to-r from-teal-500/20 to-cyan-500/20 rounded-full border border-teal-500/30">
                                                <span className="text-xs font-semibold text-teal-300 uppercase tracking-wide">Software Engineer</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <p className="text-gray-300 text-sm leading-relaxed mb-6 pl-4 border-l-2 border-gradient-to-b from-teal-500 to-cyan-500 italic">
                                    "Crafting digital experiences that bridge academic excellence with technological innovation."
                                </p>

                                {/* Social Links */}
                                <div className="flex items-center space-x-3">
                                    <motion.a
                                        whileHover={{ scale: 1.05 }}
                                        whileTap={{ scale: 0.95 }}
                                        href="https://github.com/mokshupadhyay"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="group flex items-center justify-center w-10 h-10 bg-white/5 hover:bg-white/10 rounded-xl transition-all duration-300 border border-white/10 hover:border-white/20"
                                    >
                                        <svg className="w-5 h-5 text-gray-300 group-hover:text-white transition-colors duration-300" fill="currentColor" viewBox="0 0 24 24">
                                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                                        </svg>
                                    </motion.a>
                                    <motion.a
                                        whileHover={{ scale: 1.05 }}
                                        whileTap={{ scale: 0.95 }}
                                        href="https://www.linkedin.com/in/moksh-upadhyay-4b5a61257/"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="group flex items-center justify-center w-10 h-10 bg-white/5 hover:bg-white/10 rounded-xl transition-all duration-300 border border-white/10 hover:border-white/20"
                                    >
                                        <svg className="w-5 h-5 text-gray-300 group-hover:text-white transition-colors duration-300" fill="currentColor" viewBox="0 0 24 24">
                                            <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
                                        </svg>
                                    </motion.a>
                                    <motion.a
                                        whileHover={{ scale: 1.02 }}
                                        whileTap={{ scale: 0.98 }}
                                        href="https://mokshdev.vercel.app/"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="group flex-1 flex items-center justify-center px-4 py-2 bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 rounded-xl font-medium text-sm transition-all duration-300 shadow-lg hover:shadow-xl"
                                    >
                                        <svg className="w-4 h-4 mr-2 group-hover:rotate-12 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                        </svg>
                                        Portfolio
                                    </motion.a>
                                </div>
                            </div>
                        </motion.div>
                    </div>

                    {/* Bottom Section */}
                    <motion.div
                        variants={fadeInUp}
                        className="border-t border-white/10 pt-8"
                    >
                        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
                            {/* Copyright */}
                            <div className="flex items-center space-x-2">
                                <div className="w-8 h-8 bg-gradient-to-br from-teal-500 to-cyan-500 rounded-lg flex items-center justify-center">
                                    <span className="text-white font-bold text-xs">©</span>
                                </div>
                                <p className="text-gray-400 text-sm">
                                    <span className="font-semibold text-gray-300">{currentYear}</span> Capstone Portal. Crafted with passion for academic excellence
                                </p>
                            </div>

                            {/* Status Badge */}
                            <div className="flex items-center space-x-4">
                                <div className="flex items-center space-x-2 px-3 py-1.5 bg-teal-900/30 border border-teal-500/30 rounded-full">
                                    <div className="w-2 h-2 bg-teal-400 rounded-full animate-pulse"></div>
                                    <span className="text-teal-300 text-xs font-medium">System Online</span>
                                </div>
                                {/* <div className="text-gray-500 text-xs flex items-center">
                                    Made with{' '}
                                    <motion.span
                                        animate={{
                                            scale: [1, 1.2, 1],
                                            transition: {
                                                repeat: Infinity,
                                                duration: 2
                                            }
                                        }}
                                        className="mx-1 text-red-500"
                                    >
                                        ❤️
                                    </motion.span>{' '}
                                    in India
                                </div> */}
                            </div>
                        </div>
                    </motion.div>
                </motion.div>
            </div>

            <style jsx>{`
                @keyframes blob {
                    0% { transform: translate(0, 0) scale(1); }
                    33% { transform: translate(30px, -50px) scale(1.1); }
                    66% { transform: translate(-20px, 20px) scale(0.9); }
                    100% { transform: translate(0, 0) scale(1); }
                }
                .animate-blob {
                    animation: blob 7s infinite;
                }
                .animation-delay-2000 {
                    animation-delay: 2s;
                }
                .animation-delay-4000 {
                    animation-delay: 4s;
                }
            `}</style>
        </footer>
    );
};

export default Footer;