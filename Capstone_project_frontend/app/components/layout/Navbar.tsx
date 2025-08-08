
'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useAuth } from '@/app/context/AuthContext';
import { useRouter } from 'next/navigation';

const Navbar = () => {
    const { user, logout } = useAuth();
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [isLoggingOut, setIsLoggingOut] = useState(false);
    const [isScrolled, setIsScrolled] = useState(false);
    const router = useRouter();

    // Handle scroll effect
    useEffect(() => {
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 10);
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    // Prevent scrolling when mobile menu is open
    useEffect(() => {
        if (mobileMenuOpen) {
            document.body.style.overflow = 'hidden';
            document.body.style.paddingRight = '0px'; // Prevent layout shift
        } else {
            document.body.style.overflow = 'unset';
            document.body.style.paddingRight = '0px';
        }
        return () => {
            document.body.style.overflow = 'unset';
            document.body.style.paddingRight = '0px';
        };
    }, [mobileMenuOpen]);

    const toggleMobileMenu = () => setMobileMenuOpen(!mobileMenuOpen);
    const handleNavClick = () => setMobileMenuOpen(false);

    const handleLogout = async () => {
        if (isLoggingOut) return;
        try {
            setIsLoggingOut(true);
            await new Promise(resolve => setTimeout(resolve, 500));
            logout();
            setMobileMenuOpen(false);
            await router.push('/login');
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            setIsLoggingOut(false);
        }
    };

    const getNavLinks = () => {
        if (!user) {
            return [
                { href: '/', label: 'Home' },
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

    const navLinks = getNavLinks();

    return (
        <>
            <nav className={`fixed w-full z-50 transition-all duration-300 ${isScrolled ? 'bg-white/90 backdrop-blur-xl shadow-lg border-b border-slate-200/50' : 'bg-white/95 backdrop-blur-sm'}`}>
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center py-4">
                        {/* Logo */}
                        <Link href="/" className="flex items-center group" onClick={handleNavClick}>
                            <div className="flex items-center space-x-3">
                                <div className="w-10 h-10 bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-105">
                                    <span className="text-white font-bold text-lg">CP</span>
                                </div>
                                <div className="transform transition-transform duration-300 group-hover:translate-x-1">
                                    <h1 className="text-xl font-bold text-slate-900 tracking-tight">Capstone Portal</h1>
                                    <p className="text-xs text-slate-500 -mt-1">Academic Excellence</p>
                                </div>
                            </div>
                        </Link>

                        {/* Desktop Menu */}
                        <div className="hidden lg:flex items-center space-x-1">
                            {navLinks.map((link) => (
                                <Link
                                    key={link.href}
                                    href={link.href}
                                    className="relative px-4 py-2.5 text-slate-700 hover:text-slate-900 rounded-xl transition-all duration-200 font-medium group overflow-hidden"
                                >
                                    <span className="relative z-10">{link.label}</span>
                                    <div className="absolute inset-0 bg-slate-50 transform origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-200 rounded-xl"></div>
                                    <div className="absolute bottom-1.5 left-4 right-4 h-0.5 bg-gradient-to-r from-teal-400 to-cyan-400 transform origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-300 group-hover:shadow-[0_0_8px_rgba(45,212,191,0.4)]"></div>
                                </Link>
                            ))}

                            {user ? (
                                <div className="flex items-center ml-6 pl-6 border-l border-slate-200">
                                    <div className="flex items-center space-x-4">
                                        <div className="text-right">
                                            <div className="text-sm font-semibold text-slate-900">{user.username}</div>
                                            <div className="text-xs text-slate-500 capitalize">{user.role}</div>
                                        </div>
                                        <div className="w-10 h-10 bg-gradient-to-br from-slate-700 to-slate-800 rounded-full flex items-center justify-center shadow-lg transform hover:scale-105 transition-transform duration-200">
                                            <span className="text-white font-semibold text-sm">
                                                {user.username.charAt(0).toUpperCase()}
                                            </span>
                                        </div>
                                        <button
                                            onClick={handleLogout}
                                            disabled={isLoggingOut}
                                            className="relative bg-slate-900 hover:bg-slate-800 text-white px-5 py-2.5 rounded-xl font-medium transition-all duration-300 shadow-lg hover:shadow-xl disabled:bg-slate-700 disabled:cursor-not-allowed group overflow-hidden"
                                        >
                                            <div className={`flex items-center justify-center ${isLoggingOut ? 'opacity-0' : 'opacity-100'} transition-opacity duration-200`}>
                                                <svg className="w-4 h-4 mr-2 transform group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                                </svg>
                                                Logout
                                            </div>
                                            {isLoggingOut && (
                                                <div className="absolute inset-0 flex items-center justify-center bg-slate-900">
                                                    <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                                </div>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex items-center space-x-3 ml-6">
                                    <Link
                                        href="/login"
                                        className="relative text-slate-700 hover:text-slate-900 px-4 py-2.5 rounded-xl font-medium transition-all duration-200 hover:bg-slate-50 group"
                                    >
                                        <span className="relative z-10">Login</span>
                                        <div className="absolute bottom-1.5 left-4 right-4 h-0.5 bg-gradient-to-r from-teal-400 to-cyan-400 transform origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-300 group-hover:shadow-[0_0_8px_rgba(45,212,191,0.4)]"></div>
                                    </Link>
                                    <Link
                                        href="/register"
                                        className="bg-slate-900 hover:bg-slate-800 text-white px-5 py-2.5 rounded-xl font-medium transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105"
                                    >
                                        Register
                                    </Link>
                                </div>
                            )}
                        </div>

                        {/* Mobile Menu Button */}
                        <div className="lg:hidden">
                            <button
                                onClick={toggleMobileMenu}
                                className="text-slate-700 hover:text-slate-900 p-2.5 rounded-xl hover:bg-slate-50 transition-all duration-200 relative z-[60]"
                                aria-label="Toggle mobile menu"
                            >
                                <svg
                                    className="h-6 w-6 transform transition-all duration-300"
                                    style={{ transform: mobileMenuOpen ? 'rotate(180deg)' : 'rotate(0)' }}
                                    fill="none"
                                    viewBox="0 0 24 24"
                                    stroke="currentColor"
                                    strokeWidth={2}
                                >
                                    <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        d={mobileMenuOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16m-7 6h7"}
                                    />
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Mobile Menu Overlay */}
            {mobileMenuOpen && (
                <div className="fixed inset-0 z-[55] lg:hidden">
                    {/* Blur Backdrop */}
                    <div
                        className="absolute inset-0 bg-black/40 backdrop-blur-md transition-opacity duration-300"
                        onClick={() => setMobileMenuOpen(false)}
                    />

                    {/* Mobile Menu Panel */}
                    <div className="absolute inset-y-0 right-0 w-full max-w-sm bg-white/95 backdrop-blur-xl shadow-2xl border-l border-slate-200/50">
                        <div className="flex flex-col h-full">
                            {/* Header */}
                            <div className="flex items-center justify-between p-6 border-b border-slate-200/60 bg-gradient-to-r from-slate-50 to-white">
                                <div className="flex items-center space-x-3">
                                    <div className="w-8 h-8 bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg flex items-center justify-center shadow-md">
                                        <span className="text-white font-bold text-sm">CP</span>
                                    </div>
                                    <h2 className="text-lg font-bold bg-gradient-to-r from-slate-800 to-slate-600 bg-clip-text text-transparent">Menu</h2>
                                </div>
                                <button
                                    onClick={() => setMobileMenuOpen(false)}
                                    className="p-2 text-slate-500 hover:text-slate-700 rounded-xl hover:bg-slate-100 transition-all duration-200"
                                >
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            {/* Navigation Links */}
                            <div className="flex-1 overflow-y-auto py-6 px-4">
                                <div className="space-y-2">
                                    {navLinks.map((link, index) => (
                                        <Link
                                            key={link.href}
                                            href={link.href}
                                            onClick={handleNavClick}
                                            className="group flex items-center px-4 py-4 text-slate-700 hover:text-slate-900 rounded-xl transition-all duration-200 hover:bg-gradient-to-r hover:from-slate-50 hover:to-slate-100 border border-transparent hover:border-slate-200/50 hover:shadow-sm"
                                            style={{ animationDelay: `${index * 50}ms` }}
                                        >
                                            <div className="w-2 h-2 bg-gradient-to-r from-teal-400 to-cyan-400 rounded-full mr-4 opacity-0 group-hover:opacity-100 transform scale-0 group-hover:scale-100 transition-all duration-200"></div>
                                            <span className="font-medium">{link.label}</span>
                                            <svg className="w-4 h-4 ml-auto text-slate-400 group-hover:text-slate-600 transform group-hover:translate-x-1 transition-all duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                            </svg>
                                        </Link>
                                    ))}
                                </div>
                            </div>

                            {/* Authentication Section */}
                            <div className="p-6 border-t border-slate-200/60 bg-gradient-to-t from-slate-50/50 to-transparent">
                                {user ? (
                                    <div className="space-y-4">
                                        {/* User Profile */}
                                        <div className="flex items-center space-x-4 p-4 bg-white rounded-xl shadow-sm border border-slate-200/50">
                                            <div className="w-12 h-12 bg-gradient-to-br from-slate-700 to-slate-800 rounded-full flex items-center justify-center shadow-lg">
                                                <span className="text-white font-bold text-lg">
                                                    {user.username.charAt(0).toUpperCase()}
                                                </span>
                                            </div>
                                            <div className="flex-1">
                                                <div className="font-semibold text-slate-900">{user.username}</div>
                                                <div className="text-sm text-slate-500 capitalize bg-slate-100 px-2 py-1 rounded-full inline-block">
                                                    {user.role}
                                                </div>
                                            </div>
                                        </div>

                                        {/* Logout Button */}
                                        <button
                                            onClick={handleLogout}
                                            disabled={isLoggingOut}
                                            className="w-full bg-gradient-to-r from-slate-900 to-slate-800 hover:from-slate-800 hover:to-slate-700 text-white py-4 rounded-xl font-medium transition-all duration-300 shadow-lg hover:shadow-xl disabled:opacity-75 disabled:cursor-not-allowed group relative overflow-hidden"
                                        >
                                            <div className={`flex items-center justify-center ${isLoggingOut ? 'opacity-0' : 'opacity-100'} transition-opacity duration-200`}>
                                                <svg className="w-5 h-5 mr-2 transform group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                                </svg>
                                                Logout
                                            </div>
                                            {isLoggingOut && (
                                                <div className="absolute inset-0 flex items-center justify-center bg-slate-900">
                                                    <div className="h-5 w-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                                </div>
                                            )}
                                        </button>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        <Link
                                            href="/login"
                                            onClick={handleNavClick}
                                            className="w-full flex items-center justify-center px-6 py-4 bg-gradient-to-r from-slate-900 to-slate-800 hover:from-slate-800 hover:to-slate-700 text-white rounded-xl font-medium transition-all duration-300 shadow-lg hover:shadow-xl group"
                                        >
                                            <svg className="w-5 h-5 mr-2 group-hover:scale-110 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                                            </svg>
                                            Login
                                        </Link>
                                        <Link
                                            href="/register"
                                            onClick={handleNavClick}
                                            className="w-full flex items-center justify-center px-6 py-4 bg-white hover:bg-slate-50 text-slate-900 rounded-xl font-medium transition-all duration-300 border border-slate-200 shadow-sm hover:shadow-md group"
                                        >
                                            <svg className="w-5 h-5 mr-2 group-hover:scale-110 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                                            </svg>
                                            Register
                                        </Link>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};

export default Navbar;