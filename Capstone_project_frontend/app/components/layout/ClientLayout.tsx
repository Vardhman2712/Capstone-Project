'use client';

import { AuthProvider } from '@/app/context/AuthContext';
import Navbar from './Navbar';
import Footer from './Footer';

export default function ClientLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <AuthProvider>
            <div className="min-h-screen flex flex-col">
                <Navbar />
                <main className="flex-grow container mx-auto px-4 py-8 pt-[94px]">
                    {children}
                </main>
                <Footer />
            </div>
        </AuthProvider>
    );
} 