'use client'

import { Suspense } from 'react';
import { useState } from "react";
import { useRouter } from 'next/navigation';
import ForgotPasswordModal from "../components/auth/ForgotPasswordModal";
import Loader from '../components/ui/Loader';

export default function ForgotPasswordPage() {
    const [isOpen, setIsOpen] = useState(true);
    const router = useRouter();

    const handleClose = () => {
        setIsOpen(false);
        router.push('/login');
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white">
            <Suspense fallback={<Loader variant="full-page" text="Loading password reset..." />}>
                <div className="container mx-auto px-4 py-8 flex items-center justify-center min-h-screen">
                    <div className="w-full max-w-xl">
                        <ForgotPasswordModal isOpen={isOpen} onClose={handleClose} />
                    </div>
                </div>
            </Suspense>
        </div>
    );
}