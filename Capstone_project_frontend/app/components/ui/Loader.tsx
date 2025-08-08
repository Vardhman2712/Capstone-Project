'use client';

import React from 'react';

interface LoaderProps {
    variant?: 'default' | 'minimal' | 'full-page';
    size?: 'small' | 'medium' | 'large';
    text?: string;
    className?: string;
}

const Loader: React.FC<LoaderProps> = ({
    variant = 'default',
    size = 'medium',
    text = 'Loading...',
    className = ''
}) => {
    // Size mappings for spinner dimensions
    const spinnerSizes = {
        small: {
            outer: 'w-16 h-16',
            inner: 'w-12 h-12',
            border: 'border-2',
            text: 'text-sm'
        },
        medium: {
            outer: 'w-24 h-24',
            inner: 'w-20 h-20',
            border: 'border-3',
            text: 'text-base'
        },
        large: {
            outer: 'w-32 h-32',
            inner: 'w-24 h-24',
            border: 'border-4',
            text: 'text-lg'
        }
    };

    const selectedSize = spinnerSizes[size];

    if (variant === 'minimal') {
        return (
            <div className={`flex items-center justify-center ${className}`}>
                <div className={`${selectedSize.outer} border-t-4 border-b-4 border-teal-500 rounded-full animate-spin`}></div>
            </div>
        );
    }

    if (variant === 'full-page') {
        return (
            <div className="fixed inset-0 bg-gradient-to-br from-gray-50 to-white flex items-center justify-center z-50">
                <div className="max-w-md w-full space-y-6 text-center px-4">
                    <div className="relative">
                        <div className="absolute inset-0 flex items-center justify-center">
                            <div className={`${selectedSize.outer} ${selectedSize.border} border-t border-b border-teal-500 rounded-full animate-spin`}></div>
                        </div>
                        <div className="absolute inset-0 flex items-center justify-center">
                            <div className={`${selectedSize.inner} ${selectedSize.border} border-t border-b border-cyan-500 rounded-full animate-spin-slow`}></div>
                        </div>
                    </div>
                    {text && (
                        <div className="mt-16 space-y-2">
                            <h2 className={`text-center font-semibold text-gray-900 ${selectedSize.text}`}>
                                {text}
                            </h2>
                            <p className="text-gray-500 text-sm">Please wait while we load your content</p>
                        </div>
                    )}
                </div>
            </div>
        );
    }

    // Default variant
    return (
        <div className={`flex flex-col items-center justify-center ${className}`}>
            <div className="relative">
                <div className="absolute inset-0 flex items-center justify-center">
                    <div className={`${selectedSize.outer} ${selectedSize.border} border-t border-b border-teal-500 rounded-full animate-spin`}></div>
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                    <div className={`${selectedSize.inner} ${selectedSize.border} border-t border-b border-cyan-500 rounded-full animate-spin-slow`}></div>
                </div>
            </div>
            {text && (
                <div className={`mt-16 text-center ${selectedSize.text}`}>
                    <p className="font-medium text-gray-900">{text}</p>
                </div>
            )}
        </div>
    );
};

export default Loader; 