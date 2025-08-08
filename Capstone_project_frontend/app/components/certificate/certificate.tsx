import React, { useState } from 'react';

import { Margin, Resolution, usePDF } from 'react-to-pdf';



const Certificate = ({
    studentName = "John Doe",
    projectName = "Advanced Web Development",
    teacherName = "Dr. Sarah Johnson",
    completionDate = "2024-05-25",
    projectDuration = "2 weeks",
    referenceNumber
}) => {
    const [isDownloading, setIsDownloading] = useState(false);

    const formatDate = (inputDate) => {
        const date = new Date(inputDate);
        return isNaN(date.getTime())
            ? 'Unknown Date'
            : date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
            });
    };

    const downloadAsPDF = async () => {
        setIsDownloading(true);
        try {
            // Use modern browser printing API for better PDF generation
            window.print();
        } catch (error) {
            console.error('Error generating PDF:', error);
        } finally {
            setIsDownloading(false);
        }
    };

    const { toPDF, targetRef } = usePDF({
        filename: `${studentName} - ${projectName} Certificate.pdf`,
        method: "save", // or "open" if you just want to preview
        resolution: Resolution.LOW, // or 1 (lowest acceptable for readable text)
        canvas: {
            mimeType: "image/jpeg", // JPEG is more compressed than PNG
            qualityRatio: 0.75,      // Lower = more compression, try 0.6–0.75
            useCORS: true,
            logging: false,
        },
        page: {
            format: "a4",           // Stick to standard formats to avoid rendering issues
            orientation: "portrait",
            margin: Margin.SMALL,   // Or 0 if you want to save even more space
        },
        overrides: {
            canvas: {
                scale: 3,             // Lower scale = smaller output; 1 is often good enough
            },
            pdf: {
                compress: true        // Enable compression in jsPDF
            }
        }
    });


    const formattedDate = formatDate(completionDate);
    const certNumber = referenceNumber || 'UC-' + Math.random().toString(36).substring(2, 15);
    const refNumber = Math.floor(1000 + Math.random() * 9000);

    return (
        <>
            <style jsx>{`
                @media print {
                    body * {
                        visibility: hidden;
                    }
                    .certificate-container,
                    .certificate-container * {
                        visibility: visible;
                    }
                    .certificate-container {
                        position: absolute;
                        left: 0;
                        top: 0;
                        width: 100%;
                    }
                    .no-print {
                        display: none !important;
                    }
                    .certificate {
                        box-shadow: none !important;
                        border: none !important;
                        margin: 0 !important;
                        page-break-inside: avoid;
                    }
                }
            `}</style>

            <div style={{
                minHeight: '100vh',
                background: 'linear-gradient(135deg, #f9fafb 0%, #dbeafe 50%, #e0e7ff 100%)',
                padding: '2rem 1rem'
            }}>
                <div style={{
                    maxWidth: '1200px',
                    margin: '0 auto'
                }}>
                    {/* Header with Download Button */}
                    <div className="no-print" style={{
                        textAlign: 'center',
                        marginBottom: '2rem'
                    }}>
                        <h1 style={{
                            fontSize: '2rem',
                            fontWeight: '700',
                            color: '#1f2937',
                            marginBottom: '1.5rem',
                            fontFamily: 'Georgia, serif'
                        }}>
                            Professional Certificate
                        </h1>
                        <button
                            onClick={toPDF}
                            disabled={isDownloading}
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                gap: '0.5rem',
                                padding: '0.75rem 2rem',
                                background: 'linear-gradient(90deg, #2563eb 0%, #4f46e5 100%)',
                                color: '#fff',
                                fontWeight: '600',
                                borderRadius: '0.5rem',
                                border: 'none',
                                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.3)',
                                cursor: 'pointer',
                                fontSize: '1rem',
                                transition: 'all 0.2s ease',
                                opacity: isDownloading ? '0.7' : '1'
                            }}
                            onMouseOver={(e) => {
                                if (!isDownloading) {
                                    e.target.style.transform = 'translateY(-2px)';
                                    e.target.style.boxShadow = '0 6px 20px rgba(37, 99, 235, 0.4)';
                                }
                            }}
                            onMouseOut={(e) => {
                                e.target.style.transform = 'translateY(0)';
                                e.target.style.boxShadow = '0 4px 14px rgba(37, 99, 235, 0.3)';
                            }}
                        >
                            {isDownloading ? (
                                <>
                                    <div style={{
                                        width: '20px',
                                        height: '20px',
                                        border: '2px solid #ffffff',
                                        borderTop: '2px solid transparent',
                                        borderRadius: '50%',
                                        animation: 'spin 1s linear infinite'
                                    }}></div>
                                    Generating PDF...
                                </>
                            ) : (
                                <>
                                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                    </svg>
                                    Download Certificate
                                </>
                            )}
                        </button>
                    </div>

                    {/* Certificate */}
                    <div className="certificate-container" ref={targetRef}>
                        <div className="certificate" style={{
                            background: '#ffffff',
                            borderRadius: '12px',
                            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
                            overflow: 'hidden',
                            border: '1px solid #e5e7eb',
                            fontFamily: 'Georgia, serif'
                        }}>
                            {/* Top Gradient Bar */}
                            <div style={{
                                height: '12px',
                                background: '#244da1'
                            }}></div>

                            {/* Certificate Content */}
                            <div style={{
                                padding: '3rem 2.5rem'
                            }}>
                                {/* Header Section */}
                                {/* Header Section */}
                                <div style={{
                                    marginBottom: '3rem'
                                }}>
                                    <div style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        flexWrap: 'wrap'
                                    }}>
                                        {/* Left: Logo and Title */}
                                        <div>
                                            <div style={{ display: 'inline-block', verticalAlign: 'middle' }}>
                                                {/* <div style={{
                                                    display: 'inline-block',
                                                    width: '48px',
                                                    height: '48px',
                                                    backgroundColor: '#0f8482',
                                                    borderRadius: '8px',
                                                    textAlign: 'center',
                                                    verticalAlign: 'middle',
                                                    position: 'relative',
                                                }}>
                                                    <span style={{
                                                        display: 'inline-block',
                                                        lineHeight: '48px',
                                                        color: '#ffffff',
                                                        fontWeight: '700',
                                                        fontSize: '24px',
                                                        fontFamily: 'Arial, sans-serif',
                                                    }}>C</span>
                                                </div> */}
                                                <div style={{
                                                    display: 'inline-block',
                                                    marginLeft: '12px',
                                                    verticalAlign: 'middle',
                                                    fontFamily: 'Arial, sans-serif'
                                                }}>
                                                    <div style={{
                                                        fontSize: '20px',
                                                        fontWeight: '700',
                                                        color: '#244da1',
                                                        lineHeight: 1.2,
                                                    }}>
                                                        CAPSTONE
                                                    </div>
                                                    <div style={{
                                                        fontSize: '14px',
                                                        fontWeight: '600',
                                                        color: '#4b5563',
                                                        lineHeight: 1.2,
                                                    }}>
                                                        PROJECT
                                                    </div>
                                                </div>
                                            </div>


                                        </div>



                                        {/* Right: Certificate Numbers */}
                                        <div style={{
                                            textAlign: 'right',
                                            fontSize: '0.875rem',
                                            color: '#4b5563',
                                            lineHeight: '1.5',
                                            marginTop: '1rem'
                                        }}>
                                            <div>Certificate No: <span style={{ fontWeight: '600' }}>{certNumber}</span></div>
                                            <div>Reference: <span style={{ fontWeight: '600' }}>{refNumber}</span></div>
                                        </div>
                                    </div>
                                </div>


                                {/* Main Content */}
                                <div style={{
                                    textAlign: 'center',
                                    marginBottom: '3rem'
                                }}>
                                    <h2 style={{
                                        fontSize: '2.25rem',
                                        fontWeight: '700',
                                        textTransform: 'uppercase',
                                        color: '#1f2937',
                                        marginBottom: '1rem',
                                        letterSpacing: '0.1em'
                                    }}>
                                        Certificate of Completion
                                    </h2>

                                    <div style={{
                                        fontSize: '2.5rem',
                                        fontWeight: '700',
                                        color: '#244da1',
                                        margin: '2rem 0',
                                        lineHeight: '1.2'
                                    }}>
                                        {projectName}
                                    </div>

                                    <p style={{
                                        fontSize: '1.25rem',
                                        color: '#374151',
                                        marginBottom: '1rem'
                                    }}>
                                        This certifies that
                                    </p>

                                    <div style={{
                                        fontSize: '2.5rem',
                                        fontWeight: '800',
                                        color: '#1f2937',
                                        borderBottom: '2px solid #e5e7eb',
                                        paddingBottom: '0.5rem',
                                        margin: '0 auto 2rem auto',
                                        maxWidth: '320px',
                                        textAlign: 'center'
                                    }}>
                                        {studentName}
                                    </div>

                                    <p style={{
                                        fontSize: '1rem',
                                        color: '#374151',
                                        maxWidth: '500px',
                                        margin: '0 auto',
                                        lineHeight: '1.6'
                                    }}>
                                        has successfully completed the capstone project with excellence
                                        and dedication on <strong>{formattedDate}</strong>
                                    </p>
                                </div>

                                {/* Footer Section */}
                                <div style={{
                                    marginTop: '4rem'
                                }}>
                                    <div style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'flex-start',
                                        marginTop: '4rem',
                                        flexWrap: 'wrap',
                                        gap: '1rem'
                                    }}>
                                        {/* Teacher Signature Box */}
                                        <div style={{
                                            borderTop: '2px solid #9ca3af',
                                            paddingTop: '0.75rem',
                                            minWidth: '200px',
                                            maxWidth: '300px'
                                        }}>
                                            <div style={{
                                                fontWeight: '700',
                                                fontSize: '1rem',
                                                color: '#1f2937',
                                                marginBottom: '0.25rem'
                                            }}>
                                                {teacherName}
                                            </div>
                                            <div style={{
                                                fontSize: '0.875rem',
                                                color: '#6b7280'
                                            }}>
                                                Project Instructor
                                            </div>
                                        </div>

                                        {/* Duration & Completion Box */}
                                        <div style={{
                                            fontSize: '0.875rem',
                                            color: '#6b7280',
                                            backgroundColor: '#f9fafb',
                                            padding: '1rem',
                                            borderRadius: '8px',
                                            lineHeight: '1.5',
                                            textAlign: 'left',
                                            minWidth: '200px',
                                            maxWidth: '300px'
                                        }}>
                                            <div><strong>Duration:</strong> {projectDuration}</div>
                                            <div><strong>Completed:</strong> {formattedDate}</div>
                                        </div>
                                    </div>


                                </div>
                            </div>

                            {/* Bottom Gradient Bar */}
                            <div style={{
                                height: '12px',
                                background: '#244da1'
                            }}></div>
                        </div>
                    </div>

                    {/* Bottom Note */}
                    <div className="no-print" style={{
                        textAlign: 'center',
                        marginTop: '2rem',
                        fontSize: '0.875rem',
                        color: '#4b5563'
                    }}>
                        <p>This certificate validates the successful completion of the capstone project requirements.</p>
                    </div>
                </div>
            </div>
        </>
    );
};

export default Certificate;