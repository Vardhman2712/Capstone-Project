import React, { useState, useEffect } from 'react';
import {
    Download, X, AlertCircle, FileText, ImageIcon, ZoomIn, ZoomOut, RotateCw,
    Archive, FileSpreadsheet, FileCode, File, Eye, EyeOff
} from 'lucide-react';

interface FileViewerProps {
    fileName: string;
    fileUrl: string;
    fileType?: string;
    isOpen: boolean;
    onClose: () => void;
    layout?: 'inline' | 'modal';
    // Specific file type props
    isImage?: boolean;
    isPDF?: boolean;
    isZip?: boolean;
    isCSV?: boolean;
    isTxt?: boolean;
    isCode?: boolean; // For JS, JSON, XML, etc.
}

type FileTypeInfo = {
    icon: React.ComponentType<any>;
    label: string;
    canPreview: boolean;
    previewMethod?: 'iframe' | 'text' | 'csv' | 'image';
};

const FileViewer: React.FC<FileViewerProps> = ({
    fileName,
    fileUrl,
    fileType = 'document',
    isOpen,
    onClose,
    layout = 'inline',
    isImage = false,
    isPDF = false,
    isZip = false,
    isCSV = false,
    isTxt = false,
    isCode = false
}) => {
    const [isLoading, setIsLoading] = useState(false);
    const [previewMethod, setPreviewMethod] = useState<'google' | 'pdfjs'>('google');
    const [imageZoom, setImageZoom] = useState(100);
    const [imageRotation, setImageRotation] = useState(0);
    const [textContent, setTextContent] = useState<string>('');
    const [csvData, setCSVData] = useState<string[][]>([]);
    const [loadingContent, setLoadingContent] = useState(false);

    // Determine file type info
    const getFileTypeInfo = (): FileTypeInfo => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';

        if (isImage) return { icon: ImageIcon, label: 'Image File', canPreview: true, previewMethod: 'image' };
        if (isPDF) return { icon: FileText, label: 'PDF Document', canPreview: true, previewMethod: 'iframe' };
        if (isZip) return { icon: Archive, label: 'ZIP Archive', canPreview: false };
        if (isCSV) return { icon: FileSpreadsheet, label: 'CSV File', canPreview: true, previewMethod: 'csv' };
        if (isTxt || extension === 'txt') return { icon: FileText, label: 'Text File', canPreview: true, previewMethod: 'text' };
        if (isCode || ['tsx', 'jsx', 'ts', 'js', 'py', 'java', 'cpp'].includes(extension)) {
            return { icon: FileCode, label: 'Code File', canPreview: true, previewMethod: 'text' };
        }
        return { icon: File, label: fileType.replace('_', ' '), canPreview: false };
    };

    const fileInfo = getFileTypeInfo();

    // Load text/CSV content
    useEffect(() => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';
        const isTextOrCodeFile = isTxt || isCode || ['txt', 'tsx', 'jsx', 'ts', 'js', 'py', 'java', 'cpp'].includes(extension);

        if (isTextOrCodeFile && isOpen && fileUrl) {
            console.log('Loading content for:', fileName); // Debug log
            loadTextContent();
        }
    }, [isOpen, isTxt, isCode, fileUrl, fileName]);

    const loadTextContent = async () => {
        console.log('Starting to load content...'); // Debug log
        setLoadingContent(true);
        try {
            const response = await fetch(fileUrl);
            if (!response.ok) {
                throw new Error(`Failed to fetch file content: ${response.status}`);
            }
            const text = await response.text();
            console.log('Content loaded successfully:', text.slice(0, 100)); // Debug log first 100 chars

            if (isCSV) {
                const rows = text.split('\n').map(row =>
                    row.split(',').map(cell => cell.trim().replace(/^["']|["']$/g, ''))
                );
                setCSVData(rows.filter(row => row.some(cell => cell.length > 0)));
            } else {
                setTextContent(text);
            }
        } catch (error) {
            console.error('Failed to load file content:', error);
            setTextContent(`Error loading file content: ${error.message}. Please try downloading the file instead.`);
        } finally {
            setLoadingContent(false);
        }
    };

    const getPreviewUrl = (method: string) => {
        switch (method) {
            case 'pdfjs':
                return `https://mozilla.github.io/pdf.js/web/viewer.html?file=${encodeURIComponent(fileUrl)}`;
            case 'google':
                return `https://drive.google.com/viewerng/viewer?embedded=true&url=${encodeURIComponent(fileUrl)}`;
            default:
                return fileUrl;
        }
    };

    const handleDownload = async () => {
        setIsLoading(true);
        try {
            const response = await fetch(fileUrl);
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Download failed:', error);
            alert('Failed to download the file.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleZoomIn = () => setImageZoom(prev => Math.min(prev + 25, 300));
    const handleZoomOut = () => setImageZoom(prev => Math.max(prev - 25, 25));
    const handleRotate = () => setImageRotation(prev => (prev + 90) % 360);

    if (!isOpen) return null;

    const renderContent = () => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';
        const isTextOrCode = isTxt || isCode || ['txt', 'tsx', 'jsx', 'ts', 'js', 'py', 'java', 'cpp'].includes(extension);

        if (!fileInfo.canPreview && !isTextOrCode) {
            return (
                <div className="w-full h-full flex flex-col items-center justify-center p-8 text-center bg-gray-50">
                    <div className="p-6 bg-white rounded-full shadow-lg mb-6">
                        <fileInfo.icon className="w-16 h-16 text-gray-400" />
                    </div>
                    <h3 className="text-xl font-semibold text-gray-700 mb-2">Preview Not Available</h3>
                    <p className="text-gray-500 mb-6 max-w-md">
                        This file type cannot be previewed in the browser.
                        {isZip && " Extract the archive to view its contents."}
                    </p>
                    <button
                        onClick={handleDownload}
                        disabled={isLoading}
                        className="flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 disabled:bg-blue-400 transition-colors shadow-sm"
                    >
                        <Download className="w-5 h-5" />
                        {isLoading ? 'Downloading...' : 'Download to View Content'}
                    </button>
                </div>
            );
        }

        if (isTextOrCode) {
            return (
                <div className="w-full h-full overflow-auto p-6 bg-white">
                    {loadingContent ? (
                        <div className="flex items-center justify-center h-32">
                            <div className="animate-spin rounded-full h-6 w-6 border-2 border-blue-500 border-t-transparent"></div>
                            <span className="ml-2 text-gray-500">Loading content...</span>
                        </div>
                    ) : (
                        <div className="bg-gray-50 p-4 rounded-lg border">
                            <div className="flex items-center justify-between mb-2 text-sm text-gray-600 border-b pb-2">
                                <span className="font-medium">{fileName}</span>
                                <span className="uppercase bg-gray-200 px-2 py-1 rounded text-xs">{extension}</span>
                            </div>
                            {textContent ? (
                                <pre className="whitespace-pre-wrap font-mono text-sm text-gray-800 overflow-auto max-h-[calc(100vh-200px)] p-4">
                                    {textContent}
                                </pre>
                            ) : (
                                <div className="text-center text-gray-500 py-4">
                                    No content available
                                </div>
                            )}
                        </div>
                    )}
                </div>
            );
        }

        switch (fileInfo.previewMethod) {
            case 'image':
                return (
                    <div className="w-full h-full flex items-center justify-center p-4">
                        <div className="max-w-full max-h-full overflow-auto">
                            <img
                                src={fileUrl}
                                alt={fileName}
                                className="transition-transform duration-200 shadow-lg rounded-lg"
                                style={{
                                    transform: `scale(${imageZoom / 100}) rotate(${imageRotation}deg)`,
                                    maxWidth: 'none',
                                    maxHeight: 'none'
                                }}
                                onError={(e) => {
                                    console.error('Image failed to load');
                                    e.currentTarget.style.display = 'none';
                                }}
                            />
                        </div>
                    </div>
                );

            case 'text':
                return (
                    <div className="w-full h-full overflow-auto p-6 bg-white">
                        {loadingContent ? (
                            <div className="flex items-center justify-center h-32">
                                <div className="animate-spin rounded-full h-6 w-6 border-2 border-blue-500 border-t-transparent"></div>
                                <span className="ml-2 text-gray-500">Loading content...</span>
                            </div>
                        ) : (
                            <div className="bg-gray-50 p-4 rounded-lg border">
                                <div className="flex items-center justify-between mb-2 text-sm text-gray-600">
                                    <span>{fileName}</span>
                                    <span className="uppercase">{extension}</span>
                                </div>
                                <pre className="whitespace-pre-wrap font-mono text-sm text-gray-800 overflow-auto max-h-[calc(100vh-200px)]">
                                    {textContent}
                                </pre>
                            </div>
                        )}
                    </div>
                );

            case 'csv':
                return (
                    <div className="w-full h-full overflow-auto p-6 bg-white">
                        {loadingContent ? (
                            <div className="flex items-center justify-center h-32">
                                <div className="text-gray-500">Loading CSV data...</div>
                            </div>
                        ) : csvData.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="min-w-full border border-gray-300 text-sm">
                                    <thead>
                                        {csvData[0] && (
                                            <tr className="bg-gray-50">
                                                {csvData[0].map((header, index) => (
                                                    <th key={index} className="border border-gray-300 px-4 py-2 text-left font-semibold text-gray-700">
                                                        {header}
                                                    </th>
                                                ))}
                                            </tr>
                                        )}
                                    </thead>
                                    <tbody>
                                        {csvData.slice(1).map((row, rowIndex) => (
                                            <tr key={rowIndex} className={rowIndex % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                                                {row.map((cell, cellIndex) => (
                                                    <td key={cellIndex} className="border border-gray-300 px-4 py-2 text-gray-800">
                                                        {cell}
                                                    </td>
                                                ))}
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="text-center text-gray-500 py-8">
                                No data found or invalid CSV format
                            </div>
                        )}
                    </div>
                );

            case 'iframe':
                return (
                    <iframe
                        src={getPreviewUrl(previewMethod)}
                        className="w-full h-full border-0"
                        title={`Preview - ${fileName}`}
                        sandbox="allow-scripts allow-same-origin allow-popups"
                    />
                );

            default:
                return null;
        }
    };

    const viewerContent = (
        <div className="w-full h-full flex flex-col bg-white rounded-lg overflow-hidden">
            {/* Header */}
            <div className="flex-shrink-0 flex items-center gap-4 px-4 py-2 bg-gradient-to-r from-slate-50 to-gray-50 border-b border-gray-200">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className="p-2 bg-white rounded-lg shadow-sm border border-gray-200 flex-shrink-0">
                        <fileInfo.icon className="w-5 h-5 text-blue-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                        <h2 className="text-base font-semibold text-gray-900 truncate" title={fileName}>
                            {fileName}
                        </h2>
                        <p className="text-sm text-gray-500 flex items-center gap-2">
                            <span className="capitalize">{fileInfo.label}</span>
                            {fileInfo.canPreview ? (
                                <span className="flex items-center gap-1 text-green-600">
                                    <Eye className="w-3 h-3" />
                                    Previewable
                                </span>
                            ) : (
                                <span className="flex items-center gap-1 text-orange-600">
                                    <EyeOff className="w-3 h-3" />
                                    Download to view
                                </span>
                            )}
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                    {/* Image Controls */}
                    {isImage && (
                        <div className="flex items-center gap-2 px-3 py-1.5 bg-white rounded-lg border border-gray-200 shadow-sm">
                            <button
                                onClick={handleZoomOut}
                                className="p-1.5 hover:bg-gray-100 rounded-md transition-colors"
                                title="Zoom Out"
                            >
                                <ZoomOut className="w-4 h-4 text-gray-600" />
                            </button>
                            <span className="text-sm text-gray-600 min-w-[3rem] text-center">{imageZoom}%</span>
                            <button
                                onClick={handleZoomIn}
                                className="p-1.5 hover:bg-gray-100 rounded-md transition-colors"
                                title="Zoom In"
                            >
                                <ZoomIn className="w-4 h-4 text-gray-600" />
                            </button>
                            <div className="w-px h-4 bg-gray-300 mx-1"></div>
                            <button
                                onClick={handleRotate}
                                className="p-1.5 hover:bg-gray-100 rounded-md transition-colors"
                                title="Rotate"
                            >
                                <RotateCw className="w-4 h-4 text-gray-600" />
                            </button>
                        </div>
                    )}

                    {/* PDF Viewer Selection */}
                    {isPDF && (
                        <select
                            value={previewMethod}
                            onChange={(e) => setPreviewMethod(e.target.value as 'google' | 'pdfjs')}
                            className="px-3 py-2 bg-white border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 shadow-sm"
                        >
                            <option value="google">Google Viewer</option>
                            <option value="pdfjs">PDF.js Viewer</option>
                        </select>
                    )}

                    <button
                        onClick={handleDownload}
                        disabled={isLoading}
                        className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:bg-blue-400 transition-colors shadow-sm"
                    >
                        <Download className="w-4 h-4" />
                        {isLoading ? 'Downloading...' : 'Download'}
                    </button>

                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors"
                        title="Close"
                    >
                        <X className="w-5 h-5 text-gray-500" />
                    </button>
                </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-auto bg-gray-50">
                {renderContent()}
            </div>

            {/* Status Bar */}
            <div className="flex-shrink-0 px-6 py-3 bg-amber-50 border-t border-amber-200 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0" />
                <span className="text-sm text-amber-800">
                    {!fileInfo.canPreview
                        ? "This file type requires downloading to view its contents."
                        : isImage
                            ? "Use zoom and rotate controls above to adjust the view."
                            : isPDF
                                ? "Having trouble viewing? Try switching to a different viewer or download the file."
                                : isCSV
                                    ? "CSV data is displayed in table format. Download for full compatibility with spreadsheet applications."
                                    : "File content is displayed above. Download for offline access."
                    }
                </span>
            </div>
        </div>
    );

    if (layout === 'modal') {
        return (
            <div className="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center backdrop-blur-sm">
                <div className="w-full max-w-7xl h-[90vh] max-h-[900px]">
                    {viewerContent}
                </div>
            </div>
        );
    }

    return <div className="w-full h-full">{viewerContent}</div>;
};

export default FileViewer;